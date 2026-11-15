#!/usr/bin/env python3
"""
mfdparse — MIFARE Classic dump parser / pretty-printer
======================================================

Reads MIFARE Classic Mini / 1K / 2K / 4K dumps and prints a colour-coded,
sector-by-sector breakdown:

  * manufacturer block (UID, BCC check, SAK, ATQA)
  * Key A / access bits / GPB / Key B in every sector trailer, coloured
  * access bits fully decoded (C1 C2 C3 per block -> read/write/inc/dec rights)
    with validation of the inverted copies
  * value blocks detected and decoded (value + address, integrity-checked)
  * MAD v1 / v2 (MIFARE Application Directory) with CRC check
  * known/default keys flagged, masked keys called out
  * final key + access summary table and a list of warnings

Input formats (auto-detected, extension doesn't matter):
  .mfd / .bin / .dump   raw binary (libnfc nfc-mfclassic, mfoc, mfcuk, Proxmark .bin, ...)
  .eml                  Proxmark emulator text (one block = 32 hex chars per line)
  .mct                  MIFARE Classic Tool export ("+Sector: N" headers, "--" = unknown byte)
  .nfc                  Flipper Zero NFC file ("Block N: XX XX ..", "??" = unknown byte)

Examples:
  python3 mfdparse.py card.mfd
  python3 mfdparse.py card.mfd -s 0 -s 5          # only sectors 0 and 5
  python3 mfdparse.py card.mfd --summary          # just the key/access table
  python3 mfdparse.py card.mfd --html report.html # same coloured output as an HTML page
  python3 mfdparse.py card.mfd --json card.json   # machine-readable
  python3 mfdparse.py card.mfd --keys-out keys.dic
  python3 mfdparse.py --acl FF0780                # decode 3 access-bit bytes on their own

No dependencies beyond the Python 3.7+ standard library.
"""

import argparse
import html as htmlmod
import json
import os
import re
import sys

__version__ = "1.0"

# ════════════════════════════════════════════════════════════════════════
#  Styling: every piece of output is a list of (text, style) segments so the
#  same report can be rendered as ANSI, plain text or HTML.
# ════════════════════════════════════════════════════════════════════════

#            ANSI SGR           CSS
STYLES = {
    'title':   ('1;38;5;81',  'color:#5fd7ff;font-weight:bold'),
    'head':    ('1;97',       'color:#ffffff;font-weight:bold'),
    'sub':     ('38;5;250',   'color:#bcbcbc'),
    'dim':     ('38;5;242',   'color:#6c6c6c'),
    'unknown': ('38;5;238',   'color:#4e4e4e'),
    'uid':     ('1;38;5;203', 'color:#ff5f5f;font-weight:bold'),
    'bcc':     ('38;5;215',   'color:#ffaf5f'),
    'sak':     ('38;5;183',   'color:#d7afff'),
    'atqa':    ('38;5;147',   'color:#afafff'),
    'mfr':     ('38;5;246',   'color:#949494'),
    'keya':    ('1;38;5;77',  'color:#5fd75f;font-weight:bold'),
    'keyb':    ('1;38;5;45',  'color:#00d7ff;font-weight:bold'),
    'acc':     ('1;38;5;220', 'color:#ffd700;font-weight:bold'),
    'gpb':     ('38;5;213',   'color:#ff87ff'),
    'value':   ('1;38;5;117', 'color:#87d7ff;font-weight:bold'),
    'valinv':  ('38;5;67',    'color:#5f87af'),
    'addr':    ('38;5;180',   'color:#d7af87'),
    'crc':     ('38;5;213',   'color:#ff87ff'),
    'madinfo': ('38;5;141',   'color:#af87ff'),
    'aid':     ('38;5;180',   'color:#d7af87'),
    'data':    (None,         None),
    'empty':   ('38;5;242',   'color:#6c6c6c'),
    'ok':      ('38;5;114',   'color:#87d787'),
    'warn':    ('38;5;214',   'color:#ffaf00'),
    'err':     ('1;38;5;196', 'color:#ff3030;font-weight:bold'),
    'bad':     ('1;97;41',    'color:#ffffff;background:#aa0000;font-weight:bold'),
    'pAB':     ('38;5;114',   'color:#87d787'),
    'pA':      ('38;5;77',    'color:#5fd75f'),
    'pB':      ('38;5;45',    'color:#00d7ff'),
    'pnever':  ('38;5;167',   'color:#d75f5f'),
}


def S(text, style=None):
    return (str(text), style)


class Out:
    """Collects lines of styled segments; renders to ANSI / plain / HTML."""

    def __init__(self):
        self.lines = []

    def __call__(self, *segs):
        line = []
        for s in segs:
            if s is None or s == '':
                continue
            if isinstance(s, list):
                line.extend(s)
            elif isinstance(s, tuple):
                line.append(s)
            else:
                line.append((str(s), None))
        self.lines.append(line)

    def ansi(self, color=True):
        res = []
        for line in self.lines:
            parts = []
            for text, st in line:
                code = STYLES.get(st, (None, None))[0] if st else None
                parts.append(f"\x1b[{code}m{text}\x1b[0m" if (color and code) else text)
            res.append(''.join(parts))
        return '\n'.join(res) + '\n'

    def html(self, title):
        body = []
        for line in self.lines:
            parts = []
            for text, st in line:
                css = STYLES.get(st, (None, None))[1] if st else None
                t = htmlmod.escape(text)
                parts.append(f'<span style="{css}">{t}</span>' if css else t)
            body.append(''.join(parts))
        return (
            "<!DOCTYPE html>\n<html><head><meta charset='utf-8'>"
            f"<title>{htmlmod.escape(title)}</title>"
            "<style>body{background:#0d1117;margin:0;padding:24px}"
            "pre{color:#d0d0d0;font:13px/1.45 'JetBrains Mono','Fira Code',Consolas,Menlo,monospace;"
            "margin:0;white-space:pre}</style></head><body><pre>"
            + '\n'.join(body) + "</pre></body></html>\n"
        )


# ════════════════════════════════════════════════════════════════════════
#  MIFARE Classic knowledge
# ════════════════════════════════════════════════════════════════════════

CARD_SIZES = {          # bytes -> (name, sectors)
    320:  ('MIFARE Classic Mini', 5),
    1024: ('MIFARE Classic 1K', 16),
    2048: ('MIFARE Classic 2K', 32),
    4096: ('MIFARE Classic 4K', 40),
}

SAK_NAMES = {
    0x08: 'MIFARE Classic 1K',
    0x09: 'MIFARE Mini',
    0x18: 'MIFARE Classic 4K',
    0x19: 'MIFARE Classic 2K',
    0x88: 'MIFARE Classic 1K (Infineon)',
    0x10: 'MIFARE Plus 2K (SL2)',
    0x11: 'MIFARE Plus 4K (SL2)',
    0x28: 'SmartMX with MIFARE Classic 1K emulation',
    0x38: 'SmartMX with MIFARE Classic 4K emulation',
}

UID_MFR = {0x02: 'STMicroelectronics', 0x04: 'NXP', 0x05: 'Infineon', 0x07: 'Texas Instruments'}

KNOWN_KEYS = {
    'FFFFFFFFFFFF': 'factory default',
    'A0A1A2A3A4A5': 'MAD key A (public)',
    'D3F7D3F7D3F7': 'NFC Forum / NDEF key A (public)',
    'B0B1B2B3B4B5': 'common default',
    'AABBCCDDEEFF': 'common default',
    '000000000000': 'all zeros',
    '4D3A99C351DD': 'public default-key dictionary',
    '1A982C7E459A': 'public default-key dictionary',
    '714C5C886E97': 'public default-key dictionary',
    '587EE5F9350F': 'public default-key dictionary',
    'A0478CC39091': 'public default-key dictionary',
    '533CB6C723F6': 'public default-key dictionary',
    '8FD0A4F256E9': 'public default-key dictionary',
}

# Data blocks: (C1,C2,C3) -> (read, write, increment, decrement/transfer/restore, meaning)
DATA_ACL = {
    (0, 0, 0): ('A|B',   'A|B',   'A|B',   'A|B',   'transport config — fully open'),
    (0, 1, 0): ('A|B',   'never', 'never', 'never', 'read-only'),
    (1, 0, 0): ('A|B',   'B',     'never', 'never', 'read A|B, write B'),
    (1, 1, 0): ('A|B',   'B',     'B',     'A|B',   'value block (recharge with B)'),
    (0, 0, 1): ('A|B',   'never', 'never', 'A|B',   'value block, decrement only'),
    (0, 1, 1): ('B',     'B',     'never', 'never', 'read/write with Key B only'),
    (1, 0, 1): ('B',     'never', 'never', 'never', 'read-only with Key B'),
    (1, 1, 1): ('never', 'never', 'never', 'never', 'locked — no access'),
}

# Sector trailer: (C1,C2,C3) -> (KeyA rd, KeyA wr, ACL rd, ACL wr, KeyB rd, KeyB wr, meaning)
TRAILER_ACL = {
    (0, 0, 0): ('never', 'A',     'A',   'never', 'A',     'A',     'Key B readable; ACL frozen'),
    (0, 1, 0): ('never', 'never', 'A',   'never', 'A',     'never', 'Key B readable; all frozen'),
    (1, 0, 0): ('never', 'B',     'A|B', 'never', 'never', 'B',     'keys managed by B; ACL frozen'),
    (1, 1, 0): ('never', 'never', 'A|B', 'never', 'never', 'never', 'trailer frozen'),
    (0, 0, 1): ('never', 'A',     'A',   'A',     'A',     'A',     'transport config — Key A owns all'),
    (0, 1, 1): ('never', 'B',     'A|B', 'B',     'never', 'B',     'Key B manages sector (recommended)'),
    (1, 0, 1): ('never', 'never', 'A|B', 'B',     'never', 'never', 'keys frozen; ACL writable with B'),
    (1, 1, 1): ('never', 'never', 'A|B', 'never', 'never', 'never', 'trailer frozen'),
}
KEYB_READABLE = {(0, 0, 0), (0, 1, 0), (0, 0, 1)}


def decode_access(b6, b7, b8):
    """Return ([(C1,C2,C3) for groups 0..3], valid). Group 3 = sector trailer."""
    c1 = (b7 >> 4) & 0xF
    c2 = b8 & 0xF
    c3 = (b8 >> 4) & 0xF
    valid = (((b6 & 0xF) ^ c1) == 0xF and
             (((b6 >> 4) & 0xF) ^ c2) == 0xF and
             ((b7 & 0xF) ^ c3) == 0xF)
    conds = [(((c1 >> i) & 1), ((c2 >> i) & 1), ((c3 >> i) & 1)) for i in range(4)]
    return conds, valid


def encode_access(conds):
    """Inverse of decode_access: [(C1,C2,C3) x4] -> 3 bytes."""
    c1 = c2 = c3 = 0
    for i, (a, b, c) in enumerate(conds):
        c1 |= a << i
        c2 |= b << i
        c3 |= c << i
    return bytes([((~c2 & 0xF) << 4) | (~c1 & 0xF), (c1 << 4) | (~c3 & 0xF), (c3 << 4) | c2])


def effective(perm, keyb_readable):
    """If Key B is readable it can't be used to authenticate."""
    if not keyb_readable:
        return perm, False
    if perm == 'A|B':
        return 'A', True
    if perm == 'B':
        return 'never', True
    return perm, False


def perm_style(p):
    return {'A|B': 'pAB', 'A': 'pA', 'B': 'pB', 'never': 'pnever'}.get(p, None)


def parse_value_block(blk):
    """Return (value, addr) if blk is a correctly formatted value block, else None."""
    if blk[0:4] != blk[8:12]:
        return None
    if any((blk[i] ^ blk[i + 4]) != 0xFF for i in range(4)):
        return None
    if blk[12] != blk[14] or blk[13] != blk[15] or (blk[12] ^ blk[13]) != 0xFF:
        return None
    return int.from_bytes(blk[0:4], 'little', signed=True), blk[12]


def mad_crc(data):
    crc = 0xC7
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1D) if crc & 0x80 else (crc << 1)
            crc &= 0xFF
    return crc


def aid_label(ac, fcc):
    if fcc == 0x00:
        return {0x00: 'free', 0x01: 'defect', 0x02: 'reserved',
                0x03: 'additional directory info', 0x04: 'card holder info',
                0x05: 'not applicable'}.get(ac, 'card administration')
    if (ac, fcc) == (0x03, 0xE1):
        return 'NDEF'
    if fcc == 0xE1:
        return 'NFC Forum'
    return ''


def sector_layout(nsec):
    out, blk = [], 0
    for s in range(nsec):
        n = 4 if s < 32 else 16
        out.append((s, blk, n))
        blk += n
    return out


def nsec_for_blocks(nblocks):
    for size, (_, nsec) in sorted(CARD_SIZES.items()):
        if nblocks <= size // 16:
            return nsec, size
    return 40, 4096


# ════════════════════════════════════════════════════════════════════════
#  Loading
# ════════════════════════════════════════════════════════════════════════

class Dump:
    def __init__(self, blocks, fmt, notes, forced_size=None):
        """blocks: dict blockno -> (bytes16, known[16])"""
        maxblk = max(blocks) + 1 if blocks else 0
        if forced_size:
            size = forced_size
        else:
            _, size = nsec_for_blocks(maxblk)
        self.size = size
        self.name, self.nsec = CARD_SIZES[size]
        self.fmt = fmt
        self.notes = list(notes)
        nb = size // 16
        self.data = bytearray(size)
        self.known = [False] * size
        for b, (raw, kn) in blocks.items():
            if b >= nb:
                self.notes.append(('warn', f'block {b} beyond {self.name} layout — ignored'))
                continue
            self.data[b * 16:b * 16 + 16] = raw
            self.known[b * 16:b * 16 + 16] = kn
        missing = sum(1 for b in range(nb) if b not in blocks)
        if missing:
            self.notes.append(('warn', f'{missing} block(s) missing from the dump — shown as --'))

    def block(self, n):
        return bytes(self.data[n * 16:n * 16 + 16])

    def bknown(self, n):
        return self.known[n * 16:n * 16 + 16]

    def block_fully_known(self, n):
        return all(self.bknown(n))


HEXLINE = re.compile(r'^[0-9A-Fa-f\-]{32}$')


def _hexline(line, unk='-'):
    raw, kn = bytearray(16), [False] * 16
    for i in range(16):
        pair = line[i * 2:i * 2 + 2]
        if unk in pair:
            continue
        raw[i] = int(pair, 16)
        kn[i] = True
    return bytes(raw), kn


def load_dump(path):
    with open(path, 'rb') as f:
        raw = f.read()
    text = None
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        pass

    if text is not None:
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        # Flipper Zero .nfc
        if lines and 'Flipper' in lines[0]:
            blocks, forced = {}, None
            for l in lines:
                m = re.match(r'^Mifare Classic type:\s*(\S+)', l, re.I)
                if m:
                    forced = {'MINI': 320, '1K': 1024, '2K': 2048, '4K': 4096}.get(m.group(1).upper())
                m = re.match(r'^Block\s+(\d+):\s*(.*)$', l)
                if m:
                    toks = m.group(2).split()
                    if len(toks) != 16:
                        continue
                    r, kn = bytearray(16), [False] * 16
                    for i, t in enumerate(toks):
                        if '?' not in t:
                            r[i] = int(t, 16)
                            kn[i] = True
                    blocks[int(m.group(1))] = (bytes(r), kn)
            if blocks:
                return Dump(blocks, 'Flipper Zero .nfc', [], forced)
        # MCT / Proxmark eml
        if lines and all(HEXLINE.match(l) or l.startswith('+Sector') for l in lines):
            if any(l.startswith('+Sector') for l in lines):
                secs, cur = {}, None
                for l in lines:
                    if l.startswith('+Sector'):
                        cur = int(re.findall(r'\d+', l)[0])
                        secs[cur] = []
                    elif cur is not None:
                        secs[cur].append(_hexline(l))
                maxsec = max(secs)
                nsec = next(n for n in (5, 16, 32, 40) if maxsec < n)
                blocks = {}
                for s, first, n in sector_layout(nsec):
                    for i, blk in enumerate(secs.get(s, [])[:n]):
                        blocks[first + i] = blk
                size = {5: 320, 16: 1024, 32: 2048, 40: 4096}[nsec]
                return Dump(blocks, 'MIFARE Classic Tool (.mct)', [], size)
            blocks = {i: _hexline(l) for i, l in enumerate(lines)}
            return Dump(blocks, 'Proxmark emulator (.eml)', [])

    # raw binary
    notes = []
    n = len(raw)
    if n not in CARD_SIZES:
        if n == 0:
            raise ValueError('file is empty')
        notes.append(('warn', f'unusual dump size {n} bytes (expected 320/1024/2048/4096)'))
        if n % 16:
            notes.append(('warn', f'size is not a multiple of 16 — last {n % 16} byte(s) ignored'))
        raw = raw[:4096]
    blocks = {}
    for b in range(len(raw) // 16):
        blocks[b] = (raw[b * 16:b * 16 + 16], [True] * 16)
    return Dump(blocks, 'raw binary (.mfd/.bin)', notes)


# ════════════════════════════════════════════════════════════════════════
#  Analysis
# ════════════════════════════════════════════════════════════════════════

def analyse(d, uid_len=0):
    """Build a structured description of the dump (also used for --json)."""
    res = {'card': d.name, 'size': d.size, 'format': d.fmt, 'sectors': [], 'warnings': []}
    warn = res['warnings']
    for lvl, msg in d.notes:
        warn.append({'sector': None, 'level': lvl, 'msg': msg})

    # ── manufacturer block
    b0, k0 = d.block(0), d.bknown(0)
    man = None
    if all(k0[:8]):
        bcc_calc = b0[0] ^ b0[1] ^ b0[2] ^ b0[3]
        ul = uid_len or (4 if bcc_calc == b0[4] else 7)
        man = {'uid_len': ul}
        if ul == 4:
            man.update(uid=b0[0:4].hex().upper(), bcc=b0[4], bcc_calc=bcc_calc,
                       bcc_ok=bcc_calc == b0[4], sak=b0[5],
                       atqa=f'{b0[7]:02X}{b0[6]:02X}', mfr_data=b0[8:].hex().upper())
            if bcc_calc != b0[4]:
                warn.append({'sector': 0, 'level': 'err',
                             'msg': f'BCC mismatch in block 0 (stored {b0[4]:02X}, expected {bcc_calc:02X})'})
        else:
            man.update(uid=b0[0:7].hex().upper(), mfr_data=b0[7:].hex().upper())
            if not uid_len:
                warn.append({'sector': 0, 'level': 'warn',
                             'msg': 'BCC of first 4 bytes does not match — treating as 7-byte UID '
                                    '(use --uid-len 4 to force)'})
    res['manufacturer'] = man

    # ── MAD
    mad = None
    t0 = d.block(3)
    if d.block_fully_known(3) and d.block_fully_known(1) and d.block_fully_known(2):
        gpb = t0[9]
        if gpb & 0x80:
            ver = gpb & 0x03
            payload = d.block(1)[1:] + d.block(2)
            stored = d.block(1)[0]
            mad = {'version': ver, 'multi_app': bool(gpb & 0x40), 'crc': stored,
                   'crc_calc': mad_crc(payload), 'info': d.block(1)[1], 'aids': {}}
            mad['crc_ok'] = mad['crc'] == mad['crc_calc']
            aid_bytes = d.block(1)[2:] + d.block(2)
            for s in range(1, 16):
                ac, fcc = aid_bytes[(s - 1) * 2], aid_bytes[(s - 1) * 2 + 1]
                mad['aids'][s] = (ac, fcc)
            if not mad['crc_ok']:
                warn.append({'sector': 0, 'level': 'warn',
                             'msg': f"MAD1 CRC mismatch (stored {mad['crc']:02X}, calc {mad['crc_calc']:02X})"})
            if ver == 2 and d.nsec == 40 and all(d.block_fully_known(b) for b in (64, 65, 66)):
                m2 = d.block(64) + d.block(65) + d.block(66)
                mad['mad2'] = {'crc': m2[0], 'crc_calc': mad_crc(m2[1:]), 'info': m2[1], 'aids': {}}
                mad['mad2']['crc_ok'] = mad['mad2']['crc'] == mad['mad2']['crc_calc']
                for s in range(17, 40):
                    i = 2 + (s - 17) * 2
                    mad['mad2']['aids'][s] = (m2[i], m2[i + 1])
                if not mad['mad2']['crc_ok']:
                    warn.append({'sector': 16, 'level': 'warn', 'msg': 'MAD2 CRC mismatch'})
    res['mad'] = mad

    # ── sectors
    for s, first, n in sector_layout(d.nsec):
        tb = first + n - 1
        tr, tk = d.block(tb), d.bknown(tb)
        sec = {'sector': s, 'first_block': first, 'blocks': n, 'trailer_block': tb}
        sec['key_a'] = tr[0:6].hex().upper() if all(tk[0:6]) else None
        sec['key_b'] = tr[10:16].hex().upper() if all(tk[10:16]) else None
        sec['access_bytes'] = tr[6:9].hex().upper() if all(tk[6:9]) else None
        sec['gpb'] = tr[9] if tk[9] else None
        sec['access_valid'] = None
        sec['conds'] = None
        sec['keyb_readable'] = False
        if sec['access_bytes']:
            conds, valid = decode_access(*tr[6:9])
            sec['conds'] = conds
            sec['access_valid'] = valid
            sec['keyb_readable'] = valid and conds[3] in KEYB_READABLE
            if not valid:
                warn.append({'sector': s, 'level': 'err',
                             'msg': f"invalid access bits {sec['access_bytes']} — inverted copies don't match; "
                                    'a real card irreversibly blocks this sector'})
        # key notes
        for which in ('a', 'b'):
            key = sec['key_' + which]
            if key is None:
                continue
            if key == '000000000000':
                masked = which == 'a' or not sec['keyb_readable']
                if masked:
                    continue  # reported inline, not a "default key" warning
            if key in KNOWN_KEYS:
                warn.append({'sector': s, 'level': 'warn',
                             'msg': f'Key {which.upper()} is a known key: {key} ({KNOWN_KEYS[key]})'})
        if sec['keyb_readable']:
            warn.append({'sector': s, 'level': 'info',
                         'msg': 'Key B is readable → it is plain data and cannot be used to authenticate'})
        # blocks
        sec['block_info'] = []
        for i in range(n):
            b = first + i
            blk = d.block(b)
            info = {'block': b, 'hex': ''.join(f'{x:02X}' if k else '--' for x, k in zip(blk, d.bknown(b)))}
            if b == 0:
                info['type'] = 'manufacturer'
            elif i == n - 1:
                info['type'] = 'trailer'
            elif mad and s == 0 and b in (1, 2):
                info['type'] = 'mad'
            elif mad and 'mad2' in mad and s == 16 and i < 3:
                info['type'] = 'mad'
            elif d.block_fully_known(b) and parse_value_block(blk):
                v, a = parse_value_block(blk)
                info.update(type='value', value=v, addr=a)
            elif not d.block_fully_known(b):
                info['type'] = 'unknown' if not any(d.bknown(b)) else 'data'
            elif blk in (b'\x00' * 16, b'\xff' * 16):
                info['type'] = 'empty'
            else:
                info['type'] = 'data'
            sec['block_info'].append(info)
        res['sectors'].append(sec)
    return res


# ════════════════════════════════════════════════════════════════════════
#  Rendering
# ════════════════════════════════════════════════════════════════════════

def group_of(i, n):
    """Map block index within sector -> access-condition group (0..3)."""
    if n == 4:
        return i
    return 3 if i == 15 else i // 5


def byte_styles(btype, blk, sec, man, d, bno):
    st = ['data'] * 16
    if btype == 'manufacturer' and man:
        if man['uid_len'] == 4:
            st = ['uid'] * 4 + ['bcc' if man['bcc_ok'] else 'bad', 'sak', 'atqa', 'atqa'] + ['mfr'] * 8
        else:
            st = ['uid'] * 7 + ['mfr'] * 9
    elif btype == 'trailer':
        acc = 'acc' if sec['access_valid'] in (True, None) else 'bad'
        st = ['keya'] * 6 + [acc] * 3 + ['gpb'] + ['keyb'] * 6
    elif btype == 'value':
        st = ['value'] * 4 + ['valinv'] * 4 + ['value'] * 4 + ['addr', 'valinv', 'addr', 'valinv']
    elif btype == 'mad':
        st = ['aid'] * 16
        if bno in (1, 64):
            st[0], st[1] = 'crc', 'madinfo'
    elif btype == 'empty':
        st = ['empty'] * 16
    return st


def block_tag(info, sec, man):
    t = info['type']
    if t == 'manufacturer':
        return S('manufacturer', 'uid')
    if t == 'trailer':
        return S('sector trailer', 'acc')
    if t == 'value':
        return [S('value ', 'value'), S(f"{info['value']}", 'head'), S(f"  addr {info['addr']:02X}", 'addr')]
    if t == 'mad':
        return S('MAD', 'madinfo')
    if t == 'empty':
        return S('empty', 'dim')
    if t == 'unknown':
        return S('not read', 'unknown')
    return S('data', 'dim')


def render_block_line(o, d, bno, info, sec, man, show_ascii, group_label):
    blk, kn = d.block(bno), d.bknown(bno)
    styles = byte_styles(info['type'], blk, sec, man, d, bno)
    hexsegs = []
    for i in range(16):
        if kn[i]:
            hexsegs.append(S(f'{blk[i]:02X}', styles[i]))
        else:
            hexsegs.append(S('--', 'unknown'))
        if i < 15:
            hexsegs.append(S(' '))
    segs = [S(f'  {bno:>4} ', 'dim'), S(f'{group_label:<2}', 'dim'), S('│ ', 'dim')] + hexsegs
    if show_ascii:
        asc = []
        for x, k in zip(blk, kn):
            if not k:
                asc.append(S(' ', None))
            elif 0x20 <= x < 0x7F:
                asc.append(S(chr(x), None))
            else:
                asc.append(S('.', 'unknown'))
        segs += [S(' │ ', 'dim')] + asc
    segs += [S(' │ ', 'dim'), block_tag(info, sec, man)]
    o(*segs)


def key_line(o, label, key, style, readable_info, sec):
    which = label[-1]
    segs = [S(f'      {label:<6} ', 'sub')]
    if key is None:
        o(*segs, S('------------', 'unknown'), S('  not in dump', 'dim'))
        return
    segs.append(S(key, style))
    notes = []
    if key == '000000000000' and which == 'A':
        notes.append(S('  possibly masked — cards never return Key A; dump tool may not have filled it in', 'warn'))
    elif key == '000000000000' and which == 'B' and not sec['keyb_readable']:
        notes.append(S('  possibly masked — Key B not readable under these access bits', 'warn'))
    elif key in KNOWN_KEYS:
        notes.append(S(f'  ⚠ {KNOWN_KEYS[key]}', 'warn'))
    if which == 'B' and sec['keyb_readable']:
        notes.append(S('  readable → used as data, NOT usable for auth', 'warn'))
    o(*segs, *notes)


def render_acl(o, sec, n, first):
    ab = sec['access_bytes']
    if ab is None:
        o(S('      Access ', 'sub'), S('------', 'unknown'), S('  access bits not in dump', 'dim'))
        return
    valid = sec['access_valid']
    gpb = sec['gpb']
    segs = [S('      Access ', 'sub'),
            S(' '.join(ab[i:i + 2] for i in range(0, 6, 2)), 'acc' if valid else 'bad'),
            S('  ✔ valid' if valid else '  ✘ INVALID — inverted bits mismatch, sector would be bricked',
              'ok' if valid else 'err')]
    if gpb is not None:
        segs += [S('    GPB ', 'sub'), S(f'{gpb:02X}', 'gpb')]
        if sec['sector'] == 0 and gpb & 0x80:
            segs.append(S(f"  (MAD present, v{gpb & 3}{', multi-app' if gpb & 0x40 else ''})", 'dim'))
    o(*segs)

    conds = sec['conds']
    kbr = sec['keyb_readable']
    # raw bit view
    bits = []
    for g in range(4):
        c = conds[g]
        bits.append(S(f"  g{g}:", 'dim'))
        bits.append(S(f"{c[0]}{c[1]}{c[2]}", 'acc' if valid else 'err'))
    o(S('      C1C2C3 ', 'sub'), *bits, S('   (g3 = trailer)', 'dim'))
    if not valid:
        o(S('      (table below is decoded from the non-inverted bits only)', 'err'))

    o()
    o(S('        Blocks        C1 C2 C3   Read    Write   Incr    Dec/Tfr  Meaning', 'head'))
    any_eff = False
    for g in range(3):
        if n == 4:
            label = f'{first + g}'
        else:
            label = f'{first + g * 5}-{first + g * 5 + 4}'
        c = conds[g]
        rd, wr, inc, dec, meaning = DATA_ACL[c]
        cells = []
        for p in (rd, wr, inc, dec):
            e, changed = effective(p, kbr)
            any_eff |= changed
            txt = e + ('*' if changed else '')
            cells.append(S(f'{txt:<8}', perm_style(e)))
        o(S(f'        {label:<13} ', 'sub'), S(f' {c[0]}  {c[1]}  {c[2]}    ', 'acc'), *cells,
          S(meaning, 'dim'))
    c = conds[3]
    kar, kaw, acr, acw, kbrd, kbw, meaning = TRAILER_ACL[c]
    o()
    o(S('        Trailer       C1 C2 C3   KeyA rd KeyA wr ACL rd  ACL wr  KeyB rd KeyB wr  Meaning', 'head'))
    cells = []
    for p in (kar, kaw, acr, acw, kbrd, kbw):
        cells.append(S(f'{p:<8}', perm_style(p)))
    o(S(f'        {first + n - 1:<13} ', 'sub'), S(f' {c[0]}  {c[1]}  {c[2]}    ', 'acc'), *cells,
      S(meaning, 'dim'))
    if any_eff:
        o(S('        * Key B is readable here, so the card refuses it for auth — effective right shown', 'warn'))


def render_manufacturer(o, man):
    if not man:
        o(S('      Block 0 not fully in dump', 'unknown'))
        return
    if man['uid_len'] == 4:
        uid = man['uid']
        segs = [S('      UID    ', 'sub'), S(' '.join(uid[i:i + 2] for i in range(0, 8, 2)), 'uid'),
                S('  (4-byte', 'dim')]
        if uid.startswith('08'):
            segs.append(S(', 08 = random ID', 'dim'))
        segs.append(S(')', 'dim'))
        o(*segs)
        o(S('      BCC    ', 'sub'), S(f"{man['bcc']:02X}", 'bcc' if man['bcc_ok'] else 'bad'),
          S('  ✔ matches UID XOR' if man['bcc_ok'] else f"  ✘ expected {man['bcc_calc']:02X}",
            'ok' if man['bcc_ok'] else 'err'))
        sak = man['sak']
        o(S('      SAK    ', 'sub'), S(f'{sak:02X}', 'sak'), S(f"  {SAK_NAMES.get(sak, 'unknown/custom')}", 'dim'),
          S('     ATQA ', 'sub'), S(man['atqa'], 'atqa'))
        o(S('      Mfr    ', 'sub'), S(' '.join(man['mfr_data'][i:i + 2] for i in range(0, 16, 2)), 'mfr'),
          S('  (values as stored in the dump)', 'dim'))
    else:
        uid = man['uid']
        o(S('      UID    ', 'sub'), S(' '.join(uid[i:i + 2] for i in range(0, 14, 2)), 'uid'),
          S(f"  (7-byte, manufacturer: {UID_MFR.get(int(uid[:2], 16), 'unknown')})", 'dim'))
        o(S('      Mfr    ', 'sub'), S(' '.join(man['mfr_data'][i:i + 2] for i in range(0, 18, 2)), 'mfr'))


def render_mad(o, mad, which='mad1'):
    m = mad if which == 'mad1' else mad['mad2']
    name = 'MAD v1' if which == 'mad1' else 'MAD v2'
    cps = m['info'] & 0x3F
    o(S(f'      {name}  ', 'sub'), S('CRC ', 'sub'), S(f"{m['crc']:02X}", 'crc'),
      S('  ✔' if m['crc_ok'] else f"  ✘ calc {m['crc_calc']:02X}", 'ok' if m['crc_ok'] else 'err'),
      S('   info ', 'sub'), S(f"{m['info']:02X}", 'madinfo'),
      S(f"  (card publisher sector: {cps if cps else 'none'})", 'dim'))
    items = list(m['aids'].items())
    for row in range(0, len(items), 4):
        segs = [S('        ')]
        for s, (ac, fcc) in items[row:row + 4]:
            lbl = aid_label(ac, fcc)
            segs += [S(f'S{s:02d} ', 'dim'), S(f'{ac:02X}{fcc:02X}', 'aid' if (ac or fcc) else 'dim'),
                     S(f' {lbl:<10}  ', 'dim')]
        o(*segs)


def render_summary(o, res):
    o(S('━' * 96, 'dim'))
    o(S('  KEY & ACCESS SUMMARY', 'title'))
    o(S('━' * 96, 'dim'))
    o(S('   Sec  Blocks    Key A          Key B          Access     GPB  Notes', 'head'))
    for sec in res['sectors']:
        s, first, n = sec['sector'], sec['first_block'], sec['blocks']
        notes = []
        ka, kb = sec['key_a'], sec['key_b']
        for key in (ka, kb):
            if key and key in KNOWN_KEYS and key != '000000000000':
                notes.append(S('default-key ', 'warn'))
                break
        if sec['access_valid'] is False:
            notes.append(S('INVALID-ACL ', 'err'))
        if sec['keyb_readable']:
            notes.append(S('KeyB-readable ', 'warn'))
        if sec['conds'] and sec['access_valid']:
            if sec['conds'][3] == (0, 0, 1) and all(c == (0, 0, 0) for c in sec['conds'][:3]):
                notes.append(S('transport ', 'dim'))
        vals = [bi for bi in sec['block_info'] if bi['type'] == 'value']
        if vals:
            notes.append(S(f'{len(vals)} value blk ', 'value'))
        if any(bi['type'] == 'mad' for bi in sec['block_info']):
            notes.append(S('MAD ', 'madinfo'))
        if all(bi['type'] in ('empty', 'trailer', 'manufacturer', 'mad') for bi in sec['block_info']) and not vals:
            pass
        ab = sec['access_bytes']
        o(S(f'   {s:>3}  {first:>3}-{first + n - 1:<4}  ', 'sub'),
          S(ka or '------------', 'keya' if ka else 'unknown'), S('   '),
          S(kb or '------------', 'keyb' if kb else 'unknown'), S('   '),
          S(f"{ab[0:2]} {ab[2:4]} {ab[4:6]}" if ab else '-- -- --',
            ('acc' if sec['access_valid'] else 'bad') if ab else 'unknown'), S('   '),
          S(f"{sec['gpb']:02X}" if sec['gpb'] is not None else '--', 'gpb'), S('   '),
          *notes)

    keys = {}
    for sec in res['sectors']:
        for k in (sec['key_a'], sec['key_b']):
            if k:
                keys[k] = keys.get(k, 0) + 1
    o()
    o(S(f'  Unique keys: {len(keys)}', 'head'))
    for k, cnt in sorted(keys.items(), key=lambda x: -x[1]):
        o(S('    '), S(k, 'acc'), S(f'  ×{cnt:<3}', 'dim'),
          S(KNOWN_KEYS.get(k, ''), 'warn' if k in KNOWN_KEYS else 'dim'))


def render_warnings(o, res):
    ws = [w for w in res['warnings'] if w['level'] in ('err', 'warn')]
    infos = [w for w in res['warnings'] if w['level'] == 'info']
    o()
    o(S('━' * 96, 'dim'))
    uniq = {(w['level'], w['msg']) for w in ws + infos}
    errs = sum(1 for l, _ in uniq if l == 'err')
    nwarn = sum(1 for l, _ in uniq if l == 'warn')
    ninfo = sum(1 for l, _ in uniq if l == 'info')
    o(S('  FINDINGS  ', 'title'), S(f'{errs} error(s)', 'err' if errs else 'ok'), S(' · ', 'dim'),
      S(f'{nwarn} warning(s)', 'warn' if nwarn else 'ok'), S(' · ', 'dim'),
      S(f'{ninfo} note(s)', 'dim'))
    o(S('━' * 96, 'dim'))
    if not ws and not infos:
        o(S('  nothing notable', 'ok'))
    # group identical messages across sectors
    grouped = {}
    for w in ws + infos:
        grouped.setdefault((w['level'], w['msg']), []).append(w['sector'])
    order = {'err': 0, 'warn': 1, 'info': 2}
    width = max([len(sector_ranges(v)) for v in grouped.values()] + [4]) + 2
    for (lvl, msg), secs in sorted(grouped.items(), key=lambda kv: (order[kv[0][0]], kv[1][0] or -1)):
        tag = {'err': ('✘', 'err'), 'warn': ('⚠', 'warn'), 'info': ('•', 'dim')}[lvl]
        o(S(f'  {tag[0]} ', tag[1]), S(f'{sector_ranges(secs):<{width}}', 'sub'),
          S(msg, None if lvl != 'info' else 'dim'))


def sector_ranges(secs):
    if secs == [None]:
        return 'file'
    secs = sorted(s for s in secs if s is not None)
    parts, start, prev = [], None, None
    for s in secs:
        if start is None:
            start = prev = s
        elif s == prev + 1:
            prev = s
        else:
            parts.append((start, prev))
            start = prev = s
    if start is not None:
        parts.append((start, prev))
    txt = ','.join(f'S{a:02d}' if a == b else f'S{a:02d}–{b:02d}' for a, b in parts)
    return txt


def render_legend(o):
    o(S('  Legend: ', 'dim'),
      S('UID', 'uid'), S(' '), S('BCC', 'bcc'), S(' '), S('SAK', 'sak'), S(' '), S('ATQA', 'atqa'),
      S('  │  ', 'dim'),
      S('Key A', 'keya'), S(' '), S('Access', 'acc'), S(' '), S('GPB', 'gpb'), S(' '), S('Key B', 'keyb'),
      S('  │  ', 'dim'),
      S('Value', 'value'), S(' '), S('~Value', 'valinv'), S(' '), S('Addr', 'addr'),
      S('  │  ', 'dim'),
      S('MAD-CRC', 'crc'), S(' '), S('AID', 'aid'))
    o(S('  Rights:  ', 'dim'), S('A|B', 'pAB'), S(' either key  ', 'dim'), S('A', 'pA'),
      S(' Key A only  ', 'dim'), S('B', 'pB'), S(' Key B only  ', 'dim'), S('never', 'pnever'),
      S(' not allowed', 'dim'))


def render(res, d, args, path):
    o = Out()
    o(S('━' * 96, 'dim'))
    o(S('  MIFARE CLASSIC DUMP  ', 'title'), S(os.path.basename(path), 'head'))
    o(S('━' * 96, 'dim'))
    o(S('  Card    ', 'sub'), S(res['card'], 'head'), S(f"  ({res['size']} bytes, {d.nsec} sectors)", 'dim'))
    o(S('  Format  ', 'sub'), S(res['format'], None))
    man = res['manufacturer']
    if man:
        o(S('  UID     ', 'sub'), S(man['uid'], 'uid'))
    render_legend(o)

    if not args.summary:
        only = set(args.sector or [])
        for sec in res['sectors']:
            s = sec['sector']
            if only and s not in only:
                continue
            first, n = sec['first_block'], sec['blocks']
            o()
            o(S(f'┏━ Sector {s:>2} ', 'title'), S(f'━━ blocks {first}–{first + n - 1} ', 'dim'),
              S('━' * (72 - len(str(first)) - len(str(first + n - 1))), 'dim'))
            for i, info in enumerate(sec['block_info']):
                g = group_of(i, n)
                render_block_line(o, d, info['block'], info, sec, man, not args.no_ascii,
                                  'T' if g == 3 else f'{g}')
            o(S('┃', 'title'))
            if s == 0:
                render_manufacturer(o, man)
                if res['mad']:
                    render_mad(o, res['mad'], 'mad1')
                o(S('┃', 'title'))
            if s == 16 and res['mad'] and 'mad2' in res['mad']:
                render_mad(o, res['mad'], 'mad2')
                o(S('┃', 'title'))
            key_line(o, 'Key A', sec['key_a'], 'keya', None, sec)
            key_line(o, 'Key B', sec['key_b'], 'keyb', None, sec)
            render_acl(o, sec, n, first)
        o()

    render_summary(o, res)
    render_warnings(o, res)
    return o


def acl_only(hexstr, color):
    hexstr = re.sub(r'[^0-9A-Fa-f]', '', hexstr)
    if len(hexstr) < 6:
        sys.exit('--acl needs 3 bytes, e.g. FF0780')
    bts = bytes.fromhex(hexstr[:6])
    conds, valid = decode_access(*bts)
    sec = {'sector': -1, 'access_bytes': bts.hex().upper(), 'access_valid': valid, 'gpb': None,
           'conds': conds, 'keyb_readable': valid and conds[3] in KEYB_READABLE}
    o = Out()
    o(S('  Access bits decode (4-block sector; for 4K sectors 32–39 groups are 5 blocks)', 'title'))
    render_acl(o, sec, 4, 0)
    sys.stdout.write(o.ansi(color))


def json_ready(res):
    out = json.loads(json.dumps(res, default=lambda x: x.hex() if isinstance(x, bytes) else str(x)))
    for sec in out['sectors']:
        if sec['conds']:
            c = [tuple(x) for x in sec['conds']]
            kbr = sec['keyb_readable']
            sec['access'] = {
                'groups': [dict(zip(('read', 'write', 'increment', 'decrement'),
                                    [effective(p, kbr)[0] for p in DATA_ACL[c[g]][:4]]),
                                c1c2c3=''.join(map(str, c[g])), meaning=DATA_ACL[c[g]][4]) for g in range(3)],
                'trailer': dict(zip(('keya_read', 'keya_write', 'acl_read', 'acl_write', 'keyb_read', 'keyb_write'),
                                    TRAILER_ACL[c[3]][:6]),
                                c1c2c3=''.join(map(str, c[3])), meaning=TRAILER_ACL[c[3]][6]),
            }
        del sec['conds']
    return out


def main():
    ap = argparse.ArgumentParser(
        description='Parse MIFARE Classic dumps (.mfd/.bin/.eml/.mct/.nfc) into a coloured, decoded report.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Examples:\n  %(prog)s card.mfd\n  %(prog)s card.mfd -s 1 -s 2\n'
               '  %(prog)s card.mfd --html report.html\n  %(prog)s --acl 787788')
    ap.add_argument('dump', nargs='?', help='dump file')
    ap.add_argument('-s', '--sector', type=int, action='append', help='only show this sector (repeatable)')
    ap.add_argument('--summary', action='store_true', help='only print the key/access summary + findings')
    ap.add_argument('--no-ascii', action='store_true', help='hide the ASCII column')
    ap.add_argument('--no-color', action='store_true', help='disable colours (also: NO_COLOR env var)')
    ap.add_argument('--color', action='store_true', help='force colours even when piped (e.g. into less -R)')
    ap.add_argument('--uid-len', type=int, choices=(4, 7), default=0, help='force UID length (default: auto via BCC)')
    ap.add_argument('--html', metavar='FILE', help='also write the coloured report as an HTML page')
    ap.add_argument('--json', metavar='FILE', help="write structured JSON ('-' for stdout)")
    ap.add_argument('--keys-out', metavar='FILE', help='write unique keys, one per line (mfoc/proxmark .dic style)')
    ap.add_argument('--acl', metavar='HEX', help='decode 3 access-bit bytes (e.g. FF0780) and exit')
    ap.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    args = ap.parse_args()

    if os.name == 'nt':
        os.system('')  # enable ANSI escape processing on Windows 10+ consoles
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass

    color = (args.color or (sys.stdout.isatty() and 'NO_COLOR' not in os.environ)) and not args.no_color

    if args.acl:
        acl_only(args.acl, color)
        return
    if not args.dump:
        ap.error('a dump file is required (or use --acl)')

    try:
        d = load_dump(args.dump)
    except (OSError, ValueError) as e:
        sys.exit(f'error: {e}')

    res = analyse(d, args.uid_len)

    if args.json == '-':
        print(json.dumps(json_ready(res), indent=2))
        return

    report = render(res, d, args, args.dump)
    sys.stdout.write(report.ansi(color))

    if args.html:
        with open(args.html, 'w', encoding='utf-8') as f:
            f.write(report.html(f'MIFARE dump — {os.path.basename(args.dump)}'))
        print(f'HTML report written to {args.html}', file=sys.stderr)
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(json_ready(res), f, indent=2)
        print(f'JSON written to {args.json}', file=sys.stderr)
    if args.keys_out:
        keys = []
        for sec in res['sectors']:
            for k in (sec['key_a'], sec['key_b']):
                if k and k not in keys:
                    keys.append(k)
        with open(args.keys_out, 'w') as f:
            f.write('\n'.join(keys) + '\n')
        print(f'{len(keys)} unique key(s) written to {args.keys_out}', file=sys.stderr)


if __name__ == '__main__':
    main()
