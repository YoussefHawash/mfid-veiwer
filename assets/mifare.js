/*!
 * mifare.js — MIFARE Classic dump parser (browser + Node)
 * Parses raw .mfd/.bin, Proxmark .eml, MIFARE Classic Tool .mct and Flipper .nfc dumps.
 * MIT License.
 */
(function (root) {
  'use strict';

  const CARD_SIZES = {
    320: ['MIFARE Classic Mini', 5],
    1024: ['MIFARE Classic 1K', 16],
    2048: ['MIFARE Classic 2K', 32],
    4096: ['MIFARE Classic 4K', 40],
  };

  const SAK_NAMES = {
    0x08: 'MIFARE Classic 1K', 0x09: 'MIFARE Mini', 0x18: 'MIFARE Classic 4K',
    0x19: 'MIFARE Classic 2K', 0x88: 'MIFARE Classic 1K (Infineon)',
    0x10: 'MIFARE Plus 2K (SL2)', 0x11: 'MIFARE Plus 4K (SL2)',
    0x28: 'SmartMX with MIFARE Classic 1K emulation',
    0x38: 'SmartMX with MIFARE Classic 4K emulation',
  };

  const UID_MFR = { 0x02: 'STMicroelectronics', 0x04: 'NXP', 0x05: 'Infineon', 0x07: 'Texas Instruments' };

  const KNOWN_KEYS = {
    FFFFFFFFFFFF: 'factory default',
    A0A1A2A3A4A5: 'MAD key A (public)',
    D3F7D3F7D3F7: 'NFC Forum / NDEF key A (public)',
    B0B1B2B3B4B5: 'common default',
    AABBCCDDEEFF: 'common default',
    '000000000000': 'all zeros',
    '4D3A99C351DD': 'public default-key dictionary',
    '1A982C7E459A': 'public default-key dictionary',
    '714C5C886E97': 'public default-key dictionary',
    '587EE5F9350F': 'public default-key dictionary',
    A0478CC39091: 'public default-key dictionary',
    '533CB6C723F6': 'public default-key dictionary',
    '8FD0A4F256E9': 'public default-key dictionary',
  };

  // Data blocks: C1C2C3 -> [read, write, increment, decrement/transfer/restore, meaning]
  const DATA_ACL = {
    '000': ['A|B', 'A|B', 'A|B', 'A|B', 'transport config — fully open'],
    '010': ['A|B', 'never', 'never', 'never', 'read-only'],
    '100': ['A|B', 'B', 'never', 'never', 'read A|B, write B'],
    '110': ['A|B', 'B', 'B', 'A|B', 'value block (recharge with B)'],
    '001': ['A|B', 'never', 'never', 'A|B', 'value block, decrement only'],
    '011': ['B', 'B', 'never', 'never', 'read/write with Key B only'],
    '101': ['B', 'never', 'never', 'never', 'read-only with Key B'],
    '111': ['never', 'never', 'never', 'never', 'locked — no access'],
  };

  // Trailer: C1C2C3 -> [KeyA rd, KeyA wr, ACL rd, ACL wr, KeyB rd, KeyB wr, meaning]
  const TRAILER_ACL = {
    '000': ['never', 'A', 'A', 'never', 'A', 'A', 'Key B readable; ACL frozen'],
    '010': ['never', 'never', 'A', 'never', 'A', 'never', 'Key B readable; all frozen'],
    '100': ['never', 'B', 'A|B', 'never', 'never', 'B', 'keys managed by B; ACL frozen'],
    '110': ['never', 'never', 'A|B', 'never', 'never', 'never', 'trailer frozen'],
    '001': ['never', 'A', 'A', 'A', 'A', 'A', 'transport config — Key A owns all'],
    '011': ['never', 'B', 'A|B', 'B', 'never', 'B', 'Key B manages sector (recommended)'],
    '101': ['never', 'never', 'A|B', 'B', 'never', 'never', 'keys frozen; ACL writable with B'],
    '111': ['never', 'never', 'A|B', 'never', 'never', 'never', 'trailer frozen'],
  };
  const KEYB_READABLE = new Set(['000', '010', '001']);

  const hex2 = (n) => n.toString(16).toUpperCase().padStart(2, '0');
  const toHex = (arr) => Array.from(arr, hex2).join('');

  /** Returns {conds:['C1C2C3' x4], valid}. Group 3 is the sector trailer. */
  function decodeAccess(b6, b7, b8) {
    const c1 = (b7 >> 4) & 0xf, c2 = b8 & 0xf, c3 = (b8 >> 4) & 0xf;
    const valid = ((b6 & 0xf) ^ c1) === 0xf && (((b6 >> 4) & 0xf) ^ c2) === 0xf && ((b7 & 0xf) ^ c3) === 0xf;
    const conds = [0, 1, 2, 3].map((i) => `${(c1 >> i) & 1}${(c2 >> i) & 1}${(c3 >> i) & 1}`);
    return { conds, valid };
  }

  /** ['C1C2C3' x4] -> [b6, b7, b8] */
  function encodeAccess(conds) {
    let c1 = 0, c2 = 0, c3 = 0;
    conds.forEach((c, i) => { c1 |= +c[0] << i; c2 |= +c[1] << i; c3 |= +c[2] << i; });
    return [((~c2 & 0xf) << 4) | (~c1 & 0xf), (c1 << 4) | (~c3 & 0xf), (c3 << 4) | c2];
  }

  /** If Key B is readable it cannot be used to authenticate. */
  function effective(perm, keybReadable) {
    if (!keybReadable) return [perm, false];
    if (perm === 'A|B') return ['A', true];
    if (perm === 'B') return ['never', true];
    return [perm, false];
  }

  function parseValueBlock(b) {
    for (let i = 0; i < 4; i++) {
      if (b[i] !== b[i + 8]) return null;
      if ((b[i] ^ b[i + 4]) !== 0xff) return null;
    }
    if (b[12] !== b[14] || b[13] !== b[15] || (b[12] ^ b[13]) !== 0xff) return null;
    const v = (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) | 0;
    return { value: v, addr: b[12] };
  }

  function madCrc(data) {
    let crc = 0xc7;
    for (const byte of data) {
      crc ^= byte;
      for (let i = 0; i < 8; i++) crc = (crc & 0x80 ? (crc << 1) ^ 0x1d : crc << 1) & 0xff;
    }
    return crc;
  }

  function aidLabel(ac, fcc) {
    if (fcc === 0x00) {
      return ({ 0: 'free', 1: 'defect', 2: 'reserved', 3: 'additional directory info',
        4: 'card holder info', 5: 'not applicable' })[ac] || 'card administration';
    }
    if (ac === 0x03 && fcc === 0xe1) return 'NDEF';
    if (fcc === 0xe1) return 'NFC Forum';
    return '';
  }

  function sectorLayout(nsec) {
    const out = [];
    let blk = 0;
    for (let s = 0; s < nsec; s++) {
      const n = s < 32 ? 4 : 16;
      out.push({ sector: s, first: blk, n });
      blk += n;
    }
    return out;
  }

  function sizeForBlocks(nblocks) {
    for (const size of [320, 1024, 2048, 4096]) if (nblocks <= size / 16) return size;
    return 4096;
  }

  /* ───────────────────────── Dump container ───────────────────────── */

  class Dump {
    /** blocks: Map<blockNo, {raw:Uint8Array(16), known:bool[16]}> */
    constructor(blocks, fmt, notes, forcedSize) {
      const maxBlk = blocks.size ? Math.max(...blocks.keys()) + 1 : 0;
      this.size = forcedSize || sizeForBlocks(maxBlk);
      [this.name, this.nsec] = CARD_SIZES[this.size];
      this.fmt = fmt;
      this.notes = notes.slice();
      const nb = this.size / 16;
      this.data = new Uint8Array(this.size);
      this.known = new Array(this.size).fill(false);
      for (const [b, { raw, known }] of blocks) {
        if (b >= nb) { this.notes.push(['warn', `block ${b} beyond ${this.name} layout — ignored`]); continue; }
        this.data.set(raw, b * 16);
        for (let i = 0; i < 16; i++) this.known[b * 16 + i] = known[i];
      }
      let missing = 0;
      for (let b = 0; b < nb; b++) if (!blocks.has(b)) missing++;
      if (missing) this.notes.push(['warn', `${missing} block(s) missing from the dump — shown as --`]);
    }
    block(n) { return this.data.slice(n * 16, n * 16 + 16); }
    bknown(n) { return this.known.slice(n * 16, n * 16 + 16); }
    full(n) { return this.bknown(n).every(Boolean); }
  }

  const HEXLINE = /^[0-9A-Fa-f-]{32}$/;

  function hexLine(line) {
    const raw = new Uint8Array(16), known = new Array(16).fill(false);
    for (let i = 0; i < 16; i++) {
      const p = line.substr(i * 2, 2);
      if (p.includes('-')) continue;
      raw[i] = parseInt(p, 16);
      known[i] = true;
    }
    return { raw, known };
  }

  /** bytes: Uint8Array of the file contents */
  function loadDump(bytes) {
    let text = null;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch (e) { /* binary */ }

    if (text !== null) {
      const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      // Flipper Zero .nfc
      if (lines.length && lines[0].includes('Flipper')) {
        const blocks = new Map();
        let forced;
        for (const l of lines) {
          let m = l.match(/^Mifare Classic type:\s*(\S+)/i);
          if (m) forced = { MINI: 320, '1K': 1024, '2K': 2048, '4K': 4096 }[m[1].toUpperCase()];
          m = l.match(/^Block\s+(\d+):\s*(.*)$/);
          if (m) {
            const toks = m[2].split(/\s+/);
            if (toks.length !== 16) continue;
            const raw = new Uint8Array(16), known = new Array(16).fill(false);
            toks.forEach((t, i) => { if (!t.includes('?')) { raw[i] = parseInt(t, 16); known[i] = true; } });
            blocks.set(+m[1], { raw, known });
          }
        }
        if (blocks.size) return new Dump(blocks, 'Flipper Zero (.nfc)', [], forced);
      }
      // MCT / Proxmark eml
      if (lines.length && lines.every((l) => HEXLINE.test(l) || l.startsWith('+Sector'))) {
        if (lines.some((l) => l.startsWith('+Sector'))) {
          const secs = new Map();
          let cur = null;
          for (const l of lines) {
            if (l.startsWith('+Sector')) { cur = +l.match(/\d+/)[0]; secs.set(cur, []); }
            else if (cur !== null) secs.get(cur).push(hexLine(l));
          }
          const maxSec = Math.max(...secs.keys());
          const nsec = [5, 16, 32, 40].find((n) => maxSec < n) || 40;
          const blocks = new Map();
          for (const { sector, first, n } of sectorLayout(nsec)) {
            (secs.get(sector) || []).slice(0, n).forEach((blk, i) => blocks.set(first + i, blk));
          }
          return new Dump(blocks, 'MIFARE Classic Tool (.mct)', [], { 5: 320, 16: 1024, 32: 2048, 40: 4096 }[nsec]);
        }
        const blocks = new Map();
        lines.forEach((l, i) => blocks.set(i, hexLine(l)));
        return new Dump(blocks, 'Proxmark emulator (.eml)', []);
      }
    }

    // raw binary
    const notes = [];
    let raw = bytes;
    if (!raw.length) throw new Error('file is empty');
    if (!CARD_SIZES[raw.length]) {
      notes.push(['warn', `unusual dump size ${raw.length} bytes (expected 320/1024/2048/4096)`]);
      if (raw.length % 16) notes.push(['warn', `size is not a multiple of 16 — last ${raw.length % 16} byte(s) ignored`]);
      raw = raw.slice(0, 4096);
    }
    const blocks = new Map();
    for (let b = 0; b < Math.floor(raw.length / 16); b++) {
      blocks.set(b, { raw: raw.slice(b * 16, b * 16 + 16), known: new Array(16).fill(true) });
    }
    return new Dump(blocks, 'raw binary (.mfd / .bin)', notes);
  }

  /* ───────────────────────── Analysis ───────────────────────── */

  function analyse(d, uidLen = 0) {
    const res = { card: d.name, size: d.size, nsec: d.nsec, format: d.fmt, sectors: [], warnings: [] };
    const warn = (sector, level, msg) => res.warnings.push({ sector, level, msg });
    d.notes.forEach(([lvl, msg]) => warn(null, lvl, msg));

    // manufacturer block
    const b0 = d.block(0), k0 = d.bknown(0);
    let man = null;
    if (k0.slice(0, 8).every(Boolean)) {
      const bccCalc = b0[0] ^ b0[1] ^ b0[2] ^ b0[3];
      const ul = uidLen || (bccCalc === b0[4] ? 4 : 7);
      man = { uidLen: ul };
      if (ul === 4) {
        Object.assign(man, {
          uid: toHex(b0.slice(0, 4)), bcc: b0[4], bccCalc, bccOk: bccCalc === b0[4], sak: b0[5],
          sakName: SAK_NAMES[b0[5]] || 'unknown / custom', atqa: hex2(b0[7]) + hex2(b0[6]),
          mfrData: toHex(b0.slice(8)),
        });
        if (!man.bccOk) warn(0, 'err', `BCC mismatch in block 0 (stored ${hex2(b0[4])}, expected ${hex2(bccCalc)})`);
      } else {
        Object.assign(man, { uid: toHex(b0.slice(0, 7)), mfrData: toHex(b0.slice(7)), mfr: UID_MFR[b0[0]] || 'unknown' });
        if (!uidLen) warn(0, 'warn', 'BCC of first 4 bytes does not match — treating as 7-byte UID (set UID length to 4 to force)');
      }
    }
    res.manufacturer = man;

    // MAD
    let mad = null;
    if (d.full(1) && d.full(2) && d.full(3)) {
      const gpb = d.block(3)[9];
      if (gpb & 0x80) {
        const b1 = d.block(1), b2 = d.block(2);
        const payload = [...b1.slice(1), ...b2];
        const aidBytes = [...b1.slice(2), ...b2];
        mad = { version: gpb & 3, multiApp: !!(gpb & 0x40), crc: b1[0], crcCalc: madCrc(payload), info: b1[1], aids: [] };
        mad.crcOk = mad.crc === mad.crcCalc;
        for (let s = 1; s < 16; s++) {
          const ac = aidBytes[(s - 1) * 2], fcc = aidBytes[(s - 1) * 2 + 1];
          mad.aids.push({ sector: s, ac, fcc, aid: hex2(ac) + hex2(fcc), label: aidLabel(ac, fcc) });
        }
        if (!mad.crcOk) warn(0, 'warn', `MAD1 CRC mismatch (stored ${hex2(mad.crc)}, calculated ${hex2(mad.crcCalc)})`);
        if (mad.version === 2 && d.nsec === 40 && [64, 65, 66].every((b) => d.full(b))) {
          const m2 = [...d.block(64), ...d.block(65), ...d.block(66)];
          const m = { crc: m2[0], crcCalc: madCrc(m2.slice(1)), info: m2[1], aids: [] };
          m.crcOk = m.crc === m.crcCalc;
          for (let s = 17; s < 40; s++) {
            const i = 2 + (s - 17) * 2;
            m.aids.push({ sector: s, ac: m2[i], fcc: m2[i + 1], aid: hex2(m2[i]) + hex2(m2[i + 1]), label: aidLabel(m2[i], m2[i + 1]) });
          }
          if (!m.crcOk) warn(16, 'warn', 'MAD2 CRC mismatch');
          mad.mad2 = m;
        }
      }
    }
    res.mad = mad;

    // sectors
    for (const { sector: s, first, n } of sectorLayout(d.nsec)) {
      const tb = first + n - 1, tr = d.block(tb), tk = d.bknown(tb);
      const all = (a, b) => tk.slice(a, b).every(Boolean);
      const sec = {
        sector: s, firstBlock: first, blocks: n, trailerBlock: tb,
        keyA: all(0, 6) ? toHex(tr.slice(0, 6)) : null,
        keyB: all(10, 16) ? toHex(tr.slice(10, 16)) : null,
        accessBytes: all(6, 9) ? toHex(tr.slice(6, 9)) : null,
        gpb: tk[9] ? tr[9] : null,
        accessValid: null, conds: null, keybReadable: false, blockInfo: [],
      };
      if (sec.accessBytes) {
        const { conds, valid } = decodeAccess(tr[6], tr[7], tr[8]);
        sec.conds = conds;
        sec.accessValid = valid;
        sec.keybReadable = valid && KEYB_READABLE.has(conds[3]);
        if (!valid) warn(s, 'err', `invalid access bits ${sec.accessBytes} — inverted copies don't match; a real card irreversibly blocks this sector`);
      }
      for (const which of ['A', 'B']) {
        const key = sec['key' + which];
        if (!key) continue;
        if (key === '000000000000' && (which === 'A' || !sec.keybReadable)) continue; // masked, reported inline
        if (KNOWN_KEYS[key]) warn(s, 'warn', `Key ${which} is a known key: ${key} (${KNOWN_KEYS[key]})`);
      }
      if (sec.keybReadable) warn(s, 'info', 'Key B is readable → it is plain data and cannot be used to authenticate');

      for (let i = 0; i < n; i++) {
        const b = first + i, blk = d.block(b), kn = d.bknown(b);
        const info = { block: b, group: n === 4 ? i : (i === 15 ? 3 : Math.floor(i / 5)),
          hex: Array.from(blk, (x, j) => (kn[j] ? hex2(x) : '--')).join('') };
        let vb;
        if (b === 0) info.type = 'manufacturer';
        else if (i === n - 1) info.type = 'trailer';
        else if (mad && s === 0 && (b === 1 || b === 2)) info.type = 'mad';
        else if (mad && mad.mad2 && s === 16 && i < 3) info.type = 'mad';
        else if (d.full(b) && (vb = parseValueBlock(blk))) Object.assign(info, { type: 'value' }, vb);
        else if (!kn.every(Boolean)) info.type = kn.some(Boolean) ? 'data' : 'unknown';
        else if (blk.every((x) => x === 0) || blk.every((x) => x === 0xff)) info.type = 'empty';
        else info.type = 'data';
        sec.blockInfo.push(info);
      }
      res.sectors.push(sec);
    }
    return res;
  }

  /** JSON-friendly export with permissions spelled out. */
  function toJSON(res) {
    const out = JSON.parse(JSON.stringify(res));
    out.sectors.forEach((sec) => {
      if (sec.conds) {
        sec.access = {
          groups: sec.conds.slice(0, 3).map((c) => {
            const [r, w, inc, dec, meaning] = DATA_ACL[c];
            const e = (p) => effective(p, sec.keybReadable)[0];
            return { c1c2c3: c, read: e(r), write: e(w), increment: e(inc), decrement: e(dec), meaning };
          }),
          trailer: (() => {
            const t = TRAILER_ACL[sec.conds[3]];
            return { c1c2c3: sec.conds[3], keyA_read: t[0], keyA_write: t[1], acl_read: t[2], acl_write: t[3], keyB_read: t[4], keyB_write: t[5], meaning: t[6] };
          })(),
        };
      }
    });
    return out;
  }

  const api = {
    CARD_SIZES, SAK_NAMES, UID_MFR, KNOWN_KEYS, DATA_ACL, TRAILER_ACL, KEYB_READABLE,
    decodeAccess, encodeAccess, effective, parseValueBlock, madCrc, aidLabel, sectorLayout,
    loadDump, analyse, toJSON, hex2, toHex,
  };
  root.Mifare = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
