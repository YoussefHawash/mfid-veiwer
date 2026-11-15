# MIFARE Classic Dump Parser

**Live site → https://youssefhawash.github.io/mfid-veiwer/**

Drop a MIFARE Classic dump in your browser and get a colour-coded, sector-by-sector breakdown of keys, access bits, value blocks and the MAD. Everything runs client-side: dump files are never uploaded.

## Features

**Dump parser**
- Colour-coded hexdump: UID / BCC / SAK / ATQA, **Key A**, **access bits**, GPB, **Key B**, value blocks, MAD. Hover a byte to see what it is.
- Access bits fully decoded: C1/C2/C3 per block → read / write / increment / decrement rights, and trailer rights for Key A, the access bits and Key B.
- Checks the access bits against their inverted copy and flags invalid ones (a real card permanently blocks that sector).
- Readable Key B handled properly: the card refuses it for authentication, so the *effective* rights are shown.
- Known/default keys flagged. All-zero keys that are probably masked by the card are called out separately.
- Value blocks detected and decoded (signed value + address, integrity-checked).
- MAD v1/v2 with CRC-8 check and AID labels (e.g. NDEF).
- Key & access summary, grouped findings, export to JSON or a `.dic` key list.

**Compare dumps**: load two dumps (e.g. before/after a transaction) and view them side by side. Differing bytes are highlighted, and changes are summarised: key rotations, access-bit changes (with meaning), value-block deltas (`1500 → 1250 (−250)`), and changed data blocks.

**Access bits calculator**: decode any 3 access bytes, or pick conditions per block and get the correctly inverted bytes.

## Supported formats

| Format | Source |
|---|---|
| `.mfd` / `.bin` / `.dump` | raw binary: libnfc `nfc-mfclassic`, mfoc, mfcuk, Proxmark |
| `.eml` | Proxmark emulator text |
| `.mct` | MIFARE Classic Tool (Android) export |
| `.nfc` | Flipper Zero |

Mini (320 B), 1K, 2K and 4K layouts (including 4K's 16-block sectors 32–39).

## Command-line version

The same parser is in [`cli/mfdparse.py`](cli/mfdparse.py) (Python 3, no dependencies) with ANSI colour output:

```bash
python3 cli/mfdparse.py card.mfd
python3 cli/mfdparse.py card.mfd -s 2 --html report.html --json card.json --keys-out keys.dic
python3 cli/mfdparse.py --acl FF0780
```

## Run locally

It's a static site. Serve the folder with any web server (`python3 -m http.server`) and open `http://localhost:8000`.

## Samples

`samples/` holds synthetic dumps (made-up UID and keys) that exercise MAD/NDEF, value blocks, invalid access bits and a readable Key B, plus a before/after pair for the compare view.

## Legal

For analysing cards you own or are authorised to test.

## License

MIT
