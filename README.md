# MIFARE Classic Dump Viewer

**→ [youssefhawash.github.io/mfid-veiwer](https://youssefhawash.github.io/mfid-veiwer/)**

Drop a MIFARE Classic dump in your browser to see its keys, access bits and value blocks, colour-coded and decoded. Files are parsed locally and never uploaded.

- **Parser**: sector-by-sector hexdump, access-bit permissions, default-key and invalid-ACL warnings
- **Compare**: two dumps side by side with the differing bytes highlighted
- **Access bits calculator**: decode or build trailer access bytes

Reads `.mfd` / `.bin`, Proxmark `.eml`, MIFARE Classic Tool `.mct` and Flipper `.nfc`, for Mini, 1K, 2K and 4K cards.

There's also a Python CLI version: `python3 cli/mfdparse.py card.mfd`

MIT licensed.
