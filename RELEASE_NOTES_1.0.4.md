# Hashdeep FZ v1.0.4

Hashdeep FZ hashes actual file bytes on the Flipper microSD card, verifies expected digests, creates and audits recursive manifests, and optionally controls genuine Hashdeep on Linux.

## Native Flipper features

- Streaming SHA-256, SHA-1, and MD5 hashing in bounded 1024-byte chunks.
- Exact expected-digest verification with algorithm-specific hexadecimal length validation.
- SHA-256 is the recommended default; MD5 and SHA-1 are clearly marked legacy compatibility algorithms.
- Recursive HASHDEEP-1.0 manifest creation containing size, MD5, SHA-1, SHA-256, and filename.
- Folder presets and file-browser parent selection so `/` never needs to be typed on the Flipper keyboard.
- Recursion limited to 24 levels and paths limited to 255 bytes with explicit failures instead of skipped or truncated names.
- Explicit overwrite confirmation and transactional `.partial`/backup promotion that preserves an older valid manifest after cancellation, disk-full, traversal, sync, or rename failure.
- Manifest audit with measured matched, changed, missing, new, malformed, and I/O-error counts.
- Case-insensitive digest comparison, exact path indexing, duplicate/malformed record handling, and detection of files added after manifest creation.
- A bounded native audit index of 1,024 records and 32,768 path bytes; larger manifests are rejected explicitly for external processing.
- Safe cancellation, real file/byte progress, exact failure paths, and transactional reports.

NFC, LF RFID, Sub-GHz, infrared, UART captures, and other Flipper data can be hashed as ordinary saved files. Hashdeep FZ hashes their bytes and never substitutes a UID, frequency, filename, or metadata field for a file digest.

## Genuine Hashdeep on Raspberry Pi/Linux

External mode runs the real installed `hashdeep` executable on a Raspberry Pi, Linux laptop, desktop, mini PC, or VM. The bounded UART controller exposes fixed `HASH`, `MANIFEST`, and `AUDIT` operations for files under `/var/lib/hashdeep-fz/input`.

The bridge uses fixed paths and argument arrays with `shell=False`. Temporary output is promoted only after successful completion; failed or cancelled external audits preserve the previous report. Full upstream features such as Tiger, Whirlpool, piecewise mode, DFXML, NSRL, iLook, HashKeeper, and additional CLI display modes remain available directly on Linux.

## Quick start

1. Choose SHA-256, SHA-1, or MD5 in **Settings**.
2. Select **Hash File** to calculate a digest, or enter **Expected digest** and use **Verify Digest**.
3. Select an input folder and output preset, then choose **Create Manifest**.
4. Select **Audit Manifest** to re-hash records and identify matched, changed, missing, and newly added files.
5. Press Back during work to request safe cancellation.
6. For genuine external Hashdeep, follow `EXTERNAL_HASHDEEP.md`, connect 3.3 V UART, select HASH/MANIFEST/AUDIT, and press OK to run/cancel.

## Install and verification

Requires official Flipper firmware 1.4.3 or later and a microSD card. Copy `hashdeep_fz.fap` to `/ext/apps/Tools/` and open **Apps → Tools → Hashdeep FZ**.

- Native compatibility/manifest tests: 5 passed.
- External companion tests: 4 passed.
- uFBT APPCHK: target f7/API 87.1, no unresolved symbols.
- FAP size: 48,072 bytes.
- SHA-256: `2CC7DEA7E25DBD3A5992634D1C45C4F9E6AAE941F21F6C83498A45BD76D063A6`

Hashdeep FZ original source is GNU GPL v2 or later and preserves upstream public-domain/GPL notices. Use it only on files and systems you own or are authorized to examine.
