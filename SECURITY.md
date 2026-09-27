# Security

## Supported version

Security fixes target the current `1.0.x` release line.

## Design controls

- Native reads are fixed at 1024 bytes and the complete file is never loaded into RAM.
- File and directory paths are bounded to 255 bytes; recursion is bounded to 24 levels.
- Digest input requires the exact algorithm length and hexadecimal characters.
- Manifest decimal parsing checks 64-bit overflow.
- Overlong manifest rows are consumed and counted malformed without overflowing a buffer.
- Storage return values are checked; partial writes and failed synchronization are errors.
- Manifest/report replacement is transactional through synchronized partial and backup files.
- Existing manifests require explicit replacement confirmation in the UI.
- Native audit uses an exact bounded path index and rejects oversized manifests.
- Cancellation closes files and directories before completion is reported.
- The UART decoder bounds lines to 256 bytes and discards overflow.
- The Linux bridge accepts a fixed command grammar and uses argument arrays with `shell=False`.
- The Hashdeep executable is restricted to fixed `/usr/bin/hashdeep` or `/usr/local/bin/hashdeep`; no UART or command-line executable override exists.
- External operations use fixed roots and do not accept paths from UART.
- Symlinks are not followed by companion progress measurement.
- Companion traversal errors fail the operation instead of silently undercounting input.
- Companion output is synchronized and atomically promoted only after a successful Hashdeep exit; failed or cancelled operations preserve the prior result.

## Cryptographic warning

MD5 and SHA-1 are provided only for compatibility with legacy forensic datasets. They are collision-broken and must not establish trust for new data. Use SHA-256 for new integrity checks. A matching digest shows byte equality under that algorithm; it does not prove file safety, ownership, authenticity, or absence of malicious content.

## Reporting

Do not publish sensitive evidence files. Report a vulnerability privately to the repository owner with version, firmware version, reproduction steps, and the smallest non-sensitive fixture possible.
