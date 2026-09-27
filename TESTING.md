# Testing

## Automated checks

Run from the repository root:

```powershell
python tests/run_tests.py
python tests/test_companion.py
python -m ufbt
```

The host suite checks MD5/SHA-1/SHA-256 known-answer vectors for empty, `abc`, one-byte, chunk-boundary, and large inputs; exact digest validation; manifest creation/audit results; malformed and duplicate records; missing and changed files; cancellation; and output failures. Companion tests verify fixed operations, path measurement, token bounding, and preservation of an existing report when an external audit fails.

## Device checks

1. Confirm Settings reports `Crypto self-test PASS`.
2. Hash a zero-byte file and compare SHA-256 with `e3b0c442...b855`.
3. Hash a file containing exactly `abc`; compare MD5 `90015098...f72`, SHA-1 `a9993e36...d89d`, and SHA-256 `ba7816bf...15ad`.
4. Create a manifest for a small directory, audit unchanged, edit one file, delete one file, and audit again.
5. Add a file after creation and confirm `New: 1`; uppercase one manifest digest and confirm it still matches.
6. Cancel replacement of an existing manifest and confirm the original remains byte-for-byte intact.
7. Fill the SD card during creation and confirm the old manifest remains intact and no final partial result is accepted.
8. Cancel a large file and a directory operation with Back.
9. Remove the SD card only when safe to reproduce read/write failure handling, then reboot if firmware requests it.
10. Repeat an operation 25 times and confirm all worker/UART resources release.
11. If a native read fails, confirm the result names the exact failing file or directory under `Failure path`.

## Current build evidence

- Version: 1.0.1
- SDK: official firmware 1.4.3, target f7, API 87.1
- Command: `python -m ufbt`
- Result: clean FAP build and APPCHK pass
- Artifact: `dist/hashdeep_fz.fap`, 48,072 bytes, SHA-256 `5584A6B8986A4FF3A88D2CD039B92F3DFDDA5C03A5F54CF9E916CC704037A6AC`
- Snyk Code: 0 high, 0 medium, 8 low. All eight low findings are the intentional MD5/SHA-1 forensic-compatibility implementation and known-answer tests; neither algorithm is used for password storage, both are labeled legacy, and SHA-256 is the default.
- Raspberry Pi hardware: not claimed tested until real companion hardware is available

Snyk and other scanners supplement, but do not replace, native arithmetic, parser, path, storage, cancellation, and UART review.
