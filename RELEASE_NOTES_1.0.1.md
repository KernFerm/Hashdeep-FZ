# Hashdeep FZ v1.0.1

Hashdeep FZ performs real streaming file hashing and bounded HASHDEEP-1.0 manifest operations directly on Flipper Zero. It also supports genuine upstream Hashdeep through an optional Raspberry Pi or other Linux companion connected by 3.3 V UART.

## What is included

- Native streaming MD5, SHA-1, and SHA-256 hashing of actual microSD file bytes
- Expected-digest verification with measured `MATCH` or `MISMATCH` results
- Recursive manifest creation and audit with matched, changed, missing, and new-file counts
- Transactional native manifest and report saving
- Exact failure-path reporting for native storage read errors
- External Hash, Manifest, and Audit operations using genuine upstream Hashdeep on Raspberry Pi/Linux
- Preservation of an existing external report when an operation fails or is cancelled
- Crypto self-test and visible application version

MD5 and SHA-1 are included only for compatibility with legacy forensic data. SHA-256 is the default and recommended algorithm.

## Install

Download `hashdeep_fz.fap` from the Assets section below and copy it to:

```text
/ext/apps/Tools/hashdeep_fz.fap
```

The build targets official Flipper firmware 1.4.3, target f7, API 87.1.

See `README.md` for native usage and `EXTERNAL_HASHDEEP.md` for Raspberry Pi/Linux setup.

## Validation

- Clean f7/API 87.1 build and APPCHK passed
- Native compatibility tests: 5/5 passed
- Linux companion tests: 4/4 passed
- Snyk Code: zero high and zero medium findings

Artifact SHA-256:

```text
5584A6B8986A4FF3A88D2CD039B92F3DFDDA5C03A5F54CF9E916CC704037A6AC
```
