# Changelog

## 1.0.1 — 2026-09-27

- Added the exact failing file or directory path to native error reports.
- Verified native end-of-directory handling against the official firmware 1.4.3 storage API contract.
- Made stale native report and manifest recovery fail safely when cleanup cannot complete.
- Prevented a failed external audit from replacing a previously valid report.
- Added external temporary-output synchronization, directory synchronization, strict traversal-error handling, cleanup, serial flushing, and bounded process termination.
- Expanded regression coverage for preservation of an existing report after a failed external audit.

## 1.0.0 — 2026-09-26

- Added real streaming MD5, SHA-1, and SHA-256 file hashing.
- Added exact expected-digest validation and MATCH/MISMATCH results.
- Added recursive HASHDEEP-1.0 manifest creation and bounded audit.
- Added native new-file detection by walking the root recorded in native manifests.
- Added slash-free input-folder presets and parent-folder selection through the file browser.
- Made manifest and report replacement transactional with partial/backup recovery.
- Added overwrite confirmation, slash-free output presets, and filename-only editing.
- Added exact bounded audit indexing, case-insensitive digest comparison, long filenames, directory/read error detection, and synchronized progress snapshots.
- Corrected external UART initialization ordering.
- Added actual file/byte progress, cancellation, storage errors, and measured SD reports.
- Added Settings, About, application version, and crypto known-answer self-test.
- Added bounded HDF1 UART and a Linux/Raspberry Pi companion invoking genuine Hashdeep.
- Built successfully for official firmware 1.4.3, target f7, API 87.1.
