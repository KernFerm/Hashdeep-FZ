# Hashdeep FZ

Hashdeep FZ hashes the actual bytes of files stored on a Flipper Zero microSD card. Version 1.0.4 provides two real operating modes: bounded native MD5, SHA-1, SHA-256, verification, recursive manifest creation and audit on the Flipper; or genuine upstream Hashdeep running on a Raspberry Pi/Linux computer while the Flipper acts as its 3.3 V UART controller and measured status display.

Current release: **v1.0.4**.

## Install the FAP

The release build targets official Flipper firmware 1.4.3, target f7, API 87.1. A different firmware API may require rebuilding.

### Install with qFlipper

1. Download `hashdeep_fz.fap` from the latest GitHub release or this repository's `dist` folder.
2. Connect the Flipper Zero by USB and open qFlipper.
3. Open the microSD card browser, then `apps/Tools`.
4. Copy `hashdeep_fz.fap` to `/ext/apps/Tools/`.
5. Safely disconnect the Flipper.
6. Open **Apps → Tools → Hashdeep FZ**.

The extension is `.fap` (Flipper Application Package), not `.fab`.

### Install directly from microSD

Put the card in a computer, copy `hashdeep_fz.fap` into `apps/Tools/`, safely eject the card, and return it to the Flipper.

## Native Flipper use

### Hash a file

1. In **Settings**, select SHA-256, SHA-1, or MD5. SHA-1 and MD5 are marked legacy.
2. Open **Hash File** and select any readable file on microSD.
3. The worker reads the file in 1024-byte chunks and displays only the digest calculated from those bytes.
4. The measured report is also saved as `/ext/hashdeep_fz/report.txt`.

NFC, LF RFID, Sub-GHz, infrared, UART captures, and other app data are supported as ordinary saved files. Hashdeep FZ hashes their file bytes; it never presents a UID, frequency, radio identifier, filename, or metadata field as a file hash.

### Verify an expected digest

1. Select the matching algorithm in **Settings**.
2. Open **Expected digest** and enter exactly 32 hexadecimal characters for MD5, 40 for SHA-1, or 64 for SHA-256.
3. Open **Verify Digest** and select the file.
4. The result is `MATCH` only when the actual calculated digest equals the entered value; otherwise it is `MISMATCH`.

Invalid lengths and non-hexadecimal characters are rejected before reading the file.

### Create a recursive manifest

1. Open **Settings → Input folder** and choose SD root, Apps/Tools, NFC, Sub-GHz, LF RFID, Infrared, or Hashdeep input. No slash typing is required.
2. For another existing folder, open **Choose folder via file**, select any file inside that folder, and the app automatically uses its parent directory.
3. In **Settings → Output folder**, choose a slash-free output-folder preset. Use **Manifest filename** to edit only the filename; no `/` entry is required.
4. Open **Create Manifest**.

The app walks the directory with official storage APIs, skips `.` and `..`, limits recursion to 24 levels and paths to 255 bytes, hashes files with all three native algorithms, records the audited root, and streams each record directly to storage. It excludes its current output manifest and app-owned report files, since those are modified by the operation itself. It does not retain the complete tree or manifest in RAM.

If the output already exists, the app requires explicit replacement confirmation. Creation writes and synchronizes a `.partial` file first. The old manifest is retained as a temporary backup until the completed file has been renamed successfully; cancellation, disk-full, or traversal failure removes the partial file and preserves the old manifest.

Native output follows the documented upstream format:

```text
%%%% HASHDEEP-1.0
%%%% size,md5,sha1,sha256,filename
```

### Audit a manifest

Open **Audit Manifest** and select a manifest created by native mode. Every record is parsed and validated before use. The app reopens every named file, hashes its actual bytes, then walks the recorded root to identify actual files absent from the manifest. It reports measured matched, changed, missing, new, malformed, and I/O-error counts. Hexadecimal digests compare without case sensitivity. The manifest itself is excluded if stored within the audited root. Unsupported column layouts are rejected rather than guessed.

Native audit builds an exact bounded path index for at most 1,024 records and 32,768 total path bytes. This removes repeated whole-manifest scans. A larger manifest is rejected explicitly as exceeding the native limit; use external genuine Hashdeep for larger datasets.

### Cancellation and errors

Press **Back** during hashing, manifest creation, or audit to request cancellation. The current bounded read finishes, open files/directories close, and the result is labeled cancelled. Missing media, failed opens, read errors, write errors, path overflow, excessive recursion, malformed records, and unsupported manifests are not reported as successful results.

When a native file or directory read fails, the result includes the exact failure path. This distinguishes a damaged/unreadable entry or SD interruption from a normal end of directory.

Progress is based on actual files and bytes processed and is read through a mutex-protected snapshot. No percentage or ETA is invented when a complete total is unavailable. Reports are also written transactionally; a failed write or synchronization is shown as `REPORT NOT SAVED` rather than being presented as saved.

## External Hashdeep on Raspberry Pi/Linux

External mode runs the real installed `hashdeep` executable. A Raspberry Pi is optional: a spare Linux laptop, desktop, mini PC, or Linux VM with a USB-to-3.3 V UART adapter can provide the same companion role.

1. Follow [EXTERNAL_HASHDEEP.md](EXTERNAL_HASHDEEP.md).
2. Put input files under `/var/lib/hashdeep-fz/input` on the Linux system.
3. Connect crossed 3.3 V UART TX/RX plus common ground. Never connect a 5 V UART signal to the Flipper.
4. Match the baud rate in **Settings** and the bridge command.
5. In **Settings**, select external Hash, Manifest, or Audit.
6. Open **External Hashdeep**. After the bridge identifies the real Hashdeep version, press OK to start the selected genuine operation. Press OK again to cancel.

External `HASH`, `MANIFEST`, and `AUDIT` operations are available from the Flipper through the bounded HDF1 protocol. Full upstream CLI functionality remains available directly on the companion computer.

The bridge never runs received UART text through a shell. It accepts only the exact fixed commands, uses `shell=False`, fixed storage roots, and fixed argument arrays. Output is written and synchronized as a temporary file and promoted only after Hashdeep exits successfully; failed and cancelled external audits preserve the prior report.

## What is and is not supported

Native mode implements the resource-bounded feature set described above. It does not claim native compatibility with every historical md5deep/hashdeep input format, Tiger, Whirlpool, piecewise mode, DFXML, NSRL, iLook, HashKeeper, symlink traversal, or every upstream CLI display option. These features are absent, not simulated. Use genuine external Hashdeep or the Linux CLI for them. See [FEATURE_MATRIX.md](FEATURE_MATRIX.md).

MD5 and SHA-1 remain useful for compatibility with old forensic manifests but are cryptographically broken for collision resistance. Prefer SHA-256 for new integrity records.

## Build and test

Requirements: Python 3, `ufbt` 0.2.6 or newer, and official firmware/SDK 1.4.3 (API 87.1) or compatible.

```powershell
python -m pip install --upgrade ufbt
python -m ufbt update --channel release
python tests/run_tests.py
python tests/test_companion.py
python -m ufbt
```

The build creates `dist/hashdeep_fz.fap`. In a full firmware checkout, place the source at `applications_user/hashdeep_fz` and run:

```sh
./fbt fap_hashdeep_fz
```

## License and upstream

Hashdeep's upstream repository states that most of its code is a U.S. Government work in the public domain, while bundled components have GNU GPL terms. Hashdeep FZ original source is released under **GNU GPL version 2 or later** and preserves the upstream notices. See [LICENSE](LICENSE), [NOTICE](NOTICE), and [UPSTREAM_VERSION.md](UPSTREAM_VERSION.md).

Use this application only on data and systems you own or are authorized to examine.
