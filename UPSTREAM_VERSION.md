# Upstream version

- Project: Hashdeep / md5deep
- Repository: <https://github.com/jessek/hashdeep>
- Pinned revision: `877613493ff44807888ce1928129574be393cbb0`
- Commit date: `2017-08-24T08:51:32-07:00`
- Commit subject: `Merge pull request #361 from kraj/master`
- File format: `HASHDEEP-1.0`, documented by upstream `FILEFORMAT`

The revision was cloned and inspected on 2026-09-26. Relevant upstream files include `src/hash.cpp`, `src/multihash.cpp`, `src/hashlist.cpp`, `src/files.cpp`, `src/display.cpp`, `src/md5.c`, `src/sha1.c`, `src/sha256.c`, `FILEFORMAT`, and `tests/`.

The native port uses the official firmware's incremental mbedTLS digest implementations for bounded platform integration and implements compatible standard digest output and upstream manifest semantics. External mode invokes the genuine upstream `hashdeep` executable.
