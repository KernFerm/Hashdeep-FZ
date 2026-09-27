# Porting analysis

## Upstream architecture

The pinned source separates traversal (`dig.cpp`), streamed file hashing (`hash.cpp`), multi-algorithm contexts (`multihash.cpp`), known-file parsers (`files.cpp`), audit lookup (`hashlist.cpp`), result classification (`display.cpp`), and algorithm implementations. Upstream `hashlist::search` prefers a digest-and-filename match, then evaluates other enabled digests, size, and name. Audit output distinguishes exact, partial/changed, moved, unknown/new, and unused/missing entries.

## Native mapping

Flipper RAM and UI constraints make the upstream C++ containers, pthread pool, desktop filesystem layer, CLI parser, XML output, and unlimited path handling unsuitable for direct compilation. Native mode therefore ports the compatible execution model:

- incremental contexts are initialized once per file;
- each 1024-byte read updates MD5, SHA-1, and SHA-256 together;
- final digests are lowercase hexadecimal;
- recursive traversal streams one manifest row at a time;
- HASHDEEP-1.0 headers, column meanings, decimal sizes, comma handling, and comment behavior follow upstream documentation;
- audit never treats unreadable or malformed input as a match;
- counters represent completed measured work only.

The firmware SDK's maintained mbedTLS contexts replace upstream's old bundled digest sources. This preserves algorithm output while avoiding incompatible desktop wrappers and duplicate crypto code. Known-answer vectors prove the integration at application startup and in host tests.

## Bounded differences

Native manifests use exactly `size,md5,sha1,sha256,filename`. Paths are at most 255 bytes and recursion is at most 24 levels. The parser does not infer alternate legacy formats. Complete known-file tables are not accumulated in RAM; each listed path is verified directly. Features that cannot be implemented honestly within these bounds are marked absent in FEATURE_MATRIX.md.

## External mapping

The HDF1 bridge accepts only HELLO, STATUS, RUN with one of three fixed operation names, and CANCEL. It launches the pinned/installed genuine `hashdeep` program with `shell=False`. External input is rooted at `/var/lib/hashdeep-fz/input`; manifests and reports use fixed paths. Thus upstream remains responsible for full hashing, traversal, parsing, audit, and output behavior.
