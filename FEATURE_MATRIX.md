# Feature matrix

| Capability | Native Flipper | External Pi/Linux | Notes |
|---|---:|---:|---|
| Stream actual file bytes | Yes | Yes | Native chunk is 1024 bytes |
| MD5 | Yes, legacy | Yes | Standard lowercase hex |
| SHA-1 | Yes, legacy | Yes | Standard lowercase hex |
| SHA-256 | Yes | Yes | Recommended native default |
| Multiple hashes per file | Manifest mode | Yes | Native manifest calculates all three in one read |
| Single expected-digest verify | Yes | CLI | Exact validated hex |
| Recursive directory hashing | Yes | Yes | Native depth/path bounded |
| HASHDEEP-1.0 manifest creation | Yes | Yes | Native fixed four-column layout |
| Audit matched/changed/missing | Yes | Yes | Measured only |
| New-file audit classification | Yes | Yes | Native manifests record their audited root |
| Malformed manifest rejection | Yes | Yes | No partial success claim |
| Native audit capacity | 1,024 entries / 32 KiB paths | Upstream limits | Oversize is explicit, never an unbounded scan |
| Cancellation | Yes | Yes | Cooperative native; process-group signal external |
| Reports | Yes | Yes | Native report on SD; external report on Linux |
| Tiger / Whirlpool | No | If upstream build supports | Not simulated |
| DFXML / piecewise hashing | No | Yes via CLI | Run directly on Linux |
| NSRL/iLook/HashKeeper formats | No | Yes via upstream CLI | Native accepts its fixed HASHDEEP-1.0 layout |
| Symlink following | No | Upstream option-dependent | Native does not follow links |
| NFC/RFID/Sub-GHz identifiers as hashes | No | No | Saved capture files can be hashed as bytes |

“External” means the genuine installed Hashdeep executable, not a reimplementation in the bridge.
