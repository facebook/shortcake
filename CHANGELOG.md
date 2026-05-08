# Changelog

## 0.1.0-pre.4

- Protocol hardening: bound session key to the full transcript, standardized
  hashes to length-prefixed field encoding, and pinned test vectors against
  non-backwards-compatible changes.
- Security fixes: constant-time reflection check, removed unsafe zeroization
  paths, fixed `Responder` deserialization panic and rejected invalid states.
- Added serde support for `Initiator` and `Responder` (via derive).
- Misc cleanups: domain separation constants, `xwing` benchmark guidance,
  KDF nits, code dedup, and added error-path integration tests.
