# Public audit summary

This summary contains immutable source-derived conclusions only. Local hardware-run IDs, archive names, timestamps, result hashes, device evidence, and observed failure records are intentionally excluded from the public repository.

## Reviewed static contracts

- The child serves an exact 12-file static closure with graph SHA-256 `76451f8bc1229c01ab738716efd7af633285d765e5b444b2ff8b9a74cd4254fe`.
- Prepatch JIT access uses distinct writable (`RW`, protection 3) and executable (`RX`, protection 5) aliases over the same descriptor and exact `0x90000` range.
- No prepatch RWX mapping is part of the reviewed route.
- Credential bits are restored to their exact original value between write and execute lease phases.
- The patch path verifies 24 stock and 24 patched guard readbacks.
- Cleanup order is executable alias, writable alias, then descriptor; uncertain cleanup or credential outcomes quarantine the run.
- Exploit authority is retired before the postpatch HEN mapping and pthread dispatch.
- The expected external HEN is pinned to 562240 bytes and SHA-256 `29ec095fbede651e29954de43411599093138791e62105aaee6fdced58edec06`.
- The child result schema contains 93 exact fields and distinguishes dispatch evidence from runtime readiness.
- Per-device boot tombstones require an operator-attested cold reboot and exact prior run ID before another code may be issued.

## Public evidence limits

These are byte-pinned source and contract conclusions, not a public hardware evidence archive. The operator reported a visible GoldHEN load from the retained child route, but runtime readiness remains operator-observed. Firmware identity is canonical browser-UA gating rather than cryptographic attestation. Cold reboot completion is operator-attested.

The complete local evidence remains outside this repository. See `FW14_MULTIDEVICE_PROVENANCE.txt` for the original/external boundary and `FW14_MULTIDEVICE_RUNBOOK.txt` for evidence handling.
