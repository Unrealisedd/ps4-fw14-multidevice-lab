# Public audit summary

## Direct static route

The active Pages route is a deliberate click-to-run firmware 14.00 launcher. It does not execute the exploit or fetch GoldHEN on document load. The launcher requires:

- the canonical PlayStation 4 firmware 14.00 browser identity;
- the exact GitHub Pages project root with no query or fragment;
- explicit acknowledgement of the one-attempt warning;
- a deliberate button click;
- successful session-latch readback before importing the exploit client.

The client creates a cryptographically random local run ID and challenge. GoldHEN is fetched from the same origin only after exploit retirement and is independently checked for exact size, SHA-256, head bytes, mapping offset, and entry offset before dispatch.

## Preserved source-derived properties

- The source13 owner oracle is live-attested before credential mutation.
- Write and execute credential phases remain distinct and restore exact originals.
- The 632-byte patch uses distinct RW and RX aliases.
- Patch execution, 24 guard checks, alias release, descriptor release, and exploit-authority retirement precede HEN fetch/mapping.
- The HEN mapping remains the pinned anonymous RWX path required by this self-writing image.
- Cleanup failures retain/quarantine authority rather than falsely reporting a clean result.
- A successful result means dispatch occurred; `goldhenRuntimeObserved` remains false until a separate hardware observation.

## Removed server properties

The version 1.1 public route intentionally removes the version 1.0 OTP/local-server boundary. GitHub Pages cannot provide source-IP binding, a server-held intent, atomic claim consumption, durable boot tombstones, durable telemetry, server-side result validation, or abort fencing. The public UI and documentation do not claim those properties.

Browser session storage reduces accidental same-tab reuse but does not prove a cold reboot and cannot stop a user from opening another tab or clearing browser state.

## Publication boundary

The deployment workflow verifies the complete release inventory, reviewed static dependency graph, direct-launch contract, and exact HEN digest before constructing a clean allowlisted Pages artifact. The repository and release include no private hardware-run identifiers, local evidence files, credentials, or workstation paths.

This is a source-derived and deployment audit. A successful Pages deployment or desktop-browser smoke test is not evidence of a new physical-console result.
