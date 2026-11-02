# Changelog

## 1.1.0-fw14-direct.1

- Replaced the OTP/local-gateway Pages companion with a deliberate click-to-run firmware 14.00 launcher.
- Added a project-prefix-safe static claim adapter using per-click cryptographic run IDs and challenges.
- Published the operator-authorized, exact hash-pinned GoldHEN image with explicit SiSTR0/GoldHEN attribution and no MIT relicensing claim.
- Removed server intent, telemetry, result, abort, device binding, and durable evidence claims from the public contract.
- Added same-origin HEN delivery, direct-route tests, complete artifact allowlisting, and static dependency-graph verification.
- Removed the obsolete OTP gateway and dedicated GoldHEN server path from the active release.

Hardware note: this release changes hosting and control flow but does not claim a new physical-console result. The direct Pages origin still requires authorized firmware 14.00 hardware validation.

## 1.0.0-fw14-lab.1

- Added an original reusable FW14 local access gateway and console-facing UI.
- Added locally issued 80-bit one-time codes with hash-only persistence, expiry, exact device/IP binding, and atomic redemption.
- Added per-device cold-reboot locks and exact prior-run confirmation.
- Added one-child lifecycle ownership, parent-pipe termination, gateway lease, shutdown fencing, restart recovery, and terminal event settling.
- Added durable privacy-safe gateway events, per-run diagnostics, and the local `diagnose` command.
- Added recoverable fail-closed removal of legacy plaintext code hints.
- Added a static GitHub Pages companion that contains no OTP handling, HEN, or exploit execution.
- Restricted Pages transfer targets to canonical RFC 1918 IPv4 addresses, content-addressed the portal script URL, and added a deployment-gating regression contract.
- Added release integrity metadata, a non-identifying public audit summary, provenance, runbook, tests, and independent security/correctness review.
- Kept the externally supplied GoldHEN image out of the public repository while pinning its expected size and SHA-256.

Hardware note: this historical entry does not provide independently verified physical-console evidence.
