# Changelog

## 1.0.0-fw14-lab.1

- Added an original reusable FW14 local access gateway and console-facing UI.
- Added locally issued 80-bit one-time codes with hash-only persistence, expiry, exact device/IP binding, and atomic redemption.
- Added per-device cold-reboot locks and exact prior-run confirmation.
- Added one-child lifecycle ownership, parent-pipe termination, gateway lease, shutdown fencing, restart recovery, and terminal event settling.
- Added durable privacy-safe gateway events, per-run diagnostics, and the local `diagnose` command.
- Added recoverable fail-closed removal of legacy plaintext code hints.
- Added a static GitHub Pages companion that contains no OTP handling, HEN, or exploit execution.
- Added release integrity metadata, a non-identifying public audit summary, provenance, runbook, tests, and independent security/correctness review.
- Kept the externally supplied GoldHEN image out of the public repository while pinning its expected size and SHA-256.

Hardware note: this publication does not add a new hardware attempt. The retained child route was previously hardware-proven; visible GoldHEN readiness remains operator-observed.
