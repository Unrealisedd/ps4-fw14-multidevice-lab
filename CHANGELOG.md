# Changelog

## 1.2.0-fw14-goldhen.1

- Replaced the prior HEN image with the operator-supplied GoldHEN v2.4b18.13 image whose bundled README and changelog explicitly list firmware 14.00 support.
- Pinned the 297496-byte image at SHA-256 `39452f5e1c305ac9efcb4745eef7958b4db8c6d85299529f08700970b009ea4d`, head `e9a6160000`, and rel32 entry target `0x16ab`.
- Preserved the reviewed `0x4000` copy/launch offset and `0x90000` anonymous RWX mapping while migrating every runtime, test, manifest, provenance, and Pages consumer.
- Added the dependency license notices bundled with the supplied GoldHEN archive and recorded its SHA-256 provenance.
- Bumped the static module cache generation so existing browser caches cannot combine old payload contracts with the new image.

Hardware note: on 2026-11-02, the operator reported that this exact local integration "works like a charm" on their owned firmware 14.00 console. No terminal log or About-screen version capture was preserved, so this is an operator observation rather than independently captured telemetry.

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
