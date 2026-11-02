# PS4 FW14 Multi-Device Lab

Reusable, fail-closed validation harness for authorized PlayStation 4 firmware 14.00 hardware research.

Live static companion: <https://unrealisedd.github.io/ps4-fw14-multidevice-lab/>

The GitHub Pages site publishes release integrity metadata and transfers the console browser to an operator-controlled gateway on the same isolated network. It does **not** issue access codes, receive access codes, host the payload, or run the exploit.

## Safety boundary

- Use only on consoles you own or are explicitly authorized to test.
- Expect browser or console crashes. Fully cold-boot before each authorized attempt.
- One code authorizes one configured device address and one run.
- Never refresh, go back, or retry on the same boot.
- Do not expose the local gateway to the internet or place it behind a public tunnel.
- Firmware enforcement is canonical browser-identity gating, not cryptographic firmware attestation.
- GoldHEN dispatch is protocol evidence; visible runtime readiness remains an operator observation.

## What is included

- Original local access page, one-time-code registry, device binding, child coordinator, diagnostics, and GitHub Pages companion.
- Byte-pinned FW14 dual-map child route and 12-file static closure.
- Expected external HEN: 562240 bytes, SHA-256 `29ec095fbede651e29954de43411599093138791e62105aaee6fdced58edec06`. `hen.bin` is deliberately not redistributed.
- Reproducible tests, public audit summary, release manifest, runbook, and provenance statement.

Read these before use:

- [`FW14_MULTIDEVICE_RUNBOOK.txt`](FW14_MULTIDEVICE_RUNBOOK.txt)
- [`FW14_MULTIDEVICE_PROVENANCE.txt`](FW14_MULTIDEVICE_PROVENANCE.txt)
- [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)
- [`AUDIT_SUMMARY.md`](AUDIT_SUMMARY.md)

## Requirements

- Windows operator host tested with Python 3.12 and Node.js 22.
- Authorized PS4 on firmware 14.00.
- Operator host and console on the same trusted, isolated IPv4 network.
- Administrator rights if binding the gateway to TCP port 80.
- A legally obtained external `hen.bin` matching `HEN_EXPECTED_SHA256.txt`; see the official GoldHEN project reference in `THIRD_PARTY_NOTICES.md`.

## Verify the release

The complete repository inventory check does not require the external HEN. Stage the reviewed `hen.bin` at the repository root before running the gateway check:

```powershell
python -B verify_release_manifest.py --root .
python -B serve_fw14_hx1400_access.py check --root . --hen hen.bin --hen-sha256 29ec095fbede651e29954de43411599093138791e62105aaee6fdced58edec06
python -B -W error::ResourceWarning -m unittest test_verify_release_manifest test_serve_fw14_hx1400_access test_serve_fw14_hx1400_goldhen_dualmap
node --test test_github_pages_portal.mjs test_hx1400_jit_dualmap_lease.mjs test_hx1400_goldhen_dualmap_owner.mjs test_hx1400_goldhen_dualmap_stage.mjs
```

The manifest check verifies every public file, rejects symlinks, and validates the expected external HEN metadata. After `hen.bin` is staged, the offline gateway check must report `registryMutated=false`, `serverConstructed=false`, and `bound=false`.

## Start the local gateway

Create mutable state outside this repository, then run from an elevated PowerShell prompt. Replace addresses with the operator host and authorized console subnet:

```powershell
mkdir C:\FW14-Lab-State
python -B serve_fw14_hx1400_access.py serve --host 192.168.1.83 --public-host 192.168.1.83 --port 80 --child-port 8080 --client-cidr 192.168.1.0/24 --registry C:\FW14-Lab-State\access.sqlite3 --runs-root C:\FW14-Lab-State\runs --root . --hen hen.bin --hen-sha256 29ec095fbede651e29954de43411599093138791e62105aaee6fdced58edec06 --trusted-isolated-network
```

The gateway prints `READY http://192.168.1.83/` after all pinned inputs validate.

## Issue one local code

Use a stable operator-assigned device ID and the exact IPv4 currently shown by that console:

```powershell
python -B serve_fw14_hx1400_access.py issue --registry C:\FW14-Lab-State\access.sqlite3 --runs-root C:\FW14-Lab-State\runs --device-id lab-ps4-01 --expected-client 192.168.1.106 --ttl-minutes 30
```

The 80-bit code is displayed once. Only its domain-separated SHA-256 is stored. Open the live companion or `http://192.168.1.83/` on the console, enter that code, and follow the child page exactly once.

## Diagnose a failure immediately

Newest run:

```powershell
python -B serve_fw14_hx1400_access.py diagnose --registry C:\FW14-Lab-State\access.sqlite3 --runs-root C:\FW14-Lab-State\runs
```

Exact run:

```powershell
python -B serve_fw14_hx1400_access.py diagnose --registry C:\FW14-Lab-State\access.sqlite3 --runs-root C:\FW14-Lab-State\runs --run-id <exact-32-character-run-or-redemption-id>
```

Diagnostics preserve phase boundaries, child exits, browser tags, and artifact hashes without storing OTP plaintext, child intents/challenges, kernel addresses, or browser telemetry detail.

## Retest after a real cold reboot

```powershell
python -B serve_fw14_hx1400_access.py confirm-reboot --registry C:\FW14-Lab-State\access.sqlite3 --runs-root C:\FW14-Lab-State\runs --device-id lab-ps4-01 --after-run <exact-prior-run-id> --expected-client 192.168.1.106
```

Never use `confirm-reboot` to bypass an ambiguous or same-boot result.

## Repository layout

- `github-pages/` — the only directory deployed to GitHub Pages.
- `serve_fw14_hx1400_access.py` — reusable local gateway and CLI.
- `fw14_hx1400_access.html` — console-facing local access page.
- `serve_fw14_hx1400_goldhen_dualmap.py` — pinned one-shot child.
- `release-manifest.json` — complete tracked-file integrity inventory.
- `HEN_EXPECTED_SHA256.txt` — expected external HEN identity; the binary is ignored and not redistributed.
- `AUDIT_SUMMARY.md` — non-identifying source-derived audit conclusions.
- `FW14_MULTIDEVICE_RUNBOOK.txt` — full operator procedure.
- `FW14_MULTIDEVICE_PROVENANCE.txt` — original/external boundary.

Mutable registries, events, logs, run evidence, and boot tombstones are intentionally excluded from version control.

## Maintainer Pages deployment

For a newly created repository, enable **Settings → Pages → Source: GitHub Actions** before the first deployment, then push `main` or manually dispatch `Deploy Pages companion`. The workflow verifies the complete release inventory and builds a clean artifact containing exactly `.nojekyll`, `index.html`, `portal.js`, and `release-manifest.json`.

## Provenance and credits

The reusable gateway, access control, evidence protocol, diagnostics, and public UI are original implementations in this project. The child retains two empirically adopted profile values—`slots=9100000` and `drain:12`—because changing hardware-proven behavior for cosmetic reasons would reduce correctness. GoldHEN and the underlying public exploit lineage are separately authored and are not claimed as original work here.

Engineering and review used OpenAI Codex (`openai-codex/gpt-5.6-sol`) under operator direction. Hardware observations and authorization boundaries were supplied by the operator. No generated image, audio, or video assets are included.

## Uninstall

Stop the gateway. A full console cold reboot clears runtime-only state. Delete the external state directory only after preserving any evidence you need. Removing the cloned repository removes the host-side package.

## License

Original harness code and documentation are licensed under the MIT License. Third-party payloads, empirical inputs, and underlying exploit research are excluded; see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
