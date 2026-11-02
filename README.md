# PS4 FW14 Direct GoldHEN v2.4b18.13 Lab

Public, click-to-run validation route for an authorized PlayStation 4 on firmware 14.00.

**Live launcher:** <https://unrealisedd.github.io/ps4-fw14-multidevice-lab/>

## Safety boundary

- Use only on consoles you own or are explicitly authorized to test.
- Firmware 14.00 only. The launcher refuses every other canonical browser identity.
- Expect browser or console crashes and possible console-state corruption.
- Make exactly one attempt per cold boot. Never reload, go back, or retry on the same boot.
- Cold reboot after every outcome, including an apparent success.
- A successful browser result means the pinned GoldHEN launch was dispatched through `pthread_create`; runtime readiness still requires a separate visible hardware observation.

The page never auto-runs. It requires an explicit risk acknowledgement and a deliberate **Dispatch GoldHEN v2.4b18.13 once** click.

## Direct test flow

1. Fully power off the authorized console; do not use Rest Mode.
2. Cold boot firmware 14.00.
3. Open <https://unrealisedd.github.io/ps4-fw14-multidevice-lab/> in the console browser.
4. Read and accept the one-attempt warning.
5. Click **Dispatch GoldHEN v2.4b18.13 once** exactly once.
6. Wait for a terminal status. Do not refresh or navigate back.
7. Record the exact status and any visible GoldHEN observation, then cold reboot.

The public route has no OTP, local gateway, IP binding, intent token, telemetry endpoint, or server-side evidence store. Browser session latches reduce accidental same-tab reuse but cannot enforce a reboot across tabs or browser restarts.

Hardware observation (2026-11-02): the operator reported that this exact local integration "works like a charm" on their owned firmware 14.00 console. No terminal log or About-screen version capture was preserved; this is an operator-reported runtime result, not independently captured telemetry.

## Reviewed bundle

GitHub Pages serves one exact static closure plus the authorized GoldHEN v2.4b18.13 image from the same origin:

- GoldHEN release: `v2.4b18.13` with firmware 14.00 support stated in the supplied archive README and changelog
- GoldHEN size: `297496` bytes (`0x48a18`)
- GoldHEN SHA-256: `39452f5e1c305ac9efcb4745eef7958b4db8c6d85299529f08700970b009ea4d`
- Source archive SHA-256: `ec43e176f4919d5bc262579dbe9a17b4de0dbd9692a8ad0efb71b04aaf31fe73`
- Entry contract: head `e9a6160000`, rel32 target `0x16ab`, copy/launch offset `0x4000`
- Patch SHA-256: `165d2ad966b3829d1fbcb53d5e7ecbc20563de4a6a49ee70d8126d0256a49c02`
- Retained empirical profile: `slots=9100000`, collection profile `drain:12`

The stage independently verifies the HEN size, SHA-256, five-byte head, mapping offset, and entry offset before dispatch. Deployment also verifies the complete release inventory, bundled dependency notices, and static dependency graph.

## Verify a checkout or release

```powershell
python -B verify_release_manifest.py --root .
python -B -W error::ResourceWarning -m unittest test_verify_release_manifest
node --test test_github_pages_direct.mjs test_hx1400_jit_dualmap_lease.mjs test_hx1400_goldhen_dualmap_owner.mjs test_hx1400_goldhen_dualmap_stage.mjs
```

The manifest command must report `MANIFEST PASS`. The Pages workflow builds a clean allowlisted artifact; it does not upload the repository wholesale.

## Repository layout

- `fw14_hx1400_goldhen_dualmap_entry.js` — explicit-click and firmware/route gate.
- `fw14_goldhen_direct_contract.js` — direct-route profile and local cryptographic claim contract.
- `jb_hx1400_goldhen_dualmap.js` — browser exploit coordinator.
- `index.html` — direct launcher document deployed as the Pages root.
- `fw14_hx1400_goldhen_dualmap_static.json` — reviewed static dependency inventory.
- `fw14_static_graph.py` — strict static ESM closure loader shared by release verification and retained research receivers.
- `hen.bin` — authorized, hash-pinned GoldHEN image; excluded from the repository's MIT grant.
- `GOLDHEN_LICENSES.txt` — dependency notices bundled with the supplied GoldHEN archive.
- `release-manifest.json` — complete public release inventory.
- `github-pages/` — deployment-only `.nojekyll` and matching release manifest.
- `FW14_MULTIDEVICE_RUNBOOK.txt` — hardware test procedure and result interpretation.

## Provenance and credits

The direct static adapter, route gating, cleanup protocol, release verifier, and deployment workflow are original project work. The underlying exploit lineage and retained empirical profile are separately attributed in [`FW14_MULTIDEVICE_PROVENANCE.txt`](FW14_MULTIDEVICE_PROVENANCE.txt).

GoldHEN v2.4b18.13 is authored by [SiSTR0](https://github.com/SiSTR0) and contributors. This repository does not claim authorship or apply its MIT license to GoldHEN. The operator explicitly represented that this exact binary may be publicly redistributed; see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and [`GOLDHEN_LICENSES.txt`](GOLDHEN_LICENSES.txt).

Engineering and review used OpenAI Codex (`openai-codex/gpt-5.6-sol`) under operator direction. No generated image, audio, or video assets are included.

## License

Original harness code and documentation are licensed under the MIT License. GoldHEN, empirical inputs, and third-party exploit research are excluded from that grant; see [`LICENSE`](LICENSE) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
