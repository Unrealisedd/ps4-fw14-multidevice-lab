# Third-party notices

## GoldHEN v2.4b18.13

GoldHEN is separately authored by [SiSTR0](https://github.com/SiSTR0) and contributors. The official project is [GoldHEN/GoldHEN](https://github.com/GoldHEN/GoldHEN); official public binaries, when available, are published through its [releases](https://github.com/GoldHEN/GoldHEN/releases).

This repository includes one exact image from the operator-supplied `GoldHEN_v2.4b18.13.7z` archive after the operator explicitly represented that the image may be publicly redistributed. The archive's bundled README and changelog identify v2.4b18.13 and explicitly list firmware 14.00 support. Attribution is not a claim of authorship, ownership, endorsement, or upstream affiliation. GoldHEN is **not** relicensed under this repository's MIT License.

Included archive and image:

- Archive SHA-256: `ec43e176f4919d5bc262579dbe9a17b4de0dbd9692a8ad0efb71b04aaf31fe73`
- Published filename: `hen.bin` (archive member `goldhen.bin`)
- Size: 297496 bytes (`0x48a18`)
- SHA-256: `39452f5e1c305ac9efcb4745eef7958b4db8c6d85299529f08700970b009ea4d`
- Bundled dependency notices: [`GOLDHEN_LICENSES.txt`](GOLDHEN_LICENSES.txt)

## Exploit lineage and empirical profile

The underlying WebKit/kernel exploit lineage and third-party research remain the work of their respective authors. The active route retains two empirically adopted comparison values:

- `slots = 9100000`
- collection profile `drain:12`

The direct static adapter, release verifier, cleanup integration, tests, and deployment workflow are the original project scope licensed by this repository. See `FW14_MULTIDEVICE_PROVENANCE.txt` for the boundary.

## Console software

No PlayStation system software, decrypted firmware module, game content, private key, account credential, or service token is included. Use the project only on hardware you own or are explicitly authorized to test.
