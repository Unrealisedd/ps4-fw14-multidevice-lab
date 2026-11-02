# Third-party notices

## GoldHEN

GoldHEN is separately authored by [SiSTRo](https://github.com/SiSTR0) and contributors. The official project is [GoldHEN/GoldHEN](https://github.com/GoldHEN/GoldHEN); official public binaries, when available, are published through that repository and its [releases](https://github.com/GoldHEN/GoldHEN/releases).

The official repository does not publish a standard license granting blanket redistribution rights. This repository therefore does **not** redistribute `hen.bin` or relicense GoldHEN under MIT. Operators are responsible for obtaining a lawful external copy. Do not assume the official releases contain the exact FW14-specific reviewed image.

Expected local image:

- Filename: `hen.bin`
- Size: 562240 bytes
- SHA-256: `29ec095fbede651e29954de43411599093138791e62105aaee6fdced58edec06`

## Exploit lineage and empirical profile

The underlying WebKit/kernel exploit lineage and third-party research remain the work of their respective authors. The child route retains two empirically adopted comparison values:

- `slots = 9100000`
- collection profile `drain:12`

The reusable gateway, one-time-code registry, evidence protocol, diagnostics, and public UI are the original scope licensed by this repository. See `FW14_MULTIDEVICE_PROVENANCE.txt` for the exact boundary.

## Console software

No PlayStation system software, decrypted firmware module, game content, private key, account credential, service token, local run evidence, or third-party HEN binary is tracked in this repository. Use the project only on hardware you own or are explicitly authorized to test.
