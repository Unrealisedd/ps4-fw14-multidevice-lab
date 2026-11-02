from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any
import serve_fw14_hx1400_goldhen_dualmap as child


SCHEMA = "oms.fw14-hx1400-access.release.v1"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
EXCLUDED = frozenset({"release-manifest.json", "github-pages/release-manifest.json"})
OPTIONAL_LOCAL = frozenset({"hen.bin"})


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def tracked_files(root: Path) -> set[str]:
    files: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == ".git":
            continue
        if path.is_symlink():
            raise ValueError(f"release tree contains a symlink: {relative.as_posix()}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"release tree contains a non-regular entry: {relative.as_posix()}")
        name = relative.as_posix()
        if name not in EXCLUDED and name not in OPTIONAL_LOCAL:
            files.add(name)
    return files


def verify(root: Path) -> tuple[str, int]:
    root = root.resolve(strict=True)
    manifest_path = root / "release-manifest.json"
    pages_manifest = root / "github-pages" / "release-manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    if pages_manifest.read_bytes() != manifest_bytes:
        raise ValueError("root and GitHub Pages release manifests differ")
    manifest = json.loads(
        manifest_bytes.decode("utf-8"),
        object_pairs_hook=reject_duplicates,
    )
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise ValueError("release manifest schema mismatch")
    version = manifest.get("version")
    files = manifest.get("files")
    if not isinstance(version, str) or not version:
        raise ValueError("release manifest version is invalid")
    if not isinstance(files, dict) or not files:
        raise ValueError("release manifest files map is invalid")

    declared: set[str] = set()
    for name, expected in files.items():
        if not isinstance(name, str) or not isinstance(expected, str):
            raise ValueError("release manifest file entry is invalid")
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or name in EXCLUDED:
            raise ValueError(f"release manifest path is unsafe: {name}")
        if HEX64.fullmatch(expected) is None:
            raise ValueError(f"release manifest digest is invalid: {name}")
        path = root.joinpath(*pure.parts)
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"release file is missing or not regular: {name}")
        actual = sha256(path)
        if actual != expected:
            raise ValueError(f"release file digest mismatch: {name}")
        declared.add(name)

    actual_files = tracked_files(root)
    missing = sorted(actual_files - declared)
    stale = sorted(declared - actual_files)
    if missing or stale:
        raise ValueError(f"release inventory mismatch: unlisted={missing} stale={stale}")

    aliases = {
        "accessTemplateSha256": "fw14_hx1400_access.html",
        "gatewaySha256": "serve_fw14_hx1400_access.py",
    }
    for field, name in aliases.items():
        value = manifest.get(field)
        if not isinstance(value, str) or value != files.get(name):
            raise ValueError(f"release manifest alias mismatch: {field}")
    expected_hen = manifest.get("henSha256")
    if (
        not isinstance(expected_hen, str)
        or HEX64.fullmatch(expected_hen) is None
        or expected_hen != child.HEN_SHA256
    ):
        raise ValueError("release manifest HEN digest mismatch")
    checksum = (root / "HEN_EXPECTED_SHA256.txt").read_text(encoding="ascii").split()
    if checksum != [expected_hen, "hen.bin"]:
        raise ValueError("expected HEN checksum file mismatch")
    local_hen = root / "hen.bin"
    if local_hen.exists() and (local_hen.is_symlink() or sha256(local_hen) != expected_hen):
        raise ValueError("locally staged HEN digest mismatch")
    _payloads, _hashes, static_graph = child.load_manifest(root)
    if manifest.get("staticGraphSha256") != static_graph:
        raise ValueError("release manifest static graph mismatch")
    return version, len(declared)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the complete FW14 release inventory.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    version, count = verify(args.root)
    print(f"MANIFEST PASS version={version} files={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
