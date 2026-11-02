from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

import fw14_static_graph as static_graph


SCHEMA = "oms.fw14-goldhen-direct.release.v1"
STATIC_SCHEMA = "oms.fw14-hx1400-goldhen-dualmap.static.v1"
STATIC_PAGE = "/index.html"
HEN_SHA256 = "29ec095fbede651e29954de43411599093138791e62105aaee6fdced58edec06"
HEN_SIZE = 0x89440
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
EXCLUDED = frozenset({"release-manifest.json", "github-pages/release-manifest.json"})


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def exact_keys(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise ValueError(f"{label} keys mismatch: {actual}")
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
        if name not in EXCLUDED:
            files.add(name)
    return files


def load_static_manifest(root: Path) -> str:
    path = root / "fw14_hx1400_goldhen_dualmap_static.json"
    document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    document = exact_keys(document, {"schema", "files"}, "static manifest")
    if document["schema"] != STATIC_SCHEMA:
        raise ValueError("static manifest schema mismatch")
    files = document["files"]
    if not isinstance(files, dict) or not files:
        raise ValueError("static manifest files map is invalid")
    for name, digest in files.items():
        if (
            not isinstance(name, str)
            or not name.startswith("/")
            or not isinstance(digest, str)
            or HEX64.fullmatch(digest) is None
        ):
            raise ValueError("static manifest file entry is invalid")
    _payloads, _hashes, graph_digest = static_graph.load_static_graph(
        root,
        files,
        stage_page=STATIC_PAGE,
    )
    return graph_digest


def verify_hen(root: Path, files: dict[str, str], declared_digest: object) -> None:
    if declared_digest != HEN_SHA256 or files.get("hen.bin") != HEN_SHA256:
        raise ValueError("release manifest HEN digest mismatch")
    checksum = (root / "HEN_EXPECTED_SHA256.txt").read_text(encoding="ascii").split()
    if checksum != [HEN_SHA256, "hen.bin"]:
        raise ValueError("expected HEN checksum file mismatch")
    hen = root / "hen.bin"
    if hen.is_symlink() or not hen.is_file():
        raise ValueError("required HEN is missing or not regular")
    if hen.stat().st_size != HEN_SIZE:
        raise ValueError("required HEN size mismatch")
    if sha256(hen) != HEN_SHA256:
        raise ValueError("required HEN digest mismatch")


def verify(root: Path) -> tuple[str, int]:
    root = root.resolve(strict=True)
    manifest_path = root / "release-manifest.json"
    pages_manifest = root / "github-pages" / "release-manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    if pages_manifest.read_bytes() != manifest_bytes:
        raise ValueError("root and GitHub Pages release manifests differ")
    manifest = json.loads(manifest_bytes.decode("utf-8"), object_pairs_hook=reject_duplicates)
    manifest = exact_keys(
        manifest,
        {"schema", "version", "staticGraphSha256", "henSha256", "files"},
        "release manifest",
    )
    if manifest["schema"] != SCHEMA:
        raise ValueError("release manifest schema mismatch")
    version = manifest["version"]
    files = manifest["files"]
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
        if sha256(path) != expected:
            raise ValueError(f"release file digest mismatch: {name}")
        declared.add(name)

    actual_files = tracked_files(root)
    missing = sorted(actual_files - declared)
    stale = sorted(declared - actual_files)
    if missing or stale:
        raise ValueError(f"release inventory mismatch: unlisted={missing} stale={stale}")

    verify_hen(root, files, manifest["henSha256"])
    static_digest = load_static_manifest(root)
    if manifest["staticGraphSha256"] != static_digest:
        raise ValueError("release manifest static graph mismatch")
    return version, len(declared)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the complete FW14 direct release inventory.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    version, count = verify(args.root)
    print(f"MANIFEST PASS version={version} files={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
