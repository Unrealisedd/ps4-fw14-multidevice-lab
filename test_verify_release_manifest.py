from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

import verify_release_manifest as target


class ReleaseManifestBoundaryTests(unittest.TestCase):
    def test_inventory_rejects_any_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target_file = root / "target.txt"
            target_file.write_text("target", encoding="utf-8")
            link = root / "unlisted-link"
            try:
                os.symlink(target_file.name, link)
            except OSError as error:
                self.skipTest(f"symlink creation is unavailable: {error}")
            with self.assertRaisesRegex(ValueError, "symlink"):
                target.tracked_files(root)

    def test_inventory_requires_the_bundled_hen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "hen.bin").write_bytes(b"reviewed-payload")
            self.assertEqual(target.tracked_files(root), {"hen.bin"})

    def test_manifest_shapes_reject_extra_keys(self) -> None:
        with self.assertRaisesRegex(ValueError, "keys mismatch"):
            target.exact_keys(
                {"schema": "value", "files": {}, "unexpected": True},
                {"schema", "files"},
                "fixture",
            )

    def test_static_graph_follows_versioned_module_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payloads = {
                "/index.html": b'<script type="module" src="./main.js?v=reviewed"></script>',
                "/main.js": b'import "./dependency.js?v=reviewed";\n',
                "/dependency.js": b"export const reviewed = true;\n",
            }
            expected: dict[str, str] = {}
            for name, payload in payloads.items():
                root.joinpath(name.removeprefix("/")).write_bytes(payload)
                expected[name] = hashlib.sha256(payload).hexdigest()

            _payloads, hashes, graph_digest = target.static_graph.load_static_graph(
                root,
                expected,
                stage_page="/index.html",
            )

            self.assertEqual(dict(hashes), expected)
            graph_input = "".join(
                f"{name} {expected[name]}\n" for name in sorted(expected)
            ).encode("ascii")
            self.assertEqual(graph_digest, hashlib.sha256(graph_input).hexdigest())


if __name__ == "__main__":
    unittest.main()
