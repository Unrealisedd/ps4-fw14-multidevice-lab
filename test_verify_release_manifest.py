from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
