#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import sys

sys.dont_write_bytecode = True

SCRIPT = Path(__file__).with_name("verify-glib-patch.py")
ROOT = SCRIPT.resolve().parents[3]
spec = importlib.util.spec_from_file_location("verify_glib", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BackportIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.package = Path(self.temp.name) / "glib"
        shutil.copytree(ROOT / "vendor/glib", self.package)
        self.manifest = json.loads((ROOT / "vendor/glib-provenance.json").read_text())
        self.lock = (ROOT / "Cargo.lock").read_text()

    def verify(self):
        module.verify(self.package, self.manifest, self.lock)

    def test_reviewed_source_passes(self):
        self.verify()

    def test_unrelated_source_modification_fails(self):
        with (self.package / "src/lib.rs").open("a") as output:
            output.write("\n// unexpected edit\n")
        with self.assertRaises(ValueError):
            self.verify()

    def test_reverted_fix_fails(self):
        path = self.package / "src/variant_iter.rs"
        path.write_text(path.read_text().replace("&mut p,", "&p,"))
        with self.assertRaises(ValueError):
            self.verify()

    def test_extra_file_fails(self):
        (self.package / "unexpected.rs").write_text("// unexpected source\n")
        with self.assertRaises(ValueError):
            self.verify()

    def test_symlink_fails_even_if_content_matches(self):
        path = self.package / "src/lib.rs"
        target = Path(self.temp.name) / "lib.rs"
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises(ValueError):
            self.verify()

    def test_registry_replacement_fails(self):
        self.lock = self.lock.replace('name = "glib"\n', 'name = "glib"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n')
        with self.assertRaises(ValueError):
            self.verify()


if __name__ == "__main__":
    unittest.main()
