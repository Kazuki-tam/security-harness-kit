#!/usr/bin/env python3
"""Verify the complete vendored crate and the two-line upstream safety backport."""
import hashlib
import json
from pathlib import Path
import re
import sys


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify(package, manifest, lockfile):
    if package.is_symlink():
        raise ValueError("vendored package must not be a symlink")
    expected = dict(manifest["upstream_files"])
    if set(manifest["patched_files"]) != {"src/variant_iter.rs"}:
        raise ValueError("only the reviewed iterator backport is allowed")
    expected.update(manifest["patched_files"])
    actual = {}
    for path in package.rglob("*"):
        if path.is_symlink():
            raise ValueError("vendored package contains a symlink")
        if path.is_file():
            actual[path.relative_to(package).as_posix()] = digest(path.read_bytes())
    if actual != expected:
        raise ValueError("vendored files differ from the reviewed provenance manifest")
    patched = (package / "src/variant_iter.rs").read_bytes()
    original = patched.replace(
        b"let mut p: *mut libc::c_char = std::ptr::null_mut();",
        b"let p: *mut libc::c_char = std::ptr::null_mut();",
    ).replace(b"                &mut p,", b"                &p,")
    if original == patched or digest(original) != manifest["upstream_files"]["src/variant_iter.rs"]:
        raise ValueError("backport differs from the reviewed upstream fix")
    entries = lockfile.split("[[package]]")
    selected = [entry for entry in entries if re.search(r'^name = "glib"$', entry, re.M)]
    if len(selected) != 1 or 'version = "0.18.5"' not in selected[0] or re.search(r'^source =', selected[0], re.M):
        raise ValueError("Cargo.lock must select only the local patched glib 0.18.5")


def main():
    root = Path(__file__).resolve().parents[3]
    manifest = json.loads((root / "vendor/glib-provenance.json").read_text())
    verify(root / "vendor/glib", manifest, (root / "Cargo.lock").read_text())
    print("glib upstream package hashes and RUSTSEC-2024-0429 backport verified")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
