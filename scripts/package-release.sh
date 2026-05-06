#!/usr/bin/env bash
set -euo pipefail

target="${1:?target triple is required}"
version="${2:-}"

python3 - "$target" "$version" <<'PY'
import os
import shutil
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

target = sys.argv[1]
version = sys.argv[2]
root = Path.cwd()

if not version:
    in_workspace_package = False
    for line in (root / "Cargo.toml").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "[workspace.package]":
            in_workspace_package = True
            continue
        if stripped.startswith("[") and in_workspace_package:
            break
        if in_workspace_package and stripped.startswith("version ="):
            version = stripped.split("=", 1)[1].strip().strip('"')
            break

if not version:
    raise SystemExit("unable to resolve package version")

is_windows = "windows" in target
exe = ".exe" if is_windows else ""
package_name = f"shk-{target}"
cargo_target_dir = Path(os.environ.get("CARGO_TARGET_DIR", root / "target"))
bin_dir = cargo_target_dir / target / "release"
if not bin_dir.is_dir():
    bin_dir = cargo_target_dir / "release"
dist_root = root / "target" / "dist"
staging = dist_root / "pkg" / package_name

if staging.exists():
    shutil.rmtree(staging)
staging.mkdir(parents=True, exist_ok=True)
dist_root.mkdir(parents=True, exist_ok=True)

for bin_name in ("shk", "security-harness-kit"):
    src = bin_dir / f"{bin_name}{exe}"
    if not src.is_file():
        raise SystemExit(f"missing release binary: {src}")
    dst = staging / src.name
    shutil.copy2(src, dst)
    if not is_windows:
        dst.chmod(dst.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

for doc in ("README.md", "LICENSE"):
    shutil.copy2(root / doc, staging / doc)

(staging / "VERSION").write_text(version + "\n", encoding="utf-8")

if is_windows:
    archive = dist_root / f"{package_name}.zip"
    if archive.exists():
        archive.unlink()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(staging.rglob("*")):
            zf.write(path, path.relative_to(staging.parent))
else:
    archive = dist_root / f"{package_name}.tar.gz"
    if archive.exists():
        archive.unlink()
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(staging, arcname=package_name)

print(archive)
PY
