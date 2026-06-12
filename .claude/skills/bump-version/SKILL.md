---
name: bump-version
description: >
  Bump the project version across all files (Cargo.toml, package.json, tauri.conf.json, docs, skills).
  Use when the user says "update version to X.Y.Z", "bump to vX.Y.Z",
  "prepare a release", or makes any request to change the project version number.
---

# bump-version

Use the `xtask` `bump-version` command to update the version number across all files.

## Usage

```bash
cargo run -p xtask -- bump-version <new-version>
```

Example:

```bash
cargo run -p xtask -- bump-version 0.3.8
```

The `v` prefix is optional and will be stripped automatically.

## Updated Files

The command updates all of the following files.

**Bare version (`0.3.8` format)**
- `Cargo.toml` — `[workspace.package] version`
- `crates/shk-cli/Cargo.toml` — internal crate dependencies
- `crates/shk-core/Cargo.toml` — internal crate dependencies
- `apps/shk-desktop/package.json`
- `apps/shk-desktop/src-tauri/tauri.conf.json`
- `apps/shk-desktop/src-tauri/Cargo.toml` — internal crate dependencies

**v-prefixed version (`v0.3.8` format)**
- `README.md`
- `docs/installation.md`
- `docs/ci.md`
- `crates/shk-cli/src/skills/shk.md`
- `.claude/skills/shk/SKILL.md`

## Notes

- Do not edit `Cargo.lock` manually. It is updated automatically when `cargo build` runs.
- The command fails if the new version is the same as the current version.
- If a new file starts carrying a version string, add it to `BARE_VERSION_FILES` or
  `V_VERSION_FILES` in `xtask/src/main.rs`.
