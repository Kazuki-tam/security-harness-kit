#!/usr/bin/env bash
set -euo pipefail

# Keep coverage focused on testable Rust logic. Generated rules, Tauri shell
# boundaries, and external tool wrappers are still covered by smoke/targeted tests,
# but excluded from the line gate to avoid chasing process/host-specific branches.
# Vendored upstream glib retains dependency status for this first-party metric;
# its exact backport is separately hash-verified and tested in optimized Linux CI.
readonly IGNORE_FILENAME_REGEX='(vendor/glib/|crates/shk-rules/src/gitleaks_rules\.rs|apps/shk-desktop/src-tauri/src/(lib|main)\.rs|xtask/src/main\.rs|crates/shk-cli/src/(desktop_api|env_store)\.rs|crates/shk-cli/src/hooks/(ai|git)\.rs|crates/shk-cli/src/commands/(env|secrets)\.rs)'

cargo llvm-cov --workspace --all-features \
  --ignore-filename-regex "${IGNORE_FILENAME_REGEX}" \
  --fail-under-lines 90 \
  "$@"
