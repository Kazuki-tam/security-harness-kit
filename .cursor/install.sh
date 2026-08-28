#!/usr/bin/env bash
# Cloud Agent environment bootstrap for the `shk` repository.
#
# IMPORTANT: This repo ships `.cursor/hooks.json`, which registers *fail-closed*
# Cursor `shk` hooks on beforeShellExecution / beforeReadFile / beforeMCPExecution
# / beforeSubmitPrompt. If the `shk` binary is not on PATH before the agent
# starts, every shell/read/tool call is blocked (exit 127). This script therefore
# builds `shk` and installs it on PATH as part of environment setup so the agent
# is never deadlocked.
#
# Must be idempotent: it can run repeatedly and against cached/partial state.
set -euo pipefail

echo "==> shk env setup: installing system build dependencies"
# shk-cli links libdbus (via the keyring/secret-store dependency); pkg-config is
# needed to discover it. --no-install-recommends keeps the layer small.
sudo apt-get update
sudo apt-get install -y --no-install-recommends libdbus-1-dev pkg-config

echo "==> shk env setup: ensuring Rust toolchain (repo MSRV 1.88; edition2024 needs >= 1.85)"
# The base image ships Rust 1.83, which is too old for the workspace (the Tauri
# desktop crate requires edition2024). Install and default the repo's MSRV.
rustup toolchain install 1.88.0 --profile minimal
rustup default 1.88.0
rustup component add rustfmt clippy

echo "==> shk env setup: building the shk CLI (release)"
cargo build --release -p shk-cli --bin shk

echo "==> shk env setup: installing shk on PATH (required for the fail-closed hooks)"
# /usr/local/cargo/bin is on PATH via ~/.bashrc and is writable by the run user.
install -m 0755 target/release/shk /usr/local/cargo/bin/shk

echo "==> shk env setup: complete"
shk --version
