#!/usr/bin/env bash
set -euo pipefail

tag="${GITHUB_REF_NAME:?GITHUB_REF_NAME is required}"

if [[ "$tag" != v* ]]; then
  echo "expected tag to start with v, got: $tag" >&2
  exit 1
fi

expected="${tag#v}"
workspace_version="$(awk -F'"' '/^version = / { print $2; exit }' Cargo.toml)"
tauri_version="$(jq -r .version apps/shk-desktop/src-tauri/tauri.conf.json)"
package_version="$(jq -r .version apps/shk-desktop/package.json)"

if [[ "$expected" != "$workspace_version" ]]; then
  echo "workspace version mismatch: tag $tag vs Cargo.toml $workspace_version" >&2
  exit 1
fi

if [[ "$expected" != "$tauri_version" ]]; then
  echo "tauri version mismatch: tag $tag vs tauri.conf.json $tauri_version" >&2
  exit 1
fi

if [[ "$expected" != "$package_version" ]]; then
  echo "package version mismatch: tag $tag vs package.json $package_version" >&2
  exit 1
fi

echo "release versions verified for $tag"
