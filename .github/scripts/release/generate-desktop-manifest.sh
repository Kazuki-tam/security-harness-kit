#!/usr/bin/env bash
set -euo pipefail

assets_dir="${1:-release-assets}"
out="${2:-${assets_dir}/shk-desktop-latest.json}"
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
release_tag="${RELEASE_TAG:?RELEASE_TAG is required}"
version="${RELEASE_VERSION:?RELEASE_VERSION is required}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

shk_require_semver "$version"

if [[ ! -d "$assets_dir" ]]; then
  echo "assets directory not found: ${assets_dir}" >&2
  exit 1
fi

shopt -s nullglob
files=( "${assets_dir}"/shk-desktop_* )

filtered=()
for file in "${files[@]}"; do
  case "$(basename "$file")" in
    shk-desktop.sha256sum | shk-desktop-latest.json)
      ;;
    *)
      [[ -f "$file" ]] && filtered+=( "$file" )
      ;;
  esac
done

if ((${#filtered[@]} == 0)); then
  echo "no desktop release assets found in ${assets_dir}" >&2
  exit 1
fi

assets_json="$(mktemp)"
printf '[]' > "$assets_json"

base_url="https://github.com/${repo}/releases/download/${release_tag}"
for file in "${filtered[@]}"; do
  name="$(basename "$file")"
  sha256="$(sha256sum "$file" | awk '{print $1}')"
  tmp="$(mktemp)"
  jq \
    --arg name "$name" \
    --arg url "${base_url}/${name}" \
    --arg sha256 "$sha256" \
    '. + [{name: $name, url: $url, sha256: $sha256}]' \
    "$assets_json" > "$tmp"
  mv "$tmp" "$assets_json"
done

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg schema "https://security-harness-kit.local/schemas/shk-desktop-release.v1.json" \
  --arg product "shk-desktop" \
  --arg version "$version" \
  --arg repo "$repo" \
  --arg tag "$release_tag" \
  --arg generated_at "$generated_at" \
  --slurpfile assets "$assets_json" \
  '{schema: $schema, product: $product, version: $version, repository: $repo, release_tag: $tag, generated_at: $generated_at, assets: $assets[0]}' \
  > "$out"

rm -f "$assets_json"
echo "wrote ${out}"
