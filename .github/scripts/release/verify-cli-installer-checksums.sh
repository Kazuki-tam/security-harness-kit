#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

assets_dir="${1:-target/distrib}"
installer="${assets_dir}/shk-cli-installer.sh"

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{ print $1 }'
  else
    shk_error "sha256sum or shasum is required"
    exit 1
  fi
}

if [[ ! -f "$installer" ]]; then
  shk_error "shell installer not found: ${installer}"
  exit 1
fi

shopt -s nullglob
checksum_files=(
  "$assets_dir"/shk-cli-*.tar.xz.sha256
  "$assets_dir"/shk-cli-*.zip.sha256
)
shopt -u nullglob

if [[ "${#checksum_files[@]}" -eq 0 ]]; then
  shk_error "no CLI archive checksum files found in ${assets_dir}"
  exit 1
fi

installer_archives=()
verified=0
while IFS='|' read -r archive checksum_style embedded_digest; do
  [[ -n "$archive" ]] || continue

  archive_file="${assets_dir}/${archive}"
  checksum_file="${assets_dir}/${archive}.sha256"
  if [[ ! -f "$archive_file" ]]; then
    shk_error "shell installer archive not found: ${archive_file}"
    exit 1
  fi
  if [[ ! -f "$checksum_file" ]]; then
    shk_error "checksum file not found for shell installer archive: ${checksum_file}"
    exit 1
  fi

  digest="$(awk 'NR == 1 { print tolower($1) }' "$checksum_file")"
  if [[ ! "$digest" =~ ^[0-9a-fA-F]{64}$ ]]; then
    shk_error "invalid SHA-256 in ${checksum_file}"
    exit 1
  fi

  actual_digest="$(sha256_file "$archive_file" | tr '[:upper:]' '[:lower:]')"
  if [[ "$actual_digest" != "$digest" ]]; then
    shk_error "published SHA-256 does not match archive: ${archive}"
    exit 1
  fi

  embedded_digest="$(printf '%s' "$embedded_digest" | tr '[:upper:]' '[:lower:]')"
  if [[ "$checksum_style" != "sha256" || "$embedded_digest" != "$digest" ]]; then
    shk_error "SHA-256 is not embedded for shell installer archive: ${archive}"
    exit 1
  fi

  installer_archives+=("$archive")
  verified=$((verified + 1))
done < <(
  awk '
    /^[[:space:]]*"shk-cli-[^"]+\.(tar\.xz|zip)"\)$/ {
      archive = $0
      sub(/^[[:space:]]*"/, "", archive)
      sub(/"\)$/, "", archive)
      checksum_style = ""
      checksum_value = ""
      next
    }
    archive != "" && /^[[:space:]]*_checksum_style="/ {
      checksum_style = $0
      sub(/^[[:space:]]*_checksum_style="/, "", checksum_style)
      sub(/"$/, "", checksum_style)
      next
    }
    archive != "" && /^[[:space:]]*_checksum_value="/ {
      checksum_value = $0
      sub(/^[[:space:]]*_checksum_value="/, "", checksum_value)
      sub(/"$/, "", checksum_value)
      next
    }
    archive != "" && /^[[:space:]]*;;[[:space:]]*$/ {
      print archive "|" checksum_style "|" checksum_value
      archive = ""
    }
  ' "$installer"
)

if [[ "$verified" -eq 0 ]]; then
  shk_error "shell installer contains no CLI archive entries: ${installer}"
  exit 1
fi

if [[ "$verified" -ne "${#checksum_files[@]}" ]]; then
  shk_error "shell installer archive count (${verified}) does not match CLI checksum count (${#checksum_files[@]})"
  exit 1
fi

for checksum_file in "${checksum_files[@]}"; do
  expected_archive="$(basename "$checksum_file" .sha256)"
  found=false
  for archive in "${installer_archives[@]}"; do
    if [[ "$archive" == "$expected_archive" ]]; then
      found=true
      break
    fi
  done
  if [[ "$found" != true ]]; then
    shk_error "shell installer has no archive entry for: ${expected_archive}"
    exit 1
  fi
done

echo "verified ${verified} shell installer archive checksum(s)"
