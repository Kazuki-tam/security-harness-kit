#!/usr/bin/env sh
set -eu

version="${1:?version is required, without leading v}"
sha256sums="${2:?SHA256SUMS path is required}"
output="${3:?output formula path is required}"

template="packaging/homebrew/shk.rb.template"

if [ ! -f "$template" ]; then
  echo "homebrew formula: missing template: $template" >&2
  exit 1
fi

if [ ! -f "$sha256sums" ]; then
  echo "homebrew formula: missing SHA256SUMS: $sha256sums" >&2
  exit 1
fi

lookup_sha256() {
  archive="$1"
  sha="$(awk -v name="$archive" '$2 == name { print $1 }' "$sha256sums")"
  if [ -z "$sha" ]; then
    echo "homebrew formula: $archive not found in $sha256sums" >&2
    exit 1
  fi
  printf '%s' "$sha"
}

mkdir -p "$(dirname "$output")"

python3 - "$template" "$output" "$version" \
  "$(lookup_sha256 shk-aarch64-apple-darwin.tar.gz)" \
  "$(lookup_sha256 shk-aarch64-unknown-linux-gnu.tar.gz)" \
  "$(lookup_sha256 shk-x86_64-unknown-linux-gnu.tar.gz)" <<'PY'
import sys
from pathlib import Path

(
    template,
    output,
    version,
    sha_aarch64_apple,
    sha_aarch64_linux,
    sha_x86_64_linux,
) = sys.argv[1:7]

body = Path(template).read_text(encoding="utf-8")
replacements = {
    "{{version}}": version,
    "{{sha256_aarch64_apple_darwin}}": sha_aarch64_apple,
    "{{sha256_aarch64_unknown_linux_gnu}}": sha_aarch64_linux,
    "{{sha256_x86_64_unknown_linux_gnu}}": sha_x86_64_linux,
}
for needle, value in replacements.items():
    body = body.replace(needle, value)

Path(output).write_text(body, encoding="utf-8")
PY

if grep -q '{{' "$output"; then
  echo "homebrew formula: unresolved template placeholder in $output" >&2
  exit 1
fi

if command -v ruby >/dev/null 2>&1; then
  ruby -c "$output" >/dev/null
fi

echo "homebrew formula: wrote $output"
