#!/usr/bin/env sh
set -eu

version="${1:?version is required, without leading v}"
sha256sums="${2:?SHA256SUMS path is required}"
output="${3:?output manifest path is required}"

template="packaging/scoop/shk.json.template"
archive="shk-x86_64-pc-windows-msvc.zip"

if [ ! -f "$template" ]; then
  echo "scoop manifest: missing template: $template" >&2
  exit 1
fi

if [ ! -f "$sha256sums" ]; then
  echo "scoop manifest: missing SHA256SUMS: $sha256sums" >&2
  exit 1
fi

sha256="$(awk -v name="$archive" '$2 == name { print $1 }' "$sha256sums")"
if [ -z "$sha256" ]; then
  echo "scoop manifest: $archive not found in $sha256sums" >&2
  exit 1
fi

mkdir -p "$(dirname "$output")"

python3 - "$template" "$output" "$version" "$sha256" <<'PY'
import sys
from pathlib import Path

template, output, version, sha256 = sys.argv[1:5]
body = Path(template).read_text(encoding="utf-8")
body = body.replace("{{version}}", version)
body = body.replace("{{sha256_x86_64_pc_windows_msvc}}", sha256)
Path(output).write_text(body, encoding="utf-8")
PY

python3 -m json.tool "$output" >/dev/null
echo "scoop manifest: wrote $output"
