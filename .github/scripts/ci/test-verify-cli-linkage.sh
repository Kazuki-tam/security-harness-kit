#!/usr/bin/env bash
# Exercise verify-cli-linkage.sh against stubbed readelf output.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
guard="$ROOT/.github/scripts/ci/verify-cli-linkage.sh"

stub_dir="$(mktemp -d)"
trap 'rm -rf "$stub_dir"' EXIT

cat >"$stub_dir/readelf" <<'STUB'
#!/usr/bin/env bash
[[ -n "${STUB_READELF_FAIL:-}" ]] && exit 1
for lib in $STUB_NEEDED; do
  printf ' 0x0000000000000001 (NEEDED)             Shared library: [%s]\n' "$lib"
done
printf ' 0x000000000000000c (INIT)               0x1000\n'
STUB
chmod +x "$stub_dir/readelf"

check() { # expected-status description needed-libs
  local status=0
  PATH="$stub_dir:$PATH" STUB_NEEDED="$3" "$guard" shk >/dev/null 2>&1 || status=$?
  if [[ "$status" != "$1" ]]; then
    echo "FAIL: $2 (expected exit $1, got $status)" >&2
    exit 1
  fi
  echo "ok: $2"
}

check 0 "accepts the x86_64 C runtime" "libgcc_s.so.1 libm.so.6 libc.so.6 ld-linux-x86-64.so.2"
check 0 "accepts the aarch64 C runtime" "libgcc_s.so.1 libm.so.6 libc.so.6 ld-linux-aarch64.so.1"
check 1 "rejects libdbus" "libdbus-1.so.3 libc.so.6"
check 1 "rejects a library that only starts like an allowed one" "libcrypto.so.3 libc.so.6"
check 1 "rejects a binary with no NEEDED entries" ""

status=0
PATH="$stub_dir:$PATH" STUB_READELF_FAIL=1 STUB_NEEDED="" "$guard" shk >/dev/null 2>&1 || status=$?
if [[ "$status" == 0 ]]; then
  echo "FAIL: a readelf failure must not pass" >&2
  exit 1
fi
echo "ok: rejects a readelf failure"

echo "linkage guard tests passed"
