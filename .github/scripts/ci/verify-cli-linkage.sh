#!/usr/bin/env bash
# Fail when the Linux `shk` binary needs a shared library beyond the C runtime.
#
# Containers and servers often ship none of the desktop libraries, and a missing
# one stops the binary before any of its code runs. Claude Code treats that exit
# status (127) as a non-blocking hook error, so the managed hooks would silently
# stop protecting the session.
set -euo pipefail

binary="${1:?usage: verify-cli-linkage.sh <path-to-shk>}"

needed="$(readelf -d "$binary" | sed -n 's/.*(NEEDED).*\[\(.*\)\]$/\1/p')"
if [[ -z "$needed" ]]; then
  echo "error: no NEEDED entries found in $binary; cannot verify its linkage" >&2
  exit 1
fi

unexpected="$(grep -v -E '^(libc|libm|libgcc_s|libdl|libpthread|librt|ld-linux[^.]*)\.so(\.|$)' <<<"$needed" || true)"
if [[ -n "$unexpected" ]]; then
  echo "error: $binary needs shared libraries beyond the C runtime:" >&2
  printf '%s\n' "$unexpected" >&2
  exit 1
fi

echo "ok: $binary only needs the C runtime"
