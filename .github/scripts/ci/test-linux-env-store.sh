#!/usr/bin/env bash
# End-to-end check of `shk env` against a real Secret Service provider on Linux.
#
# Unit tests use a mock store, so this is the only coverage of the backend the
# CLI ships with. Run it inside a D-Bus session with gnome-keyring available:
#   dbus-run-session -- .github/scripts/ci/test-linux-env-store.sh target/release/shk
set -euo pipefail

shk="$(realpath "${1:?usage: test-linux-env-store.sh <path-to-shk>}")"

printf 'ci-only-passphrase\n' | gnome-keyring-daemon --unlock --components=secrets >/dev/null
sleep 1

project="$(mktemp -d)"
trap 'rm -rf "$project"' EXIT
cd "$project"
git init -q .
"$shk" init --yes >/dev/null
printf 'SAMPLE_VALUE=placeholder\n' >plain.txt

"$shk" env encrypt plain.txt -o enc.txt >/dev/null
echo "ok: encrypt stores a generated key"

"$shk" env decrypt enc.txt -o back.txt >/dev/null
grep -q '^SAMPLE_VALUE=.*placeholder' back.txt
echo "ok: decrypt reads the stored key"

"$shk" env run -f enc.txt -- sh -c 'test "$SAMPLE_VALUE" = placeholder'
echo "ok: env run injects the decrypted value"

"$shk" env key list | grep -q 'DOTENV_PRIVATE_KEY'
echo "ok: key list shows the stored key"

"$shk" env key delete --all >/dev/null
if "$shk" env decrypt enc.txt -o back2.txt --force >/dev/null 2>"$project/err.txt"; then
  echo "FAIL: decrypt succeeded after the key was deleted" >&2
  exit 1
fi
if grep -q -E 'secure storage|SS error' "$project/err.txt"; then
  echo "FAIL: a deleted key was reported as a store failure:" >&2
  cat "$project/err.txt" >&2
  exit 1
fi
echo "ok: a deleted key is reported as missing, not as a store failure"

echo "env store tests passed"
