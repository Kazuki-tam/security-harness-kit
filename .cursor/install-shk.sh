#!/usr/bin/env bash
# Idempotent, SHA-256-verified install of `shk` onto the default PATH for
# Cursor Cloud Agents. Hooks invoke `shk` by name without loading shell
# profiles, so install under /usr/local/bin by default. Pin the release tag so
# Cloud Agent Builds stay reproducible (update after each CLI release).
set -euo pipefail

SHK_REPO="Kazuki-tam/security-harness-kit"
SHK_VERSION="${SHK_VERSION:-v0.8.0}"
INSTALL_DIR="${SHK_CLI_UNMANAGED_INSTALL:-/usr/local/bin}"

if [[ ! "$SHK_VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]]; then
  echo "invalid SHK_VERSION: $SHK_VERSION" >&2
  exit 2
fi
if [[ "$SHK_VERSION" != v* ]]; then
  SHK_VERSION="v${SHK_VERSION}"
fi
EXPECTED_BARE="${SHK_VERSION#v}"

run_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    echo "root privileges (or sudo) are required to run: $*" >&2
    exit 1
  fi
}

dir_writable_or_creatable() {
  local probe="$1"
  while [ ! -e "$probe" ]; do
    local parent
    parent="$(dirname "$probe")"
    if [ "$parent" = "$probe" ]; then
      return 1
    fi
    probe="$parent"
  done
  [ -d "$probe" ] && [ -w "$probe" ]
}

install_binary() {
  local src="$1"
  local dst="$2"
  if dir_writable_or_creatable "$INSTALL_DIR"; then
    mkdir -p "$INSTALL_DIR"
    install -m 0755 "$src" "$dst"
  else
    run_root mkdir -p "$INSTALL_DIR"
    run_root install -m 0755 "$src" "$dst"
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Skip work when the pinned version is already present at INSTALL_DIR/shk (or
# on PATH when using the default install directory).
if [ -x "${INSTALL_DIR}/shk" ]; then
  current="$("${INSTALL_DIR}/shk" --version 2>/dev/null || true)"
  if [ "$current" = "shk ${EXPECTED_BARE}" ]; then
    echo "shk already present: ${current}"
    exit 0
  fi
elif [ -z "${SHK_CLI_UNMANAGED_INSTALL:-}" ] && command -v shk >/dev/null 2>&1; then
  current="$(shk --version 2>/dev/null || true)"
  if [ "$current" = "shk ${EXPECTED_BARE}" ]; then
    echo "shk already present: ${current}"
    exit 0
  fi
fi

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
  Linux-aarch64|Linux-arm64) TARGET="aarch64-unknown-linux-gnu" ;;
  Darwin-x86_64) TARGET="x86_64-apple-darwin" ;;
  Darwin-arm64) TARGET="aarch64-apple-darwin" ;;
  *)
    echo "unsupported platform: $(uname -s)-$(uname -m)" >&2
    exit 1
    ;;
esac

missing_tools=0
for tool in curl tar xz; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing_tools=1
  fi
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  missing_tools=1
fi

if [ "$missing_tools" -ne 0 ]; then
  if command -v apt-get >/dev/null 2>&1; then
    run_root env DEBIAN_FRONTEND=noninteractive apt-get update
    run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates coreutils curl tar xz-utils
  else
    echo "curl, tar, xz, and sha256sum/shasum are required to verify and unpack shk" >&2
    exit 1
  fi
fi

ASSET="shk-cli-${TARGET}.tar.xz"
BASE_URL="https://github.com/${SHK_REPO}/releases/download/${SHK_VERSION}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

curl --retry 3 --retry-all-errors --proto '=https' --tlsv1.2 -LsSf \
  -o "${WORKDIR}/${ASSET}" "${BASE_URL}/${ASSET}"
curl --retry 3 --retry-all-errors --proto '=https' --tlsv1.2 -LsSf \
  -o "${WORKDIR}/${ASSET}.sha256" "${BASE_URL}/${ASSET}.sha256"

expected_sha="$(awk 'NF { print tolower($1); exit }' "${WORKDIR}/${ASSET}.sha256")"
if [[ ! "$expected_sha" =~ ^[0-9a-f]{64}$ ]]; then
  echo "invalid SHA-256 checksum file for ${ASSET}" >&2
  exit 1
fi
actual_sha="$(sha256_file "${WORKDIR}/${ASSET}" | tr '[:upper:]' '[:lower:]')"
if [ "$actual_sha" != "$expected_sha" ]; then
  echo "SHA-256 mismatch for ${ASSET}: expected ${expected_sha}, got ${actual_sha}" >&2
  exit 1
fi

tar -xJf "${WORKDIR}/${ASSET}" -C "$WORKDIR" "shk-cli-${TARGET}/shk"
install_binary "${WORKDIR}/shk-cli-${TARGET}/shk" "${INSTALL_DIR}/shk"

echo "${INSTALL_DIR}/shk"
"${INSTALL_DIR}/shk" --version
