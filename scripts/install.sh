#!/usr/bin/env sh
set -eu

repo="${SHK_REPO:-Kazuki-tam/security-harness-kit}"
version="${SHK_VERSION:-latest}"
install_dir="${SHK_INSTALL_DIR:-/usr/local/bin}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "shk install: missing required command: $1" >&2
    exit 1
  fi
}

download() {
  url="$1"
  out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$out"
  else
    echo "shk install: curl or wget is required" >&2
    exit 1
  fi
}

sha256_file() {
  file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{ print $1 }'
  else
    echo "shk install: sha256sum or shasum is required" >&2
    exit 1
  fi
}

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Darwin) os_part="apple-darwin" ;;
    Linux) os_part="unknown-linux-gnu" ;;
    *)
      echo "shk install: unsupported OS: $os" >&2
      exit 1
      ;;
  esac

  case "$arch" in
    x86_64 | amd64)
      if [ "$os" = "Darwin" ]; then
        echo "shk install: Intel macOS is not supported; use Apple Silicon macOS or build from source" >&2
        exit 1
      fi
      arch_part="x86_64"
      ;;
    arm64 | aarch64) arch_part="aarch64" ;;
    *)
      echo "shk install: unsupported architecture: $arch" >&2
      exit 1
      ;;
  esac

  printf '%s-%s' "$arch_part" "$os_part"
}

install_bin() {
  src="$1"
  dst="$2"
  if [ -w "$install_dir" ]; then
    install -m 0755 "$src" "$dst"
  elif command -v sudo >/dev/null 2>&1; then
    sudo install -m 0755 "$src" "$dst"
  else
    echo "shk install: $install_dir is not writable and sudo is unavailable" >&2
    exit 1
  fi
}

need_cmd uname
need_cmd tar
need_cmd awk
need_cmd mktemp
need_cmd install

target="${SHK_TARGET:-$(detect_target)}"
archive="shk-${target}.tar.gz"

if [ "${SHK_BASE_URL:-}" ]; then
  base_url="${SHK_BASE_URL}"
elif [ "$version" = "latest" ]; then
  base_url="https://github.com/${repo}/releases/latest/download"
else
  base_url="https://github.com/${repo}/releases/download/${version}"
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

echo "shk install: downloading ${archive} from ${base_url}"
download "${base_url}/${archive}" "${tmp_dir}/${archive}"
download "${base_url}/SHA256SUMS" "${tmp_dir}/SHA256SUMS"

expected="$(awk -v name="$archive" '$2 == name { print $1 }' "${tmp_dir}/SHA256SUMS")"
if [ -z "$expected" ]; then
  echo "shk install: ${archive} not found in SHA256SUMS" >&2
  exit 1
fi

actual="$(sha256_file "${tmp_dir}/${archive}")"
if [ "$expected" != "$actual" ]; then
  echo "shk install: checksum mismatch for ${archive}" >&2
  echo "expected: $expected" >&2
  echo "actual:   $actual" >&2
  exit 1
fi

tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir"
pkg_dir="${tmp_dir}/shk-${target}"

if [ ! -x "${pkg_dir}/shk" ]; then
  echo "shk install: archive did not contain executable shk" >&2
  exit 1
fi

echo "shk install: installing to ${install_dir}"
install_bin "${pkg_dir}/shk" "${install_dir}/shk"
install_bin "${pkg_dir}/security-harness-kit" "${install_dir}/security-harness-kit"

echo "shk install: installed $("$install_dir/shk" --version 2>/dev/null || printf 'shk')"
