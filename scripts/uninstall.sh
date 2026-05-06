#!/usr/bin/env sh
set -eu

install_dir="${SHK_INSTALL_DIR:-/usr/local/bin}"

log() {
  echo "shk uninstall: $*"
}

fail() {
  log "$*" >&2
  exit 1
}

remove_bin() {
  bin_name="$1"
  target="${install_dir}/${bin_name}"

  if [ ! -e "$target" ] && [ ! -L "$target" ]; then
    log "not found: $target"
    return
  fi

  if [ -d "$target" ]; then
    fail "refusing to remove directory: $target"
  fi

  if [ -w "$install_dir" ]; then
    rm "$target"
  elif command -v sudo >/dev/null 2>&1; then
    sudo rm "$target"
  else
    fail "$install_dir is not writable and sudo is unavailable"
  fi

  log "removed $target"
}

remove_bin "shk"
remove_bin "security-harness-kit"
log "done"
