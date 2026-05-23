#!/usr/bin/env bash
set -euo pipefail

mode="${1:?usage: install-linux-deps.sh cli|desktop}"

packages=(libdbus-1-dev libgtk-3-dev pkg-config)

if [[ "$mode" == "desktop" ]]; then
  packages+=(
    libwebkit2gtk-4.1-dev
    libappindicator3-dev
    librsvg2-dev
    patchelf
  )
fi

sudo apt-get update
sudo apt-get install -y "${packages[@]}"
