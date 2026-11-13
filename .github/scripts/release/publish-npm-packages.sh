#!/usr/bin/env bash

# Publish the npm packages of a CLI release with npm trusted publishing
# (GitHub Actions OIDC). No npm token is read or written.
#
# Usage: publish-npm-packages.sh <packages-dir> <version>
#
# Platform packages go first and the main package last, and the main package
# is only published once every platform package is visible on the registry, so
# an install never resolves a main package whose binary is not there yet.
# Already-published versions are skipped, which makes a failed job rerunnable.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

usage="usage: publish-npm-packages.sh <packages-dir> <version>"
packages_dir="${1:?$usage}"
version="${2:?$usage}"
shk_require_stable_version "$version"

for command in jq npm tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    shk_error "${command} is required to publish the npm packages"
    exit 1
  fi
done

packages=()
while IFS= read -r package; do
  packages+=("$package")
done < <(shk_npm_package_names)

# Fail before publishing anything if a tarball is missing or misnamed.
for package in "${packages[@]}"; do
  tarball="${packages_dir}/${package}-${version}.tgz"
  if [[ ! -f "$tarball" ]]; then
    shk_error "missing npm package tarball: ${tarball}"
    exit 1
  fi
  identity="$(tar -xzOf "$tarball" package/package.json | jq -r '"\(.name)@\(.version)"')"
  if [[ "$identity" != "${package}@${version}" ]]; then
    shk_error "expected npm package ${package}@${version} in $(basename "$tarball"), found ${identity}"
    exit 1
  fi
done

is_published() {
  npm view "$1@${version}" version >/dev/null 2>&1
}

for package in "${packages[@]}"; do
  if is_published "$package"; then
    echo "${package}@${version} already published; nothing to do"
    continue
  fi
  if [[ "$package" == "$SHK_NPM_PACKAGE" ]]; then
    # Registry replicas can lag a successful publish.
    for platform_package in "${packages[@]}"; do
      [[ "$platform_package" == "$SHK_NPM_PACKAGE" ]] && continue
      if ! shk_retry 8 10 60 is_published "$platform_package"; then
        shk_error "${platform_package}@${version} is not visible on the registry; not publishing ${SHK_NPM_PACKAGE}"
        exit 1
      fi
    done
  fi
  # An absolute path is required: a bare relative path such as
  # `dist-global/x.tgz` is read by npm as a GitHub "user/repo" shortcut.
  tarball="$(cd "$packages_dir" && pwd)/${package}-${version}.tgz"
  if ! npm publish "$tarball" --provenance --access public; then
    shk_error "failed to publish ${package}@${version}. A package that has never been published needs the one-time bootstrap in docs/desktop-release.md#npm-packages before trusted publishing can publish it."
    exit 1
  fi
done

echo "npm packages published for v${version}"
