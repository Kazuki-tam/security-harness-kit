#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

source_tag="${1:?usage: verify-cli-channels.sh <source-tag>}"
case "$source_tag" in
  v*) version="${source_tag#v}" ;;
  shk-v*) version="${source_tag#shk-v}" ;;
  cli-v*) version="${source_tag#cli-v}" ;;
  *)
    shk_error "unsupported CLI source tag: ${source_tag}"
    exit 1
    ;;
esac
shk_require_semver "$version"
distribution_tag="v${version}"

for command in gh npm base64; do
  if ! command -v "$command" >/dev/null 2>&1; then
    shk_error "${command} is required to verify published CLI channels"
    exit 1
  fi
done

if [[ "$source_tag" != "$distribution_tag" ]] && ! gh release view "$distribution_tag" >/dev/null 2>&1; then
  shk_error "CLI mirror ${distribution_tag} is missing for ${source_tag}. Run: .github/scripts/release/mirror-cli-release.sh run ${source_tag}, then rerun this job"
  exit 1
fi

decode_base64() {
  if base64 --decode </dev/null >/dev/null 2>&1; then
    base64 --decode
  else
    base64 -D
  fi
}

source_sha="$(shk_commit_for_tag "$source_tag")"
distribution_sha="$(shk_commit_for_tag "$distribution_tag")"
if [[ "$source_sha" != "$distribution_sha" ]]; then
  shk_error "${distribution_tag} points to ${distribution_sha}, expected ${source_sha} (${source_tag})"
  exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

shk_retry 5 2 16 gh release download "$source_tag" --dir "$workdir" --clobber \
  -p '*-installer.sh' -p '*-installer.ps1' -p '*-dist-manifest.json'
shk_retry 5 2 16 gh release download "$distribution_tag" --dir "$workdir" --clobber \
  -p 'shk-cli-*.tar.xz' -p 'shk-cli-*.zip' -p 'shk-cli-*.sha256'

download_formula() {
  gh api repos/Kazuki-tam/homebrew-tap/contents/Formula/shk.rb --jq .content \
    | decode_base64 > "$workdir/shk.rb"
}
shk_retry 5 2 16 download_formula
if ! grep -q "v${version}" "$workdir/shk.rb"; then
  shk_error "published Homebrew formula does not reference v${version}"
  exit 1
fi

# Registry replicas can lag a successful publish. Allow roughly five minutes
# while keeping the check bounded and rerunnable.
published_npm_version="$(shk_retry 8 10 60 npm view "security-harness-kit@${version}" version)"
if [[ "$published_npm_version" != "$version" ]]; then
  shk_error "npm published ${published_npm_version}, expected ${version}"
  exit 1
fi
shk_retry 8 10 60 npm pack "security-harness-kit@${version}" --pack-destination "$workdir" >/dev/null

"${ROOT}/.github/scripts/release/verify-cli-channel-artifacts.sh" "$workdir" "$version"
echo "published installer, Homebrew, and npm channels verified for ${distribution_tag}"
