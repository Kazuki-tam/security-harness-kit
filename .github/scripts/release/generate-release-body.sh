#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

component="${RELEASE_COMPONENT:?RELEASE_COMPONENT is required}"
version="${RELEASE_VERSION:?RELEASE_VERSION is required}"
out="${1:-release-body.md}"

shk_require_semver "$version"

shk_dist_announcement() {
  dist plan --output-format=json --no-local-paths > dist-plan.json
  jq -r '.announcement_github_body' dist-plan.json
}

{
  case "$component" in
    cli)
      shk_dist_announcement
      ;;
    desktop)
      shk_desktop_release_notes "$version"
      ;;
    both)
      shk_dist_announcement
      echo ""
      shk_desktop_release_notes "$version"
      ;;
    *)
      echo "unsupported RELEASE_COMPONENT: ${component}" >&2
      exit 1
      ;;
  esac
} > "$out"

echo "wrote ${out} for ${component} v${version}"
