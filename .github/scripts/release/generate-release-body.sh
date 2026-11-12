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

# Hand-written notes for a tag, when present, lead the release body.
shk_handwritten_notes() {
  local notes_file="${SHK_RELEASE_NOTES_DIR:-${ROOT}/docs/release-notes}/$1.md"
  if [[ -f "$notes_file" ]]; then
    cat "$notes_file"
    echo ""
  fi
}

{
  case "$component" in
    cli)
      shk_handwritten_notes "v${version}"
      shk_dist_announcement
      shk_npm_release_notes "$version"
      shk_winget_release_notes
      ;;
    desktop)
      shk_handwritten_notes "desktop-v${version}"
      shk_desktop_release_notes "$version"
      ;;
    desktop-unsigned)
      shk_desktop_unsigned_release_notes "$version"
      ;;
    both)
      shk_handwritten_notes "v${version}"
      shk_handwritten_notes "desktop-v${version}"
      shk_dist_announcement
      shk_npm_release_notes "$version"
      shk_winget_release_notes
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
