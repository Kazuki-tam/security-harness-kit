#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

emit_release_plan() {
  local component="$1"
  local version="$2"
  local release_tag="$3"
  local build_cli="$4"
  local build_desktop="$5"
  local make_latest="$6"

  shk_require_semver "$version"
  shk_gh_output "component=${component}"
  shk_gh_output "version=${version}"
  shk_gh_output "release_tag=${release_tag}"
  shk_gh_output "build_cli=${build_cli}"
  shk_gh_output "build_desktop=${build_desktop}"
  shk_gh_output "make_latest=${make_latest}"
}

resolve_from_tag() {
  local tag="$1"

  case "$tag" in
    v*)
      if [[ "$tag" =~ ^v(.+)$ ]]; then
        emit_release_plan "cli" "${BASH_REMATCH[1]}" "$tag" "true" "false" "true"
        return
      fi
      ;;
    cli-v*)
      if [[ "$tag" =~ ^cli-v(.+)$ ]]; then
        emit_release_plan "cli" "${BASH_REMATCH[1]}" "$tag" "true" "false" "true"
        return
      fi
      ;;
    desktop-v*)
      if [[ "$tag" =~ ^desktop-v(.+)$ ]]; then
        emit_release_plan "desktop" "${BASH_REMATCH[1]}" "$tag" "false" "true" "false"
        return
      fi
      ;;
    shk-v*)
      if [[ "$tag" =~ ^shk-v(.+)$ ]]; then
        emit_release_plan "both" "${BASH_REMATCH[1]}" "$tag" "true" "true" "true"
        return
      fi
      ;;
  esac

  echo "unsupported release tag: ${tag}" >&2
  echo "expected vX.Y.Z, cli-vX.Y.Z, desktop-vX.Y.Z, or shk-vX.Y.Z" >&2
  exit 1
}

resolve_from_dispatch() {
  local component="${RELEASE_COMPONENT:?RELEASE_COMPONENT is required for workflow_dispatch}"
  local version="${RELEASE_VERSION:?RELEASE_VERSION is required for workflow_dispatch}"

  case "$component" in
    cli)
      emit_release_plan "cli" "$version" "cli-v${version}" "true" "false" "false"
      ;;
    desktop)
      emit_release_plan "desktop" "$version" "desktop-v${version}" "false" "true" "false"
      ;;
    both)
      emit_release_plan "both" "$version" "shk-v${version}" "true" "true" "false"
      ;;
    *)
      echo "unsupported RELEASE_COMPONENT: ${component}" >&2
      exit 1
      ;;
  esac
}

if [[ "${GITHUB_EVENT_NAME:-}" == "workflow_dispatch" ]]; then
  resolve_from_dispatch
elif [[ "${GITHUB_REF:-}" == refs/tags/* ]]; then
  resolve_from_tag "${GITHUB_REF_NAME:?GITHUB_REF_NAME is required}"
else
  echo "resolve-target.sh must run on tag push or workflow_dispatch" >&2
  exit 1
fi
