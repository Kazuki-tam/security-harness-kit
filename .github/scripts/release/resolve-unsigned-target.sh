#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

emit_unsigned_release_plan() {
  local version="$1"
  local release_tag="desktop-unsigned-v${version}"

  shk_require_semver "$version"
  shk_gh_output "component=desktop-unsigned"
  shk_gh_output "version=${version}"
  shk_gh_output "release_tag=${release_tag}"
}

resolve_from_tag() {
  local tag="$1"

  if [[ "$tag" =~ ^desktop-unsigned-v(.+)$ ]]; then
    emit_unsigned_release_plan "${BASH_REMATCH[1]}"
    return
  fi

  echo "unsupported unsigned release tag: ${tag}" >&2
  echo "expected desktop-unsigned-vX.Y.Z" >&2
  exit 1
}

resolve_from_dispatch() {
  local version="${RELEASE_VERSION:?RELEASE_VERSION is required for workflow_dispatch}"
  emit_unsigned_release_plan "$version"
}

if [[ "${GITHUB_EVENT_NAME:-}" == "workflow_dispatch" ]]; then
  resolve_from_dispatch
elif [[ "${GITHUB_REF:-}" == refs/tags/* ]]; then
  resolve_from_tag "${GITHUB_REF_NAME:?GITHUB_REF_NAME is required}"
else
  echo "resolve-unsigned-target.sh must run on tag push or workflow_dispatch" >&2
  exit 1
fi
