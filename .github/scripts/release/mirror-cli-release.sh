#!/usr/bin/env bash

# Mirror CLI assets from a combined (`shk-vX.Y.Z`) or CLI-prefixed
# (`cli-vX.Y.Z`) release to the plain `vX.Y.Z` release.
#
# Why: the release workflow drives `dist build` without an announcement tag,
# and cargo-dist cannot parse this repo's `shk-v*` / `cli-v*` tag conventions
# anyway (it only understands `v{version}` and `{package}-v{version}`), so the
# artifact-download URLs it embeds always follow its own `v{version}`
# convention. The shell/PowerShell installers, the Homebrew formula, and the
# npm package therefore resolve CLI archives from
# `releases/download/v{version}/...` no matter which tag the pipeline
# published under. Plain `v*` releases are aligned by construction; combined
# and `cli-v*` releases need this mirror so those install channels resolve.
#
# Why this is not automated inside release.yml: the "Protect release tags"
# ruleset only lets repository admins create `v*` refs, and the workflow's
# GITHUB_TOKEN has no bypass, so the mirror tag must be created with a
# maintainer's credentials. Creating the tag outside GitHub Actions re-triggers
# the Release workflow (and the duplicate CLI release would fail on the npm
# publish), so `run` parks the workflow while the tag is created and re-enables
# it on exit.
#
# Usage:
#   mirror-cli-release.sh tag <source-tag>     # print the mirror tag
#   mirror-cli-release.sh notes <source-tag>   # print the mirror release notes
#   mirror-cli-release.sh select <assets-dir>  # print the CLI assets to mirror
#   mirror-cli-release.sh run <source-tag>     # perform the mirror via gh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

RELEASE_WORKFLOW="release.yml"

usage() {
  sed -n 's/^#   //p' "${BASH_SOURCE[0]}"
}

mirror_tag_for() {
  local source_tag="$1"
  local version=""
  case "$source_tag" in
    shk-v*)
      version="${source_tag#shk-v}"
      ;;
    cli-v*)
      version="${source_tag#cli-v}"
      ;;
    v*)
      shk_error "${source_tag} already matches the cargo-dist URL convention; nothing to mirror"
      exit 1
      ;;
    *)
      shk_error "unsupported source tag: ${source_tag} (expected shk-vX.Y.Z or cli-vX.Y.Z)"
      exit 1
      ;;
  esac
  shk_require_semver "$version"
  printf 'v%s\n' "$version"
}

mirror_notes_for() {
  local source_tag="$1"
  local mirror_tag
  mirror_tag="$(mirror_tag_for "$source_tag")"
  local source_url="https://github.com/Kazuki-tam/security-harness-kit/releases/tag/${source_tag}"
  cat <<EOF
CLI asset mirror for \`${mirror_tag}\`.

The release pipeline published every asset for this version under
[\`${source_tag}\`](${source_url}), but the cargo-dist-generated install
channels (shell/PowerShell installers, the Homebrew formula, the npm package)
resolve CLI archives from \`releases/download/${mirror_tag}/...\`. This release
mirrors the CLI assets byte-for-byte (identical SHA-256) so those channels
work.

Desktop installers and updater metadata stay on [\`${source_tag}\`](${source_url}),
which remains the canonical release for this version.
EOF
}

# Print the CLI-channel assets in a downloaded release directory, one per
# line. Desktop assets are deliberately excluded: the mirror exists for the
# cargo-dist URL convention, and the desktop updater already resolves from the
# canonical tag.
select_assets() {
  local dir="$1"
  local file
  local have_archive=false
  local selected=()
  for file in "$dir"/shk-cli-* "$dir"/sha256.sum "$dir"/shk.rb "$dir"/source.tar.gz "$dir"/source.tar.gz.sha256; do
    [[ -f "$file" ]] || continue
    selected+=("$file")
    case "$file" in
      */shk-cli-*.tar.xz | */shk-cli-*.zip)
        have_archive=true
        ;;
    esac
  done
  if [[ "$have_archive" != true ]]; then
    shk_error "no shk-cli archives found in ${dir}; refusing to mirror an empty CLI release"
    exit 1
  fi
  printf '%s\n' "${selected[@]}"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    shk_error "$1 is required"
    exit 1
  fi
}

# Verify every `<name>.sha256` in the directory against its sibling.
verify_checksums() {
  local dir="$1"
  local sum_file
  (
    cd "$dir"
    for sum_file in *.sha256; do
      [[ -f "$sum_file" ]] || continue
      if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -c "$sum_file" >/dev/null
      else
        sha256sum -c "$sum_file" >/dev/null
      fi
      echo "checksum ok: ${sum_file%.sha256}"
    done
  )
}

# Resolve the commit a tag points at, dereferencing annotated tags.
commit_for_tag() {
  local tag="$1"
  local sha type
  sha="$(gh api "repos/{owner}/{repo}/git/ref/tags/${tag}" --jq .object.sha)"
  type="$(gh api "repos/{owner}/{repo}/git/ref/tags/${tag}" --jq .object.type)"
  if [[ "$type" == "tag" ]]; then
    sha="$(gh api "repos/{owner}/{repo}/git/tags/${sha}" --jq .object.sha)"
  fi
  printf '%s\n' "$sha"
}

reenable_release_workflow() {
  if gh workflow enable "$RELEASE_WORKFLOW"; then
    echo "re-enabled ${RELEASE_WORKFLOW}"
  else
    shk_error "failed to re-enable ${RELEASE_WORKFLOW}; run: gh workflow enable ${RELEASE_WORKFLOW}"
  fi
}

run_mirror() {
  local source_tag="$1"
  local mirror_tag
  mirror_tag="$(mirror_tag_for "$source_tag")"
  require_cmd gh

  if ! gh release view "$source_tag" >/dev/null 2>&1; then
    shk_error "source release ${source_tag} not found; publish it first"
    exit 1
  fi

  local workdir
  workdir="$(mktemp -d)"
  echo "downloading CLI assets from ${source_tag}"
  gh release download "$source_tag" --dir "$workdir" \
    -p 'shk-cli-*' -p 'sha256.sum' -p 'shk.rb' -p 'source.tar.gz' -p 'source.tar.gz.sha256'

  local assets=()
  local line
  while IFS= read -r line; do
    assets+=("$line")
  done < <(select_assets "$workdir")
  verify_checksums "$workdir"

  if gh release view "$mirror_tag" >/dev/null 2>&1; then
    echo "mirror release ${mirror_tag} already exists; refreshing assets"
    gh release upload "$mirror_tag" "${assets[@]}" --clobber
    rm -rf "$workdir"
    return
  fi

  local commit_sha
  commit_sha="$(commit_for_tag "$source_tag")"

  local existing_sha=""
  if existing_sha="$(commit_for_tag "$mirror_tag" 2>/dev/null)"; then
    if [[ "$existing_sha" != "$commit_sha" ]]; then
      shk_error "tag ${mirror_tag} already exists at ${existing_sha}, not ${commit_sha}; refusing to mirror"
      exit 1
    fi
  fi

  # Creating a v* tag outside Actions re-triggers the Release workflow; park
  # it until the mirror release exists.
  echo "disabling ${RELEASE_WORKFLOW} while the mirror tag is created"
  gh workflow disable "$RELEASE_WORKFLOW"
  trap reenable_release_workflow EXIT

  if [[ -z "$existing_sha" ]]; then
    gh api --method POST "repos/{owner}/{repo}/git/refs" \
      -f ref="refs/tags/${mirror_tag}" \
      -f sha="$commit_sha" >/dev/null
    echo "created tag ${mirror_tag} at ${commit_sha}"
  fi

  mirror_notes_for "$source_tag" > "${workdir}/mirror-notes.md"
  gh release create "$mirror_tag" "${assets[@]}" \
    --title "$mirror_tag" \
    --notes-file "${workdir}/mirror-notes.md" \
    --latest=false \
    --verify-tag
  echo "mirror release ${mirror_tag} published with ${#assets[@]} assets"
  rm -rf "$workdir"
}

case "${1:-}" in
  tag)
    mirror_tag_for "${2:?usage: mirror-cli-release.sh tag <source-tag>}"
    ;;
  notes)
    mirror_notes_for "${2:?usage: mirror-cli-release.sh notes <source-tag>}"
    ;;
  select)
    select_assets "${2:?usage: mirror-cli-release.sh select <assets-dir>}"
    ;;
  run)
    run_mirror "${2:?usage: mirror-cli-release.sh run <source-tag>}"
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
