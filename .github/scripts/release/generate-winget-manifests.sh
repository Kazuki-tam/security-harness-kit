#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=.github/scripts/release/common.sh
source "${ROOT}/.github/scripts/release/common.sh"

release_dir="${1:-release-assets}"
case "$release_dir" in
  /*) release_path="$release_dir" ;;
  *) release_path="${ROOT}/${release_dir}" ;;
esac
version="${RELEASE_VERSION:?RELEASE_VERSION is required}"
release_tag="${RELEASE_TAG:?RELEASE_TAG is required}"
repo="${GITHUB_REPOSITORY:-Kazuki-tam/security-harness-kit}"

package_identifier="${WINGET_PACKAGE_IDENTIFIER:-Kazuki-tam.shk}"
publisher="${WINGET_PUBLISHER:-Kazuki-tam}"
publisher_url="${WINGET_PUBLISHER_URL:-https://github.com/Kazuki-tam}"
package_name="${WINGET_PACKAGE_NAME:-shk}"
asset_name="shk-cli-x86_64-pc-windows-msvc.zip"
asset_path="${release_path}/${asset_name}"
checksum_path="${asset_path}.sha256"
archive_name="${WINGET_ARCHIVE_NAME:-shk-winget-manifests.zip}"
manifest_version="${WINGET_MANIFEST_VERSION:-1.6.0}"

shk_require_semver "$version"

if [[ "$package_identifier" != *.* || "$package_identifier" == *[\\/:]* ]]; then
  shk_error "WINGET_PACKAGE_IDENTIFIER must be dot-separated and must not contain path separators"
  exit 1
fi

if ! command -v zip >/dev/null 2>&1; then
  shk_error "zip is required to package WinGet manifests"
  exit 1
fi

if ! command -v unzip >/dev/null 2>&1; then
  shk_error "unzip is required to inspect the Windows release asset"
  exit 1
fi

if [[ ! -f "$asset_path" ]]; then
  shk_error "Windows release asset not found: ${asset_path}"
  exit 1
fi

if [[ ! -f "$checksum_path" ]]; then
  shk_error "Windows release asset checksum not found: ${checksum_path}"
  exit 1
fi

sha256="$(awk '{ print $1; exit }' "$checksum_path" | tr '[:lower:]' '[:upper:]')"
if [[ ! "$sha256" =~ ^[0-9A-F]{64}$ ]]; then
  shk_error "invalid SHA256 in ${checksum_path}"
  exit 1
fi

if ! unzip -Z1 "$asset_path" | awk '$0 == "shk.exe" { found = 1 } END { exit found ? 0 : 1 }'; then
  shk_error "Windows release asset must contain shk.exe at the archive root for WinGet portable install"
  exit 1
fi

repo_url="https://github.com/${repo}"
installer_url="${repo_url}/releases/download/${release_tag}/${asset_name}"
license_url="${repo_url}/blob/main/LICENSE"
package_path="$(printf '%s' "$package_identifier" | tr '.' '/')"
first_char="$(printf '%s' "$package_identifier" | cut -c1 | tr '[:upper:]' '[:lower:]')"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

manifest_dir="${workdir}/winget/manifests/${first_char}/${package_path}/${version}"
mkdir -p "$manifest_dir"

cat > "${manifest_dir}/${package_identifier}.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.version.${manifest_version}.schema.json
PackageIdentifier: ${package_identifier}
PackageVersion: ${version}
DefaultLocale: en-US
ManifestType: version
ManifestVersion: ${manifest_version}
EOF

cat > "${manifest_dir}/${package_identifier}.locale.en-US.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.defaultLocale.${manifest_version}.schema.json
PackageIdentifier: ${package_identifier}
PackageVersion: ${version}
PackageLocale: en-US
Publisher: ${publisher}
PublisherUrl: ${publisher_url}
PackageName: ${package_name}
PackageUrl: ${repo_url}
License: MIT
LicenseUrl: ${license_url}
ShortDescription: Local-first security harness CLI for AI coding agents
Description: shk scans, masks, audits, and blocks risky secrets and PII in local AI-assisted development workflows.
Moniker: shk
Tags:
- ai
- cli
- pii
- security
- secrets
ManifestType: defaultLocale
ManifestVersion: ${manifest_version}
EOF

cat > "${manifest_dir}/${package_identifier}.installer.yaml" <<EOF
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.installer.${manifest_version}.schema.json
PackageIdentifier: ${package_identifier}
PackageVersion: ${version}
MinimumOSVersion: 10.0.0.0
InstallerType: zip
NestedInstallerType: portable
NestedInstallerFiles:
- RelativeFilePath: shk.exe
  PortableCommandAlias: shk
Installers:
- Architecture: x64
  InstallerUrl: ${installer_url}
  InstallerSha256: ${sha256}
ManifestType: installer
ManifestVersion: ${manifest_version}
EOF

(
  cd "$workdir"
  rm -f "${release_path}/${archive_name}"
  zip -qr "${release_path}/${archive_name}" winget
)

echo "wrote ${release_path}/${archive_name}"
