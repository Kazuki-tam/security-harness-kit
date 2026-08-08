param(
  [Parameter(Mandatory = $true)]
  [string]$Path
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
  throw "artifact directory not found: $Path"
}

$artifacts = Get-ChildItem -LiteralPath $Path -File |
  Where-Object { $_.Extension -in @(".exe", ".msi") }

if (-not $artifacts) {
  throw "no Windows installer artifacts found in $Path"
}

# Unsigned artifacts are acceptable only when the release explicitly opted in
# and no Authenticode signing is configured at all.
$signingConfigured = -not [string]::IsNullOrEmpty($env:TAURI_WINDOWS_SIGN_COMMAND) -or
  -not [string]::IsNullOrEmpty($env:TAURI_WINDOWS_CERTIFICATE_THUMBPRINT)
$allowUnsigned = ($env:SHK_ALLOW_UNSIGNED_WINDOWS -eq "true") -and -not $signingConfigured

foreach ($artifact in $artifacts) {
  $signature = Get-AuthenticodeSignature -LiteralPath $artifact.FullName
  if ($signature.Status -eq "Valid") {
    Write-Host "valid Authenticode signature: $($artifact.Name)"
    continue
  }

  if ($allowUnsigned -and $signature.Status -eq "NotSigned") {
    Write-Host "unsigned Windows artifact allowed by SHK_ALLOW_UNSIGNED_WINDOWS: $($artifact.Name)"
    continue
  }

  throw "invalid Authenticode signature for $($artifact.Name): $($signature.Status) $($signature.StatusMessage)"
}
