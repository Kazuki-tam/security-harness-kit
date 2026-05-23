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

foreach ($artifact in $artifacts) {
  $signature = Get-AuthenticodeSignature -LiteralPath $artifact.FullName
  if ($signature.Status -ne "Valid") {
    throw "invalid Authenticode signature for $($artifact.Name): $($signature.Status) $($signature.StatusMessage)"
  }

  Write-Host "valid Authenticode signature: $($artifact.Name)"
}
