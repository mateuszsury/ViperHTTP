param(
    [string]$OutDir = "tools/certs",
    [string]$CommonName = "viperhttp.local",
    [int]$Days = 365
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$outAbs = Join-Path $repoRoot $OutDir
New-Item -ItemType Directory -Force -Path $outAbs | Out-Null

$crt = Join-Path $outAbs "server.crt"
$key = Join-Path $outAbs "server.key"

$cmd = @"
set -euo pipefail
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days $Days \
  -subj "/CN=$CommonName" \
  -keyout "/mnt/c/Users/thete/OneDrive/Dokumenty/PyCharm/ViperHTTP/$OutDir/server.key" \
  -out "/mnt/c/Users/thete/OneDrive/Dokumenty/PyCharm/ViperHTTP/$OutDir/server.crt"
"@

wsl bash -lc $cmd

Write-Host "Generated cert: $crt"
Write-Host "Generated key : $key"
