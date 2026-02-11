param(
    [string]$WifiPort = "COM14",
    [string]$EthPort = "COM9",
    [int]$Duration = 12,
    [int]$Workers = 6,
    [string]$Paths = "/hello,/file,/static/large.txt",
    [switch]$SyncPython,
    [switch]$SyncWww,
    [switch]$VerifyFullTest
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

$argsList = @(
    "$repoRoot\tools\bench_compare_com14_wifi_com9_eth.py",
    "--wifi-port", $WifiPort,
    "--eth-port", $EthPort,
    "--duration", $Duration,
    "--workers", $Workers,
    "--paths", $Paths
)

if ($SyncPython) { $argsList += "--sync-python" }
if ($SyncWww) { $argsList += "--sync-www" }
if ($VerifyFullTest) { $argsList += "--verify-full-test" }

python @argsList
