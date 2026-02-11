param(
    [string]$WifiPort = "COM14",
    [string]$EthPort = "COM9",
    [string]$Profiles = "mixed,api,static,c_static_only",
    [int]$Runs = 2,
    [int]$BurstClients = 24,
    [int]$BurstDuration = 30,
    [int]$LongClients = 14,
    [int]$LongDuration = 120,
    [switch]$SyncPython,
    [switch]$SyncWww,
    [switch]$VerifyFullTest,
    [switch]$RequirePass
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

$argsList = @(
    "$repoRoot\tools\bench_compare_com14_wifi_com9_eth_stress.py",
    "--wifi-port", $WifiPort,
    "--eth-port", $EthPort,
    "--profiles", $Profiles,
    "--runs", $Runs,
    "--burst-clients", $BurstClients,
    "--burst-duration", $BurstDuration,
    "--long-clients", $LongClients,
    "--long-duration", $LongDuration
)

if ($SyncPython) { $argsList += "--sync-python" }
if ($SyncWww) { $argsList += "--sync-www" }
if ($VerifyFullTest) { $argsList += "--verify-full-test" }
if ($RequirePass) { $argsList += "--require-pass" }

python @argsList
