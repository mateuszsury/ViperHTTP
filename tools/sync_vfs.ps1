param(
    [string]$Port = "COM14",
    [string]$Source = "tools\\www",
    [string]$Target = "/www",
    [int]$GzipMinSize = 1024,
    [int]$GzipLevel = 6,
    [int]$ControlTimeoutSec = 20,
    [int]$CopyTimeoutSec = 90,
    [int]$MaxCopyTimeoutSec = 300,
    [int]$CopyBytesPerSecEstimate = 120000,
    [int]$GzipTimeoutSec = 120,
    [int]$Retries = 2
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Source)) {
    throw "Source directory not found: $Source"
}

function Normalize-RemotePath([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) {
        return "/"
    }
    $normalized = $path.Replace("\", "/")
    if (-not $normalized.StartsWith("/")) {
        $normalized = "/" + $normalized
    }
    if ($normalized.Length -gt 1 -and $normalized.EndsWith("/")) {
        $normalized = $normalized.TrimEnd("/")
    }
    return $normalized
}

function Stop-StaleMpremote {
    $pattern = "mpremote connect $Port"
    Get-CimInstance Win32_Process |
        Where-Object {
            $_.Name -eq "python.exe" -and
            $_.CommandLine -and
            $_.CommandLine -match [regex]::Escape($pattern)
        } |
        ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        }
}

function Invoke-Mpremote {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args,
        [int]$TimeoutSec = 20,
        [int]$MaxRetries = 1,
        [switch]$IgnoreError
    )

    $lastError = $null
    for ($attempt = 1; $attempt -le [Math]::Max(1, $MaxRetries); $attempt++) {
        Stop-StaleMpremote

        $outFile = [System.IO.Path]::GetTempFileName()
        $errFile = [System.IO.Path]::GetTempFileName()
        try {
            $argList = @("-m", "mpremote", "connect", $Port) + $Args
            $proc = Start-Process -FilePath "python" `
                -ArgumentList $argList `
                -NoNewWindow `
                -PassThru `
                -RedirectStandardOutput $outFile `
                -RedirectStandardError $errFile

            if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                throw "mpremote timeout after ${TimeoutSec}s: $($Args -join ' ')"
            }
            $proc.WaitForExit()
            $proc.Refresh()

            $stdout = Get-Content $outFile -Raw -ErrorAction SilentlyContinue
            $stderr = Get-Content $errFile -Raw -ErrorAction SilentlyContinue
            $exitCode = $proc.ExitCode
            if ($null -eq $exitCode) {
                $exitCode = 0
            }
            if ($exitCode -eq 0) {
                return $stdout
            }
            throw "mpremote exit=${exitCode}: $stderr $stdout"
        } catch {
            $lastError = $_
            if ($attempt -lt $MaxRetries) {
                Start-Sleep -Milliseconds 300
            }
        } finally {
            Remove-Item $outFile, $errFile -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not $IgnoreError) {
        throw $lastError
    }
    return $null
}

function Ensure-RemoteDir([string]$remoteDir, [hashtable]$createdDirs) {
    if ($createdDirs.ContainsKey($remoteDir)) {
        return
    }
    Invoke-Mpremote -Args @("fs", "mkdir", ":$remoteDir") -TimeoutSec $ControlTimeoutSec -MaxRetries $Retries -IgnoreError
    $createdDirs[$remoteDir] = $true
}

$srcRoot = (Resolve-Path $Source).Path
$targetRoot = Normalize-RemotePath $Target
$created = @{}

Write-Host "sync_vfs: removing remote target :$targetRoot"
Invoke-Mpremote -Args @("fs", "rm", "-r", ":$targetRoot") -TimeoutSec $ControlTimeoutSec -MaxRetries $Retries -IgnoreError

Write-Host "sync_vfs: creating remote target :$targetRoot"
Ensure-RemoteDir -remoteDir $targetRoot -createdDirs $created

$files = Get-ChildItem -Path $srcRoot -Recurse -File
$index = 0
foreach ($f in $files) {
    $index++
    $rel = $f.FullName.Substring($srcRoot.Length).TrimStart('\', '/')
    $relRemote = $rel.Replace("\", "/")
    $remotePath = "$targetRoot/$relRemote"
    $remoteDir = [System.IO.Path]::GetDirectoryName($remotePath).Replace("\", "/")
    if ([string]::IsNullOrWhiteSpace($remoteDir)) {
        $remoteDir = $targetRoot
    }
    Ensure-RemoteDir -remoteDir $remoteDir -createdDirs $created
    $estSec = [int][Math]::Ceiling($f.Length / [double]([Math]::Max(1, $CopyBytesPerSecEstimate))) + 10
    $fileTimeout = [Math]::Max($CopyTimeoutSec, $estSec)
    $fileTimeout = [Math]::Min($MaxCopyTimeoutSec, $fileTimeout)
    Write-Host ("sync_vfs: [{0}/{1}] {2} ({3} bytes, timeout {4}s)" -f $index, $files.Count, $relRemote, $f.Length, $fileTimeout)
    Invoke-Mpremote -Args @("fs", "cp", $f.FullName, ":$remotePath") -TimeoutSec $fileTimeout -MaxRetries $Retries | Out-Null
}

Write-Host "sync_vfs: gzip_static on :$targetRoot"
$gzipScript = [System.IO.Path]::GetTempFileName() + ".py"
try {
    @(
        "import viperhttp"
        "print(viperhttp.gzip_static('$targetRoot', $GzipMinSize, $GzipLevel))"
    ) | Set-Content -Path $gzipScript -Encoding ASCII
    $gzipOut = Invoke-Mpremote -Args @("run", $gzipScript) -TimeoutSec $GzipTimeoutSec -MaxRetries $Retries
    if ($gzipOut) {
        $gzipOut.Trim() | Write-Host
    }
} finally {
    Remove-Item $gzipScript -Force -ErrorAction SilentlyContinue
}
