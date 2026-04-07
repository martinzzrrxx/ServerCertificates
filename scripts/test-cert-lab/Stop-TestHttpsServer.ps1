param([string]$OutputDirectory)

. "$PSScriptRoot\CertLab.Common.ps1"

$paths = Get-TestLabPaths -BaseDirectory $OutputDirectory
if (-not (Test-Path $paths.ServerPidPath)) {
    Write-Host "No server.pid file found."
    return
}

$serverProcessId = Get-Content $paths.ServerPidPath -Raw
$serverProcessId = $serverProcessId.Trim()
if (-not $serverProcessId) {
    Write-Host "server.pid is empty."
    return
}

$process = Get-Process -Id ([int]$serverProcessId) -ErrorAction SilentlyContinue
if ($process) {
    $process | Stop-Process -Force
    Write-Host "Stopped HTTPS test server PID $serverProcessId."
}
else {
    Write-Host "Process $serverProcessId is not running."
}

Remove-Item $paths.ServerPidPath -Force -ErrorAction SilentlyContinue
