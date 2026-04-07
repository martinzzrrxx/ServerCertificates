param(
    [ValidateSet("validated-only", "not-used")]
    [string]$Scenario = "validated-only",
    [string]$OutputDirectory,
    [int]$Port,
    [switch]$Detached
)

. "$PSScriptRoot\CertLab.Common.ps1"

$paths = Get-TestLabPaths -BaseDirectory $OutputDirectory
$scenarioDirectory = Join-Path $paths.ScenariosDirectory $Scenario
if (-not (Test-Path $scenarioDirectory)) {
    throw "Scenario directory '$scenarioDirectory' does not exist. Run New-TestCertificates.ps1 first."
}

$resolvedPort = if ($PSBoundParameters.ContainsKey("Port")) {
    $Port
}
elseif ($Scenario -eq "validated-only") {
    9443
}
else {
    9444
}

$serverCertPath = Join-Path $scenarioDirectory "server-cert.pem"
$serverKeyPath = Join-Path $scenarioDirectory "server-key.pem"
$chainPath = Join-Path $scenarioDirectory "chain.pem"

if (-not (Test-Path $serverCertPath) -or -not (Test-Path $serverKeyPath) -or -not (Test-Path $chainPath)) {
    throw "Scenario PEM files are missing. Run New-TestCertificates.ps1 first."
}

$arguments = @(
    "s_server",
    "-accept", $resolvedPort,
    "-cert", $serverCertPath,
    "-key", $serverKeyPath,
    "-cert_chain", $chainPath,
    "-tls1_2",
    "-www"
)

if ($Detached) {
    $process = Start-Process openssl -ArgumentList $arguments -PassThru
    Set-Content -Path $paths.ServerPidPath -Value $process.Id -Encoding ASCII
    Write-Host "Started detached HTTPS server on https://localhost:$resolvedPort/ (PID $($process.Id))."
    return
}

Write-Host "Serving scenario '$Scenario' on https://localhost:$resolvedPort/"
Write-Host "Press Ctrl+C to stop."
& openssl @arguments
