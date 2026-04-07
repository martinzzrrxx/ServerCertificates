param(
    [ValidateSet("validated-only", "not-used")]
    [string]$Scenario = "validated-only",
    [string]$OutputDirectory,
    [switch]$Detached
)

. "$PSScriptRoot\CertLab.Common.ps1"

$paths = Get-TestLabPaths -BaseDirectory $OutputDirectory

if (-not (Test-Path $paths.MetadataPath)) {
    & (Join-Path $PSScriptRoot "New-TestCertificates.ps1") -OutputDirectory $paths.BaseDirectory
}

& (Join-Path $PSScriptRoot "Install-TestRoot.ps1") -OutputDirectory $paths.BaseDirectory

$port = if ($Scenario -eq "validated-only") { 9443 } else { 9444 }

Write-Host ""
Write-Host "Open this URL in ServerCertViewer:"
Write-Host "  https://localhost:$port/"
Write-Host ""
if ($Scenario -eq "validated-only") {
    Write-Host "Expected result:"
    Write-Host "  - Server provides leaf + Intermediate A"
    Write-Host "  - Root should appear as 'Validated Only'"
}
else {
    Write-Host "Expected result:"
    Write-Host "  - Server provides leaf + Intermediate A + extra Intermediate B"
    Write-Host "  - Intermediate B should appear as 'Not Used'"
    Write-Host "  - Root may also appear as 'Validated Only'"
}
Write-Host ""

& (Join-Path $PSScriptRoot "Start-TestHttpsServer.ps1") -Scenario $Scenario -OutputDirectory $paths.BaseDirectory -Port $port -Detached:$Detached
