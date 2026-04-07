param([string]$OutputDirectory)

$baseDirectory = if ($OutputDirectory) { $OutputDirectory } else { Join-Path $PSScriptRoot "output" }

& (Join-Path $PSScriptRoot "Stop-TestHttpsServer.ps1") -OutputDirectory $baseDirectory
& (Join-Path $PSScriptRoot "Remove-TestRoot.ps1") -OutputDirectory $baseDirectory
