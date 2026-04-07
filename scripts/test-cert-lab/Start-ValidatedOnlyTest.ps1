param([string]$OutputDirectory)

$baseDirectory = if ($OutputDirectory) { $OutputDirectory } else { Join-Path $PSScriptRoot "output" }

& (Join-Path $PSScriptRoot "Run-TestScenario.ps1") `
    -Scenario "validated-only" `
    -OutputDirectory $baseDirectory `
    -Detached
