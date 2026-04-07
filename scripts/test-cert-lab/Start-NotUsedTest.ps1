param([string]$OutputDirectory)

$baseDirectory = if ($OutputDirectory) { $OutputDirectory } else { Join-Path $PSScriptRoot "output" }

& (Join-Path $PSScriptRoot "Run-TestScenario.ps1") `
    -Scenario "not-used" `
    -OutputDirectory $baseDirectory `
    -Detached
