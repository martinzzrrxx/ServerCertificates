# Test Certificate Lab

This folder contains a repeatable local test lab for ServerCertViewer.

It is designed to exercise two specific chain-difference cases:

- `Validated Only`
- `Not Used`

## Files

- `New-TestCertificates.ps1`
  - Generates a local root CA, two intermediates, one `localhost` leaf certificate, and scenario folders.
- `Install-TestRoot.ps1`
  - Installs the generated root into `CurrentUser\Root`.
- `Remove-TestRoot.ps1`
  - Removes the generated root from `CurrentUser\Root`.
- `Start-TestHttpsServer.ps1`
  - Starts a small HTTPS server that serves one scenario at a time.
- `Stop-TestHttpsServer.ps1`
  - Stops a detached test server using the saved PID.
- `Run-TestScenario.ps1`
  - Generates assets if needed, installs the root, prints expected results, and starts the selected scenario.

## Scenarios

### 1. `validated-only`

Server sends:

- leaf `CN=localhost`
- `Intermediate A`

Local trust path should become:

- leaf
- `Intermediate A`
- `Test Root`

Expected UI result:

- the root certificate appears at the end of the list as `Validated Only`

### 2. `not-used`

Server sends:

- leaf `CN=localhost`
- `Intermediate A`
- extra `Intermediate B`

Local trust path should become:

- leaf
- `Intermediate A`
- `Test Root`

Expected UI result:

- `Intermediate B` is marked `Not Used`
- the root certificate may also appear as `Validated Only`

## Quick Start

Generate and run the first scenario:

```powershell
pwsh .\scripts\test-cert-lab\Run-TestScenario.ps1 -Scenario validated-only
```

Generate and run the second scenario:

```powershell
pwsh .\scripts\test-cert-lab\Run-TestScenario.ps1 -Scenario not-used
```

Then open ServerCertViewer and fetch:

- `https://localhost:9443/` for `validated-only`
- `https://localhost:9444/` for `not-used`

## Detached Mode

Run in background:

```powershell
pwsh .\scripts\test-cert-lab\Run-TestScenario.ps1 -Scenario validated-only -Detached
```

Stop the detached server:

```powershell
pwsh .\scripts\test-cert-lab\Stop-TestHttpsServer.ps1
```

## Cleanup

Remove the test root when finished:

```powershell
pwsh .\scripts\test-cert-lab\Remove-TestRoot.ps1
```

Generated files are stored in:

```text
scripts/test-cert-lab/output
```
