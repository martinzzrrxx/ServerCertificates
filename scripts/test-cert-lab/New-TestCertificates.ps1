param(
    [string]$OutputDirectory,
    [string]$Password = "ServerCertViewer-Test!"
)

. "$PSScriptRoot\CertLab.Common.ps1"

$paths = Get-TestLabPaths -BaseDirectory $OutputDirectory
$securePassword = ConvertTo-SecureString $Password -AsPlainText -Force

foreach ($path in @(
    $paths.BaseDirectory,
    $paths.RootsDirectory,
    $paths.IntermediatesDirectory,
    $paths.LeafDirectory,
    $paths.ScenariosDirectory
)) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
}

$notBefore = [datetimeoffset]::UtcNow.AddDays(-1)
$notAfter = [datetimeoffset]::UtcNow.AddYears(5)

$root = New-RsaCertificate `
    -SubjectName "CN=ServerCertViewer Test Root" `
    -NotBefore $notBefore `
    -NotAfter $notAfter `
    -IsCertificateAuthority $true `
    -PathLengthConstraint 2

$intermediateA = New-RsaCertificate `
    -SubjectName "CN=ServerCertViewer Intermediate A" `
    -NotBefore $notBefore `
    -NotAfter $notAfter `
    -IsCertificateAuthority $true `
    -PathLengthConstraint 1 `
    -IssuerCertificate $root

$intermediateB = New-RsaCertificate `
    -SubjectName "CN=ServerCertViewer Extra Intermediate B" `
    -NotBefore $notBefore `
    -NotAfter $notAfter `
    -IsCertificateAuthority $true `
    -PathLengthConstraint 1 `
    -IssuerCertificate $root

$leaf = New-RsaCertificate `
    -SubjectName "CN=localhost" `
    -NotBefore $notBefore `
    -NotAfter $notAfter `
    -IsCertificateAuthority $false `
    -PathLengthConstraint 0 `
    -DnsNames @("localhost") `
    -IssuerCertificate $intermediateA

Export-CertificateArtifacts -Certificate $root -BasePath (Join-Path $paths.RootsDirectory "test-root") -Password $securePassword
Export-CertificateArtifacts -Certificate $intermediateA -BasePath (Join-Path $paths.IntermediatesDirectory "intermediate-a") -Password $securePassword
Export-CertificateArtifacts -Certificate $intermediateB -BasePath (Join-Path $paths.IntermediatesDirectory "intermediate-b") -Password $securePassword
Export-CertificateArtifacts -Certificate $leaf -BasePath (Join-Path $paths.LeafDirectory "leaf-localhost") -Password $securePassword
Export-CertificatePemArtifacts -Certificate $root -BasePath (Join-Path $paths.RootsDirectory "test-root")
Export-CertificatePemArtifacts -Certificate $intermediateA -BasePath (Join-Path $paths.IntermediatesDirectory "intermediate-a")
Export-CertificatePemArtifacts -Certificate $intermediateB -BasePath (Join-Path $paths.IntermediatesDirectory "intermediate-b")
Export-CertificatePemArtifacts -Certificate $leaf -BasePath (Join-Path $paths.LeafDirectory "leaf-localhost")

$validatedOnlyDir = Join-Path $paths.ScenariosDirectory "validated-only"
$notUsedDir = Join-Path $paths.ScenariosDirectory "not-used"
New-Item -ItemType Directory -Path $validatedOnlyDir -Force | Out-Null
New-Item -ItemType Directory -Path $notUsedDir -Force | Out-Null

Copy-Item (Join-Path $paths.LeafDirectory "leaf-localhost.pfx") (Join-Path $validatedOnlyDir "server.pfx") -Force
Copy-Item (Join-Path $paths.IntermediatesDirectory "intermediate-a.cer") (Join-Path $validatedOnlyDir "chain-1-intermediate-a.cer") -Force
Copy-Item (Join-Path $paths.LeafDirectory "leaf-localhost-cert.pem") (Join-Path $validatedOnlyDir "server-cert.pem") -Force
Copy-Item (Join-Path $paths.LeafDirectory "leaf-localhost-key.pem") (Join-Path $validatedOnlyDir "server-key.pem") -Force
$validatedOnlyChainPem = @(
    (Get-Content (Join-Path $paths.IntermediatesDirectory "intermediate-a-cert.pem") -Raw).Trim()
) -join [Environment]::NewLine
Set-Content -Path (Join-Path $validatedOnlyDir "chain.pem") -Value ($validatedOnlyChainPem + [Environment]::NewLine) -NoNewline -Encoding ASCII

Copy-Item (Join-Path $paths.LeafDirectory "leaf-localhost.pfx") (Join-Path $notUsedDir "server.pfx") -Force
Copy-Item (Join-Path $paths.IntermediatesDirectory "intermediate-a.cer") (Join-Path $notUsedDir "chain-1-intermediate-a.cer") -Force
Copy-Item (Join-Path $paths.IntermediatesDirectory "intermediate-b.cer") (Join-Path $notUsedDir "chain-2-extra-intermediate-b.cer") -Force
Copy-Item (Join-Path $paths.LeafDirectory "leaf-localhost-cert.pem") (Join-Path $notUsedDir "server-cert.pem") -Force
Copy-Item (Join-Path $paths.LeafDirectory "leaf-localhost-key.pem") (Join-Path $notUsedDir "server-key.pem") -Force
$notUsedChainPem = @(
    (Get-Content (Join-Path $paths.IntermediatesDirectory "intermediate-a-cert.pem") -Raw).Trim()
    (Get-Content (Join-Path $paths.IntermediatesDirectory "intermediate-b-cert.pem") -Raw).Trim()
) -join [Environment]::NewLine
Set-Content -Path (Join-Path $notUsedDir "chain.pem") -Value ($notUsedChainPem + [Environment]::NewLine) -NoNewline -Encoding ASCII

[System.IO.File]::WriteAllText($paths.PasswordPath, $Password)

$metadata = [ordered]@{
    createdAt = [datetimeoffset]::UtcNow.ToString("O")
    rootSubject = $root.Subject
    intermediateA = $intermediateA.Subject
    intermediateB = $intermediateB.Subject
    leafSubject = $leaf.Subject
    scenarios = @(
        @{
            name = "validated-only"
            description = "Server sends leaf plus Intermediate A. Root should appear as Validated Only once the root is trusted locally."
            url = "https://localhost:9443/"
        },
        @{
            name = "not-used"
            description = "Server sends leaf plus Intermediate A and an extra Intermediate B. Intermediate B should be marked Not Used."
            url = "https://localhost:9444/"
        }
    )
}

$metadata | ConvertTo-Json -Depth 5 | Set-Content -Path $paths.MetadataPath -Encoding UTF8

Write-Host "Test certificates generated under: $($paths.BaseDirectory)"
Write-Host "Validated-only scenario: $validatedOnlyDir"
Write-Host "Not-used scenario:      $notUsedDir"
