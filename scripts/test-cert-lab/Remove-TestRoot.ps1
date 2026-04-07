param([string]$OutputDirectory)

. "$PSScriptRoot\CertLab.Common.ps1"

$paths = Get-TestLabPaths -BaseDirectory $OutputDirectory
$rootPath = Join-Path $paths.RootsDirectory "test-root.cer"

if (-not (Test-Path $rootPath)) {
    throw "Root certificate not found. Run New-TestCertificates.ps1 first."
}

$rootCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rootPath)
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new("Root", "CurrentUser")

try {
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $matches = $store.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
        $rootCertificate.Thumbprint,
        $false)

    foreach ($certificate in $matches) {
        $store.Remove($certificate)
    }

    Write-Host "Removed $($matches.Count) matching test root certificate(s) from CurrentUser\\Root."
}
finally {
    $store.Close()
}
