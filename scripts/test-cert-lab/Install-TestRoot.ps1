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
    $existing = $store.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
        $rootCertificate.Thumbprint,
        $false)

    if ($existing.Count -eq 0) {
        $store.Add($rootCertificate)
        Write-Host "Installed test root into CurrentUser\\Root: $($rootCertificate.Subject)"
    }
    else {
        Write-Host "Test root is already installed in CurrentUser\\Root."
    }
}
finally {
    $store.Close()
}
