Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-SerialNumberBytes {
    param([int]$Length = 16)

    $serial = [byte[]]::new($Length)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($serial)
    return $serial
}

function New-RsaCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$SubjectName,
        [Parameter(Mandatory = $true)][datetimeoffset]$NotBefore,
        [Parameter(Mandatory = $true)][datetimeoffset]$NotAfter,
        [Parameter(Mandatory = $true)][bool]$IsCertificateAuthority,
        [Parameter(Mandatory = $true)][int]$PathLengthConstraint,
        [string[]]$DnsNames = @(),
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$IssuerCertificate
    )

    $rsa = [System.Security.Cryptography.RSA]::Create(4096)
    $hashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    $padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $SubjectName,
        $rsa,
        $hashAlgorithm,
        $padding)

    $basicConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
        $IsCertificateAuthority,
        $IsCertificateAuthority,
        $PathLengthConstraint,
        $true)
    $request.CertificateExtensions.Add($basicConstraints)

    if ($IsCertificateAuthority) {
        $keyUsageFlags =
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign `
            -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign `
            -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature
        $keyUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($keyUsageFlags, $true)
        $request.CertificateExtensions.Add($keyUsage)
    }
    else {
        $keyUsageFlags =
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature `
            -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
        $keyUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($keyUsageFlags, $true)
        $request.CertificateExtensions.Add($keyUsage)

        $serverAuthOid = [System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.1", "Server Authentication")
        $ekuCollection = [System.Security.Cryptography.OidCollection]::new()
        [void]$ekuCollection.Add($serverAuthOid)
        $enhancedKeyUsage = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekuCollection, $true)
        $request.CertificateExtensions.Add($enhancedKeyUsage)

        if ($DnsNames.Count -gt 0) {
            $sanBuilder = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
            foreach ($dnsName in $DnsNames) {
                $sanBuilder.AddDnsName($dnsName)
            }

            $request.CertificateExtensions.Add($sanBuilder.Build($true))
        }
    }

    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($request.PublicKey, $false))

    if ($PSBoundParameters.ContainsKey("IssuerCertificate")) {
        $issuedCertificate = $request.Create($IssuerCertificate, $NotBefore, $NotAfter, (New-SerialNumberBytes))
        return [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($issuedCertificate, $rsa)
    }

    return $request.CreateSelfSigned($NotBefore, $NotAfter)
}

function Export-CertificateArtifacts {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][securestring]$Password
    )

    $directory = Split-Path -Parent $BasePath
    if (-not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    [System.IO.File]::WriteAllBytes("$BasePath.cer", $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    [System.IO.File]::WriteAllBytes("$BasePath.pfx", $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $Password))
}

function Export-CertificatePemArtifacts {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$BasePath
    )

    $directory = Split-Path -Parent $BasePath
    if (-not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $certificatePem = $Certificate.ExportCertificatePem()
    Set-Content -Path "$BasePath-cert.pem" -Value $certificatePem -NoNewline -Encoding ASCII

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if ($null -ne $rsa) {
        try {
            $privateKeyPem = $rsa.ExportPkcs8PrivateKeyPem()
            Set-Content -Path "$BasePath-key.pem" -Value $privateKeyPem -NoNewline -Encoding ASCII
        }
        finally {
            $rsa.Dispose()
        }
    }
}

function ConvertTo-PlainText {
    param([Parameter(Mandatory = $true)][securestring]$SecureString)

    $credential = [pscredential]::new("unused", $SecureString)
    return $credential.GetNetworkCredential().Password
}

function Get-TestLabPaths {
    param([string]$BaseDirectory)

    $resolvedBase = if ($BaseDirectory) {
        $BaseDirectory
    }
    else {
        Join-Path $PSScriptRoot "output"
    }

    return [pscustomobject]@{
        BaseDirectory = $resolvedBase
        RootsDirectory = Join-Path $resolvedBase "roots"
        IntermediatesDirectory = Join-Path $resolvedBase "intermediates"
        LeafDirectory = Join-Path $resolvedBase "leaf"
        ScenariosDirectory = Join-Path $resolvedBase "scenarios"
        MetadataPath = Join-Path $resolvedBase "metadata.json"
        PasswordPath = Join-Path $resolvedBase "password.txt"
        ServerPidPath = Join-Path $resolvedBase "server.pid"
    }
}
