param(
    [ValidateSet("validated-only", "not-used")]
    [string]$Scenario = "validated-only",
    [string]$OutputDirectory,
    [int]$Port,
    [switch]$Detached,
    [switch]$ServeLoop
)

. "$PSScriptRoot\CertLab.Common.ps1"

function Start-HttpsLoop {
    param(
        [Parameter(Mandatory = $true)][string]$ScenarioDirectory,
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][int]$ListenPort
    )

    $serverCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        (Join-Path $ScenarioDirectory "server.pfx"),
        $Password,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

    $extraCertificates = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    foreach ($chainPath in Get-ChildItem -Path $ScenarioDirectory -Filter "chain-*.cer" | Sort-Object Name) {
        [void]$extraCertificates.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($chainPath.FullName))
    }

    $certificateContext = [System.Net.Security.SslStreamCertificateContext]::Create($serverCertificate, $extraCertificates)
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $ListenPort)
    $listener.Start()

    Write-Host "Serving scenario '$Scenario' on https://localhost:$ListenPort/"
    Write-Host "Press Ctrl+C to stop."

    try {
        while ($true) {
            $client = $listener.AcceptTcpClient()
            try {
                $networkStream = $client.GetStream()
                $sslStream = [System.Net.Security.SslStream]::new($networkStream, $false)
                $options = [System.Net.Security.SslServerAuthenticationOptions]::new()
                $options.ServerCertificateContext = $certificateContext
                $options.ClientCertificateRequired = $false
                $options.EnabledSslProtocols = [System.Security.Authentication.SslProtocols]::None
                $options.CertificateRevocationCheckMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck

                $sslStream.AuthenticateAsServerAsync($options).GetAwaiter().GetResult()

                $buffer = New-Object byte[] 4096
                [void]$sslStream.Read($buffer, 0, $buffer.Length)

                $body = "Scenario=$Scenario`nPort=$ListenPort`nTime=$(Get-Date -Format o)"
                $responseBytes = [System.Text.Encoding]::ASCII.GetBytes(
                    "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body")
                $sslStream.Write($responseBytes, 0, $responseBytes.Length)
                $sslStream.Flush()
                $sslStream.Dispose()
            }
            finally {
                $client.Dispose()
            }
        }
    }
    finally {
        $listener.Stop()
    }
}

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

$password = Get-Content $paths.PasswordPath -Raw
$password = $password.Trim()

if ($Detached -and -not $ServeLoop) {
    $quotedScript = '"' + $PSCommandPath + '"'
    $quotedOutput = '"' + $paths.BaseDirectory + '"'
    $command = "& $quotedScript -Scenario $Scenario -OutputDirectory $quotedOutput -Port $resolvedPort -ServeLoop"
    $process = Start-Process pwsh -ArgumentList "-NoProfile", "-File", $PSCommandPath, "-Scenario", $Scenario, "-OutputDirectory", $paths.BaseDirectory, "-Port", $resolvedPort, "-ServeLoop" -PassThru
    Set-Content -Path $paths.ServerPidPath -Value $process.Id -Encoding ASCII
    Write-Host "Started detached HTTPS server on https://localhost:$resolvedPort/ (PID $($process.Id))."
    return
}

Start-HttpsLoop -ScenarioDirectory $scenarioDirectory -Password $password -ListenPort $resolvedPort
