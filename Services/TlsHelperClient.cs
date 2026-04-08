using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ServerCertViewer.Models;

namespace ServerCertViewer.Services;

public sealed class TlsHelperClient
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public async Task<CertificateFetchResult?> TryFetchAsync(Uri uri, CancellationToken cancellationToken = default)
    {
        var request = new TlsHelperRequest
        {
            Host = uri.Host,
            Port = uri.Port,
            SniHost = uri.IdnHost
        };

        _ = request;

        var processResult = await TryFetchFromProcessAsync(request, cancellationToken);
        if (processResult is not null)
        {
            return processResult;
        }

        var stubPath = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "docs", "tls-helper-stub.json");
        var fullStubPath = Path.GetFullPath(stubPath);
        if (!File.Exists(fullStubPath))
        {
            return null;
        }

        await using var stream = File.OpenRead(fullStubPath);
        var response = await JsonSerializer.DeserializeAsync<TlsHelperResponse>(stream, JsonOptions, cancellationToken);
        if (response is null || !response.Success || response.ServerSentChain.Count == 0)
        {
            return null;
        }

        var certificates = response.ServerSentChain
            .OrderBy(certificate => certificate.Index)
            .Select(certificate => X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certificate.DerBase64)))
            .ToList();

        return new CertificateFetchResult
        {
            Certificates = certificates,
            Source = CertificateFetchSource.TlsHelper
        };
    }

    private static async Task<CertificateFetchResult?> TryFetchFromProcessAsync(
        TlsHelperRequest request,
        CancellationToken cancellationToken)
    {
        var helperPath = Path.Combine(AppContext.BaseDirectory, "TlsHelperStub.exe");
        if (!File.Exists(helperPath))
        {
            return null;
        }

        var stubPath = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "docs", "tls-helper-stub.json");
        var fullStubPath = Path.GetFullPath(stubPath);

        var startInfo = new ProcessStartInfo
        {
            FileName = helperPath,
            Arguments = $"\"{fullStubPath}\"",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = new Process { StartInfo = startInfo };
        if (!process.Start())
        {
            return null;
        }

        await process.StandardInput.WriteAsync(JsonSerializer.Serialize(request, JsonOptions));
        process.StandardInput.Close();

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        await process.WaitForExitAsync(cancellationToken);
        var stdout = await stdoutTask;
        _ = await stderrTask;

        if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(stdout))
        {
            return null;
        }

        var response = JsonSerializer.Deserialize<TlsHelperResponse>(stdout, JsonOptions);
        if (response is null || !response.Success || response.ServerSentChain.Count == 0)
        {
            return null;
        }

        var certificates = response.ServerSentChain
            .OrderBy(certificate => certificate.Index)
            .Select(certificate => X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certificate.DerBase64)))
            .ToList();

        return new CertificateFetchResult
        {
            Certificates = certificates,
            Source = CertificateFetchSource.TlsHelper
        };
    }
}
