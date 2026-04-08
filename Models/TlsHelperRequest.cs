namespace ServerCertViewer.Models;

public sealed class TlsHelperRequest
{
    public required string Host { get; init; }

    public required int Port { get; init; }

    public required string SniHost { get; init; }

    public int ConnectTimeoutMs { get; init; } = 10_000;

    public IReadOnlyList<string> SupportedTlsVersions { get; init; } = ["TLS1.2", "TLS1.3"];
}
