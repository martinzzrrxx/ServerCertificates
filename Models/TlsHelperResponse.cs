namespace ServerCertViewer.Models;

public sealed class TlsHelperResponse
{
    public required bool Success { get; init; }

    public required string FetchSource { get; init; }

    public string? NegotiatedTlsVersion { get; init; }

    public string? CipherSuite { get; init; }

    public IReadOnlyList<TlsHelperCertificatePayload> ServerSentChain { get; init; } = [];

    public string? ErrorCode { get; init; }

    public string? ErrorMessage { get; init; }

    public IReadOnlyList<string> Notes { get; init; } = [];
}
