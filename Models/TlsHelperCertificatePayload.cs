namespace ServerCertViewer.Models;

public sealed class TlsHelperCertificatePayload
{
    public required int Index { get; init; }

    public required string Subject { get; init; }

    public required string Issuer { get; init; }

    public required string Thumbprint { get; init; }

    public required string DerBase64 { get; init; }
}
