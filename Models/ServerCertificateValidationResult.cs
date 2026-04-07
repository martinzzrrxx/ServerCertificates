using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace ServerCertViewer.Models;

public sealed class ServerCertificateValidationResult
{
    public required Uri TargetUri { get; init; }

    public required DateTimeOffset ValidatedAt { get; init; }

    public required bool IsChainTrusted { get; init; }

    public required bool IsHostnameMatch { get; init; }

    public required IReadOnlyList<CertificateValidationIssue> ServerIssues { get; init; }

    public required IReadOnlyList<CertificateValidationDiagnostic> CertificateDiagnostics { get; init; }

    public required IReadOnlyList<X509Certificate2> RebuiltChain { get; init; }
}
