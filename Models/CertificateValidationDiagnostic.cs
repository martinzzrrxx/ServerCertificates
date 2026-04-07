using System.Collections.Generic;
using System.Linq;

namespace ServerCertViewer.Models;

public sealed class CertificateValidationDiagnostic
{
    public required string Thumbprint { get; init; }

    public required int SourceChainIndex { get; init; }

    public int? RebuiltChainIndex { get; init; }

    public bool UsedInValidatedChain { get; init; }

    public IReadOnlyList<CertificateValidationIssue> Issues { get; init; } = [];

    public ValidationSeverity Severity => Issues.Count == 0
        ? ValidationSeverity.Info
        : Issues.Max(issue => issue.Severity);
}
