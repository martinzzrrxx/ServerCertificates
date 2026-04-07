namespace ServerCertViewer.Models;

public sealed record CertificateValidationIssue(
    string Code,
    string Title,
    string Message,
    ValidationSeverity Severity,
    string Source);
