using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ServerCertViewer.Models;

public sealed class CertificateViewItem
{
    public CertificateViewItem(
        X509Certificate2 certificate,
        int index,
        bool isServerProvided = true,
        bool canDisplayChainDiff = false)
    {
        Certificate = certificate;
        Index = index;
        IsServerProvided = isServerProvided;
        CanDisplayChainDiff = canDisplayChainDiff;
        DisplayName = string.IsNullOrWhiteSpace(certificate.GetNameInfo(X509NameType.SimpleName, false))
            ? $"Certificate {index}"
            : certificate.GetNameInfo(X509NameType.SimpleName, false);
        Subject = certificate.Subject;
        Issuer = certificate.Issuer;
        Thumbprint = certificate.Thumbprint ?? string.Empty;
        SerialNumber = certificate.SerialNumber ?? string.Empty;
        Version = certificate.Version.ToString(CultureInfo.InvariantCulture);
        NotBefore = certificate.NotBefore.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
        NotAfter = certificate.NotAfter.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
        SignatureAlgorithm = certificate.SignatureAlgorithm.FriendlyName ?? certificate.SignatureAlgorithm.Value ?? string.Empty;
        PublicKeyAlgorithm = certificate.PublicKey.Oid.FriendlyName ?? certificate.PublicKey.Oid.Value ?? string.Empty;
        PublicKeyLength = GetPublicKeyLength(certificate);
        SubjectAlternativeNames = ReadExtensionValue(certificate, "2.5.29.17");
        BasicConstraints = ReadExtensionValue(certificate, "2.5.29.19");
        KeyUsage = ReadExtensionValue(certificate, "2.5.29.15");
        EnhancedKeyUsage = ReadEnhancedKeyUsage(certificate);
    }

    public X509Certificate2 Certificate { get; }

    public int Index { get; }

    public int DisplayIndex => Index + 1;

    public string DisplayName { get; }

    public string Subject { get; }

    public string Issuer { get; }

    public string Thumbprint { get; }

    public string SerialNumber { get; }

    public string Version { get; }

    public string NotBefore { get; }

    public string NotAfter { get; }

    public string SignatureAlgorithm { get; }

    public string PublicKeyAlgorithm { get; }

    public string PublicKeyLength { get; }

    public string SubjectAlternativeNames { get; }

    public string BasicConstraints { get; }

    public string KeyUsage { get; }

    public string EnhancedKeyUsage { get; }

    public IReadOnlyList<CertificateValidationIssue> ValidationIssues { get; private set; } = [];

    public ValidationSeverity ValidationSeverity { get; private set; } = ValidationSeverity.Info;

    public bool UsedInValidatedChain { get; private set; } = true;

    public string UsedInValidatedChainLabel => UsedInValidatedChain ? "Yes" : "No";

    public string ValidatedChainPosition { get; private set; } = "Not used";

    public bool IsServerProvided { get; }

    public bool IsValidatedOnly => !IsServerProvided;

    public bool CanDisplayChainDiff { get; }

    public bool ShouldShowValidatedOnlyBadge => CanDisplayChainDiff && IsValidatedOnly;

    public bool ShouldShowNotUsedBadge => CanDisplayChainDiff && IsServerProvided && !UsedInValidatedChain;

    public bool ShouldShowChainSourceSummary => ShouldShowValidatedOnlyBadge || ShouldShowNotUsedBadge;

    public string ChainPosition => IsValidatedOnly
        ? "Validated chain only"
        : Index == 0
            ? "Leaf"
            : $"Intermediate / Root #{Index}";

    public bool HasValidationIssues => ValidationIssues.Count > 0;

    public bool HasNoValidationIssues => ValidationIssues.Count == 0;

    public string ValidationStatusLabel => ValidationSeverity switch
    {
        ValidationSeverity.Error => "Error",
        ValidationSeverity.Warning => "Warning",
        _ => "Valid"
    };

    public string ValidationSummary => ValidationIssues.Count switch
    {
        0 => "No validation issues detected.",
        1 => ValidationIssues[0].Title,
        _ => $"{ValidationIssues.Count} validation issues"
    };

    public string ChainSourceSummary => IsValidatedOnly
        ? "Present in validated chain only."
        : UsedInValidatedChain
            ? string.Empty
            : "Not used in validated chain.";

    public void ApplyValidationDiagnostic(CertificateValidationDiagnostic? diagnostic)
    {
        ValidationIssues = diagnostic?.Issues ?? [];
        ValidationSeverity = diagnostic?.Severity ?? ValidationSeverity.Info;
        UsedInValidatedChain = diagnostic?.UsedInValidatedChain ?? true;
        ValidatedChainPosition = diagnostic is null
            ? "Unknown"
            : diagnostic.RebuiltChainIndex is int rebuiltIndex
                ? rebuiltIndex == 0 ? "Leaf" : $"Validated chain #{rebuiltIndex + 1}"
                : "Not used";
    }

    private static string ReadExtensionValue(X509Certificate2 certificate, string oid)
    {
        var extension = certificate.Extensions.Cast<X509Extension>().FirstOrDefault(item => item.Oid?.Value == oid);
        return string.IsNullOrWhiteSpace(extension?.Format(true)) ? "N/A" : extension!.Format(true);
    }

    private static string ReadEnhancedKeyUsage(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (extension is null || extension.EnhancedKeyUsages.Count == 0)
        {
            return "N/A";
        }

        return string.Join(", ", extension.EnhancedKeyUsages.Cast<Oid>().Select(oid => oid.FriendlyName ?? oid.Value));
    }

    private static string GetPublicKeyLength(X509Certificate2 certificate)
    {
        using RSA? rsa = certificate.GetRSAPublicKey();
        if (rsa?.KeySize > 0)
        {
            return $"{rsa.KeySize} bits";
        }

        using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
        if (ecdsa?.KeySize > 0)
        {
            return $"{ecdsa.KeySize} bits";
        }

        using DSA? dsa = certificate.GetDSAPublicKey();
        if (dsa?.KeySize > 0)
        {
            return $"{dsa.KeySize} bits";
        }

        return "Unknown";
    }
}
