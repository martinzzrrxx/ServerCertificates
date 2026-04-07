using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using ServerCertViewer.Models;

namespace ServerCertViewer.Services;

public static partial class CertificateValidationService
{
    public static ServerCertificateValidationResult Validate(Uri targetUri, IReadOnlyList<X509Certificate2> serverChain)
    {
        if (serverChain.Count == 0)
        {
            throw new InvalidOperationException("The server chain is empty.");
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.VerificationTime = DateTime.UtcNow;

        foreach (var certificate in serverChain.Skip(1))
        {
            chain.ChainPolicy.ExtraStore.Add(certificate);
        }

        var leafCertificate = serverChain[0];
        var isChainTrusted = chain.Build(leafCertificate);
        var rebuiltChain = chain.ChainElements
            .Cast<X509ChainElement>()
            .Select(element => X509CertificateLoader.LoadCertificate(element.Certificate.RawData))
            .ToList();

        var rebuiltIndexByThumbprint = rebuiltChain
            .Select((certificate, index) => new { certificate.Thumbprint, index })
            .Where(item => !string.IsNullOrWhiteSpace(item.Thumbprint))
            .ToDictionary(item => item.Thumbprint!, item => item.index, StringComparer.OrdinalIgnoreCase);

        var diagnostics = serverChain
            .Select((certificate, index) => BuildDiagnostic(certificate, index, rebuiltIndexByThumbprint, chain))
            .ToList();

        var serverThumbprints = new HashSet<string>(
            serverChain
                .Select(certificate => certificate.Thumbprint)
                .Where(thumbprint => !string.IsNullOrWhiteSpace(thumbprint))!
                .Select(thumbprint => thumbprint!),
            StringComparer.OrdinalIgnoreCase);

        diagnostics.AddRange(rebuiltChain
            .Select((certificate, index) => new { certificate, index })
            .Where(item => !string.IsNullOrWhiteSpace(item.certificate.Thumbprint) &&
                           !serverThumbprints.Contains(item.certificate.Thumbprint!))
            .Select(item => BuildDiagnostic(item.certificate, -1, rebuiltIndexByThumbprint, chain)));

        var serverIssues = MapChainStatuses(chain.ChainStatus);
        var hostnameMatch = IsHostnameMatch(targetUri.Host, leafCertificate, out var hostnameMessage);
        if (!hostnameMatch)
        {
            var hostnameIssue = new CertificateValidationIssue(
                "HostnameMismatch",
                "Hostname mismatch",
                hostnameMessage,
                ValidationSeverity.Error,
                "Hostname");

            diagnostics[0] = new CertificateValidationDiagnostic
            {
                Thumbprint = diagnostics[0].Thumbprint,
                SourceChainIndex = diagnostics[0].SourceChainIndex,
                RebuiltChainIndex = diagnostics[0].RebuiltChainIndex,
                UsedInValidatedChain = diagnostics[0].UsedInValidatedChain,
                Issues = diagnostics[0].Issues.Concat([hostnameIssue]).ToList()
            };
        }

        return new ServerCertificateValidationResult
        {
            TargetUri = targetUri,
            ValidatedAt = DateTimeOffset.UtcNow,
            IsChainTrusted = isChainTrusted,
            IsHostnameMatch = hostnameMatch,
            ServerIssues = serverIssues,
            CertificateDiagnostics = diagnostics,
            RebuiltChain = rebuiltChain
        };
    }

    private static CertificateValidationDiagnostic BuildDiagnostic(
        X509Certificate2 certificate,
        int sourceIndex,
        IReadOnlyDictionary<string, int> rebuiltIndexByThumbprint,
        X509Chain validatedChain)
    {
        var thumbprint = certificate.Thumbprint ?? string.Empty;
        var usedInValidatedChain = rebuiltIndexByThumbprint.TryGetValue(thumbprint, out var rebuiltIndex);

        List<CertificateValidationIssue> issues;
        if (usedInValidatedChain)
        {
            var element = validatedChain.ChainElements[rebuiltIndex];
            issues = MapChainStatuses(element.ChainElementStatus);
        }
        else
        {
            issues = [];
        }

        return new CertificateValidationDiagnostic
        {
            Thumbprint = thumbprint,
            SourceChainIndex = sourceIndex,
            RebuiltChainIndex = usedInValidatedChain ? rebuiltIndex : null,
            UsedInValidatedChain = usedInValidatedChain,
            Issues = issues
        };
    }

    private static List<CertificateValidationIssue> MapChainStatuses(X509ChainStatus[] statuses)
    {
        var issues = new List<CertificateValidationIssue>();
        var seen = new HashSet<X509ChainStatusFlags>();

        foreach (var status in statuses)
        {
            if (status.Status == X509ChainStatusFlags.NoError || !seen.Add(status.Status))
            {
                continue;
            }

            issues.Add(MapChainStatus(status.Status, status.StatusInformation));
        }

        return issues;
    }

    private static CertificateValidationIssue MapChainStatus(X509ChainStatusFlags status, string rawMessage)
    {
        return status switch
        {
            X509ChainStatusFlags.NotTimeValid => BuildIssue(status, "Certificate time invalid", "The certificate is expired or not yet valid.", ValidationSeverity.Error, "Chain"),
            X509ChainStatusFlags.UntrustedRoot => BuildIssue(status, "Untrusted root", "The chain terminates at a root certificate that is not trusted on this machine.", ValidationSeverity.Error, "Chain"),
            X509ChainStatusFlags.PartialChain => BuildIssue(status, "Partial chain", "The chain could not be completed to a trusted root.", ValidationSeverity.Error, "Chain"),
            X509ChainStatusFlags.Revoked => BuildIssue(status, "Revoked", "The certificate has been revoked.", ValidationSeverity.Error, "Chain"),
            X509ChainStatusFlags.OfflineRevocation => BuildIssue(status, "Revocation offline", "Revocation information could not be checked because the revocation server was offline or unreachable.", ValidationSeverity.Warning, "Revocation"),
            X509ChainStatusFlags.RevocationStatusUnknown => BuildIssue(status, "Unknown revocation status", "The revocation status could not be determined.", ValidationSeverity.Warning, "Revocation"),
            X509ChainStatusFlags.NotValidForUsage => BuildIssue(status, "Invalid usage", "The certificate is not valid for the required usage.", ValidationSeverity.Error, "Chain"),
            X509ChainStatusFlags.InvalidBasicConstraints => BuildIssue(status, "Invalid basic constraints", "The certificate has invalid CA or path length constraints.", ValidationSeverity.Error, "Chain"),
            X509ChainStatusFlags.InvalidNameConstraints => BuildIssue(status, "Invalid name constraints", "The certificate violates name constraints in the validation path.", ValidationSeverity.Error, "Chain"),
            X509ChainStatusFlags.Cyclic => BuildIssue(status, "Cyclic chain", "The chain contains a cycle.", ValidationSeverity.Error, "Chain"),
            X509ChainStatusFlags.NotTimeNested => BuildIssue(status, "Improper time nesting", "The certificate validity period is not properly nested within the issuer certificate validity period.", ValidationSeverity.Warning, "Chain"),
            X509ChainStatusFlags.HasWeakSignature => BuildIssue(status, "Weak signature", "The certificate uses a weak signature algorithm.", ValidationSeverity.Warning, "Chain"),
            _ => BuildIssue(status, status.ToString(), NormalizeRawStatusMessage(rawMessage), ValidationSeverity.Warning, "Chain")
        };
    }

    private static CertificateValidationIssue BuildIssue(
        X509ChainStatusFlags status,
        string title,
        string message,
        ValidationSeverity severity,
        string source)
    {
        return new CertificateValidationIssue(status.ToString(), title, message, severity, source);
    }

    private static string NormalizeRawStatusMessage(string rawMessage)
    {
        var message = string.IsNullOrWhiteSpace(rawMessage) ? "The chain status indicates a validation issue." : rawMessage.Trim();
        return RegexWhitespace().Replace(message, " ");
    }

    private static bool IsHostnameMatch(string host, X509Certificate2 certificate, out string message)
    {
        var normalizedHost = host.Trim().TrimEnd('.').ToLowerInvariant();
        var candidateNames = GetDnsNames(certificate).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        if (candidateNames.Count == 0)
        {
            message = $"The leaf certificate does not contain a DNS name that can be matched against '{host}'.";
            return false;
        }

        if (candidateNames.Any(name => IsHostMatch(normalizedHost, name)))
        {
            message = string.Empty;
            return true;
        }

        message = string.Format(
            CultureInfo.InvariantCulture,
            "The leaf certificate does not match '{0}'. Candidate names: {1}.",
            host,
            string.Join(", ", candidateNames));
        return false;
    }

    private static IEnumerable<string> GetDnsNames(X509Certificate2 certificate)
    {
        var sanExtension = certificate.Extensions["2.5.29.17"];
        if (sanExtension is not null)
        {
            foreach (Match match in RegexDnsName().Matches(sanExtension.Format(true)))
            {
                var value = match.Groups[1].Value.Trim();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    yield return value;
                }
            }
        }

        var dnsName = certificate.GetNameInfo(X509NameType.DnsName, false);
        if (!string.IsNullOrWhiteSpace(dnsName))
        {
            yield return dnsName.Trim();
        }
    }

    private static bool IsHostMatch(string host, string pattern)
    {
        var normalizedPattern = pattern.Trim().TrimEnd('.').ToLowerInvariant();
        if (normalizedPattern.Length == 0)
        {
            return false;
        }

        if (!normalizedPattern.StartsWith("*.", StringComparison.Ordinal))
        {
            return string.Equals(host, normalizedPattern, StringComparison.OrdinalIgnoreCase);
        }

        var suffix = normalizedPattern[1..];
        if (!host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var hostLabels = host.Split('.');
        var suffixLabels = suffix.TrimStart('.').Split('.');
        return hostLabels.Length == suffixLabels.Length + 1;
    }

    [GeneratedRegex(@"DNS Name=(.+?)(?:,|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RegexDnsName();

    [GeneratedRegex(@"\s+", RegexOptions.CultureInvariant)]
    private static partial Regex RegexWhitespace();
}
