using System.Security.Cryptography.X509Certificates;

namespace ServerCertViewer.Models;

public sealed class RebuiltChainEntryViewItem
{
    public RebuiltChainEntryViewItem(X509Certificate2 certificate, int index)
    {
        DisplayIndex = index + 1;
        DisplayName = string.IsNullOrWhiteSpace(certificate.GetNameInfo(X509NameType.SimpleName, false))
            ? $"Certificate {DisplayIndex}"
            : certificate.GetNameInfo(X509NameType.SimpleName, false);
        Subject = certificate.Subject;
        PositionLabel = index == 0 ? "Leaf" : $"Validated chain #{DisplayIndex}";
    }

    public int DisplayIndex { get; }

    public string DisplayName { get; }

    public string Subject { get; }

    public string PositionLabel { get; }
}
