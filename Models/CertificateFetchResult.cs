using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace ServerCertViewer.Models;

public sealed class CertificateFetchResult
{
    public required IReadOnlyList<X509Certificate2> Certificates { get; init; }

    public required CertificateFetchSource Source { get; init; }
}
