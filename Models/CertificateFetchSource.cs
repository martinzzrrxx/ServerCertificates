namespace ServerCertViewer.Models;

public enum CertificateFetchSource
{
    TlsHelper = 0,
    RawServerSent = 1,
    SslStreamFallback = 2
}
