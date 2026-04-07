using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace ServerCertViewer.Services;

public static class CertificateChainFetcher
{
    public static async Task<IReadOnlyList<X509Certificate2>> FetchAsync(Uri uri, CancellationToken cancellationToken = default)
    {
        List<X509Certificate2>? capturedChain = null;

        using var tcpClient = new TcpClient();
        await tcpClient.ConnectAsync(uri.Host, uri.Port, cancellationToken);

        using var sslStream = new SslStream(
            tcpClient.GetStream(),
            leaveInnerStreamOpen: false,
            (sender, certificate, chain, errors) =>
            {
                capturedChain = CreateChainSnapshot(certificate, chain);
                return true;
            });

        var options = new SslClientAuthenticationOptions
        {
            TargetHost = uri.Host,
            EnabledSslProtocols = SslProtocols.None,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck
        };

        await sslStream.AuthenticateAsClientAsync(options, cancellationToken);

        if (capturedChain is { Count: > 0 })
        {
            return capturedChain;
        }

        if (sslStream.RemoteCertificate is null)
        {
            throw new InvalidOperationException("The remote server did not provide a certificate.");
        }

        using var remoteCertificate = X509CertificateLoader.LoadCertificate(sslStream.RemoteCertificate.Export(X509ContentType.Cert));
        using var rebuiltChain = new X509Chain();
        rebuiltChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        rebuiltChain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
        rebuiltChain.Build(remoteCertificate);

        return CreateChainSnapshot(remoteCertificate, rebuiltChain);
    }

    private static List<X509Certificate2> CreateChainSnapshot(X509Certificate? certificate, X509Chain? chain)
    {
        var result = new List<X509Certificate2>();

        if (chain?.ChainElements.Count > 0)
        {
            result.AddRange(chain.ChainElements
                .Cast<X509ChainElement>()
                .Select(element => X509CertificateLoader.LoadCertificate(element.Certificate.RawData)));
        }
        else if (certificate is not null)
        {
            result.Add(X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert)));
        }

        return result;
    }
}
