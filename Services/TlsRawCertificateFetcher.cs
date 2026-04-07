using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ServerCertViewer.Services;

internal static class TlsRawCertificateFetcher
{
    public static async Task<IReadOnlyList<X509Certificate2>> FetchAsync(Uri uri, CancellationToken cancellationToken)
    {
        using var tcpClient = new TcpClient();
        await tcpClient.ConnectAsync(uri.Host, uri.Port, cancellationToken);

        using var networkStream = tcpClient.GetStream();
        var clientHello = BuildClientHello(uri.IdnHost);
        await networkStream.WriteAsync(clientHello, cancellationToken);
        await networkStream.FlushAsync(cancellationToken);

        var handshakeBuffer = new List<byte>();

        while (true)
        {
            var record = await ReadTlsRecordAsync(networkStream, cancellationToken);
            switch (record.ContentType)
            {
                case 22:
                    handshakeBuffer.AddRange(record.Payload);
                    if (TryExtractCertificates(handshakeBuffer, out var certificates))
                    {
                        return certificates;
                    }

                    break;
                case 21:
                    throw new InvalidOperationException("The server returned a TLS alert before sending a certificate chain.");
                case 23:
                    throw new InvalidOperationException("The server switched to encrypted TLS records before exposing a readable certificate message.");
            }
        }
    }

    private static byte[] BuildClientHello(string host)
    {
        var hostBytes = Encoding.ASCII.GetBytes(host);
        var random = new byte[32];
        RandomNumberGenerator.Fill(random);

        var cipherSuites = new byte[]
        {
            0xC0, 0x2F,
            0xC0, 0x30,
            0xC0, 0x2B,
            0xC0, 0x2C,
            0x00, 0x9C,
            0x00, 0x9D,
            0x00, 0x2F,
            0x00, 0x35
        };

        var extensions = new List<byte>();
        extensions.AddRange(BuildServerNameExtension(hostBytes));
        extensions.AddRange(BuildSupportedGroupsExtension());
        extensions.AddRange(BuildEcPointFormatsExtension());
        extensions.AddRange(BuildSignatureAlgorithmsExtension());

        var helloBodyLength = 2 + 32 + 1 + 2 + cipherSuites.Length + 1 + 1 + 2 + extensions.Count;
        var handshakeLength = 4 + helloBodyLength;
        var recordLength = handshakeLength;

        var output = new byte[5 + recordLength];
        var offset = 0;

        output[offset++] = 0x16;
        output[offset++] = 0x03;
        output[offset++] = 0x03;
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset, 2), (ushort)recordLength);
        offset += 2;

        output[offset++] = 0x01;
        WriteUInt24BigEndian(output.AsSpan(offset, 3), helloBodyLength);
        offset += 3;

        output[offset++] = 0x03;
        output[offset++] = 0x03;
        random.CopyTo(output, offset);
        offset += random.Length;

        output[offset++] = 0x00;

        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset, 2), (ushort)cipherSuites.Length);
        offset += 2;
        cipherSuites.CopyTo(output, offset);
        offset += cipherSuites.Length;

        output[offset++] = 0x01;
        output[offset++] = 0x00;

        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset, 2), (ushort)extensions.Count);
        offset += 2;
        extensions.CopyTo(output, offset);

        return output;
    }

    private static IEnumerable<byte> BuildServerNameExtension(byte[] hostBytes)
    {
        var extension = new byte[9 + hostBytes.Length];
        var offset = 0;

        extension[offset++] = 0x00;
        extension[offset++] = 0x00;
        BinaryPrimitives.WriteUInt16BigEndian(extension.AsSpan(offset, 2), (ushort)(5 + hostBytes.Length));
        offset += 2;
        BinaryPrimitives.WriteUInt16BigEndian(extension.AsSpan(offset, 2), (ushort)(3 + hostBytes.Length));
        offset += 2;
        extension[offset++] = 0x00;
        BinaryPrimitives.WriteUInt16BigEndian(extension.AsSpan(offset, 2), (ushort)hostBytes.Length);
        offset += 2;
        hostBytes.CopyTo(extension, offset);

        return extension;
    }

    private static IEnumerable<byte> BuildSupportedGroupsExtension()
    {
        return new byte[]
        {
            0x00, 0x0A,
            0x00, 0x08,
            0x00, 0x06,
            0x00, 0x17,
            0x00, 0x18,
            0x00, 0x19
        };
    }

    private static IEnumerable<byte> BuildEcPointFormatsExtension()
    {
        return new byte[]
        {
            0x00, 0x0B,
            0x00, 0x02,
            0x01,
            0x00
        };
    }

    private static IEnumerable<byte> BuildSignatureAlgorithmsExtension()
    {
        return new byte[]
        {
            0x00, 0x0D,
            0x00, 0x12,
            0x00, 0x10,
            0x04, 0x01,
            0x05, 0x01,
            0x06, 0x01,
            0x04, 0x03,
            0x05, 0x03,
            0x06, 0x03,
            0x02, 0x01,
            0x02, 0x03
        };
    }

    private static async Task<TlsRecord> ReadTlsRecordAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var header = new byte[5];
        await ReadExactAsync(stream, header, cancellationToken);

        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(3, 2));
        var payload = new byte[payloadLength];
        await ReadExactAsync(stream, payload, cancellationToken);

        return new TlsRecord(header[0], payload);
    }

    private static async Task ReadExactAsync(NetworkStream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var bytesRead = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), cancellationToken);
            if (bytesRead == 0)
            {
                throw new InvalidOperationException("The server closed the connection before the certificate chain was fully read.");
            }

            read += bytesRead;
        }
    }

    private static bool TryExtractCertificates(List<byte> handshakeBytes, out IReadOnlyList<X509Certificate2> certificates)
    {
        certificates = [];
        var offset = 0;

        while (offset + 4 <= handshakeBytes.Count)
        {
            var messageType = handshakeBytes[offset];
            var messageLength = ReadUInt24BigEndian(handshakeBytes, offset + 1);
            if (offset + 4 + messageLength > handshakeBytes.Count)
            {
                return false;
            }

            if (messageType == 0x0B)
            {
                certificates = ParseCertificateMessage(handshakeBytes, offset + 4, messageLength);
                return true;
            }

            offset += 4 + messageLength;
        }

        return false;
    }

    private static IReadOnlyList<X509Certificate2> ParseCertificateMessage(List<byte> handshakeBytes, int offset, int length)
    {
        if (length < 3)
        {
            throw new InvalidOperationException("The TLS certificate message was too short.");
        }

        var certificateListLength = ReadUInt24BigEndian(handshakeBytes, offset);
        var cursor = offset + 3;
        var end = cursor + certificateListLength;

        if (end > offset + length)
        {
            throw new InvalidOperationException("The TLS certificate list length was invalid.");
        }

        var certificates = new List<X509Certificate2>();
        while (cursor + 3 <= end)
        {
            var certificateLength = ReadUInt24BigEndian(handshakeBytes, cursor);
            cursor += 3;

            if (cursor + certificateLength > end)
            {
                throw new InvalidOperationException("A TLS certificate entry exceeded the certificate list bounds.");
            }

            var rawCertificate = handshakeBytes.Skip(cursor).Take(certificateLength).ToArray();
            certificates.Add(X509CertificateLoader.LoadCertificate(rawCertificate));
            cursor += certificateLength;
        }

        return certificates;
    }

    private static void WriteUInt24BigEndian(Span<byte> destination, int value)
    {
        destination[0] = (byte)((value >> 16) & 0xFF);
        destination[1] = (byte)((value >> 8) & 0xFF);
        destination[2] = (byte)(value & 0xFF);
    }

    private static int ReadUInt24BigEndian(List<byte> bytes, int offset)
    {
        return (bytes[offset] << 16) | (bytes[offset + 1] << 8) | bytes[offset + 2];
    }

    private readonly record struct TlsRecord(byte ContentType, byte[] Payload);
}
