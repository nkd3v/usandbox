using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace USandbox;

/// <summary>
/// A certificate authority that exists only for one sandbox run. Its private key is generated in
/// memory and never exported or written anywhere; it signs the certificates the proxy shows to the
/// sandboxed program and a CRL that the proxy serves itself, so Windows revocation checks succeed.
/// Only the throwaway account trusts it, and that account is deleted at the end of the run.
/// </summary>
sealed class CertificateAuthority : IDisposable
{
    readonly ECDsa caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    readonly ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    readonly X509Certificate2 caWithKey;
    readonly ConcurrentDictionary<string, Lazy<(X509Certificate2 Cert, SslStreamCertificateContext Context)>> leaves =
        new(StringComparer.OrdinalIgnoreCase);
    readonly string crlUrl;
    readonly DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-1), notAfter = DateTimeOffset.UtcNow.AddDays(14);

    /// <summary>The CA certificate without its private key.</summary>
    public X509Certificate2 Certificate { get; }
    public byte[] Crl { get; }

    public CertificateAuthority(string label, string crlUrl)
    {
        this.crlUrl = crlUrl;
        var request = new CertificateRequest($"CN=usandbox ephemeral CA ({label}), O=usandbox", caKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        caWithKey = request.CreateSelfSigned(notBefore, notAfter);
        Certificate = X509CertificateLoader.LoadCertificate(caWithKey.RawData);

        // An empty CRL: nothing this CA issued is revoked.
        Crl = new CertificateRevocationListBuilder().Build(caWithKey, BigInteger.One, notAfter, HashAlgorithmName.SHA256);
    }

    public string CertificatePem => Certificate.ExportCertificatePem();

    /// <summary>Server certificate (and chain context) for <paramref name="host"/>, created on first use.</summary>
    public SslStreamCertificateContext GetServerContext(string host) =>
        leaves.GetOrAdd(host, h => new Lazy<(X509Certificate2, SslStreamCertificateContext)>(() => CreateLeaf(h))).Value.Context;

    (X509Certificate2, SslStreamCertificateContext) CreateLeaf(string host)
    {
        string cn = host.Length > 64 ? host[..64] : host;
        var request = new CertificateRequest($"CN={cn}, O=usandbox", leafKey, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        if (IPAddress.TryParse(host, out var ip)) san.AddIpAddress(ip); else san.AddDnsName(host);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(caWithKey, true, false));
        request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(new[] { crlUrl }));

        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        using var issued = request.Create(caWithKey, notBefore, notAfter, serial);
        using var withKey = issued.CopyWithPrivateKey(leafKey);

        // Schannel cannot use an in-memory (ephemeral) key, so the leaf goes through a PKCS#12
        // round trip. Windows keeps that key in a temporary container that is deleted when the
        // certificate is disposed. The leaf key is not the CA key: it cannot sign other certificates.
        var cert = X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.DefaultKeySet);
        var context = SslStreamCertificateContext.Create(cert, new X509Certificate2Collection(Certificate), offline: true);
        return (cert, context);
    }

    /// <summary>The CA certificate plus the machine's trusted roots, for programs that read a PEM bundle.</summary>
    public string BuildPemBundle()
    {
        var sb = new StringBuilder();
        sb.Append("# usandbox ephemeral CA\n").Append(CertificatePem).Append('\n');
        using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        foreach (var cert in store.Certificates)
        {
            using (cert)
            {
                if (cert.NotAfter < DateTime.Now) continue;
                sb.Append("# ").Append(cert.GetNameInfo(X509NameType.SimpleName, false)).Append('\n');
                sb.Append(cert.ExportCertificatePem()).Append('\n');
            }
        }
        return sb.ToString();
    }

    public void Dispose()
    {
        foreach (var leaf in leaves.Values)
        {
            if (leaf.IsValueCreated) leaf.Value.Cert.Dispose();
        }
        leaves.Clear();
        caWithKey.Dispose();
        Certificate.Dispose();
        caKey.Dispose();
        leafKey.Dispose();
    }
}
