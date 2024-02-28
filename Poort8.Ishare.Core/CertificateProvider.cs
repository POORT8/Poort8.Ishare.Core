using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Poort8.Ishare.Core;

public class CertificateProvider : ICertificateProvider
{
    private readonly X509Certificate2 _certificate;
    private readonly X509Certificate2Collection _chainCertificates;
    private readonly ILogger<CertificateProvider> _logger;
    private readonly IshareCoreOptions _options;

    public CertificateProvider(
        ILogger<CertificateProvider> logger,
        IOptions<IshareCoreOptions> options)
    {
        _logger = logger;
        _options = options.Value;

        try
        {
            var keyVaultUrl = _options.AzureKeyVaultUrl;
            var certificateName = _options.CertificateName;
            if (!string.IsNullOrWhiteSpace(keyVaultUrl) && !string.IsNullOrWhiteSpace(certificateName))
            {
                var certificateClient = new CertificateClient(new Uri(keyVaultUrl), new DefaultAzureCredential());
                _certificate = certificateClient.DownloadCertificate(certificateName);
            }
            else
            {
                _certificate = new X509Certificate2(
                    Convert.FromBase64String(_options.Certificate!),
                    string.IsNullOrEmpty(_options.CertificatePassword) ? null : _options.CertificatePassword);
            }

            _chainCertificates = new X509Certificate2Collection();
            var chain = _options.CertificateChain!.Split(',');
            foreach (var certificate in chain)
            {
                _chainCertificates.Add(
                    new X509Certificate2(Convert.FromBase64String(certificate),
                    string.IsNullOrEmpty(_options.CertificateChainPassword) ? null : _options.CertificateChainPassword));
            }
        }
        catch (Exception e)
        {
            _logger.LogCritical("Could not create the certificate from configuration: {msg}", e.Message);
            throw;
        }
    }

    public X509Certificate2 GetSigningCertificate()
    {
        return _certificate;
    }

    public X509SigningCredentials GetSigningCredentials()
    {
        return new X509SigningCredentials(_certificate);
    }

    public X509Chain GetChain()
    {
        var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(_chainCertificates);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; //TODO: iSHARE is not clear on whether to check revocation online as well.
        var isValid = chain.Build(_certificate);

        //NOTE: These are our trusted certificates from the configuration/vault, so we don't do additional checks.
        if (!isValid) { throw new Exception("Certificate chain is not valid."); }

        return chain;
    }

    public IEnumerable<string> GetChainString()
    {
        var chain = GetChain();
        return chain.ChainElements.Select(c => Convert.ToBase64String(c.Certificate.GetRawCertData()));
    }

    public static string GetSha256Thumbprint(X509Certificate2 certificate)
    {
        var hash = SHA256.HashData(certificate.RawData);
        return BitConverter.ToString(hash).Replace("-", string.Empty);
    }
}
