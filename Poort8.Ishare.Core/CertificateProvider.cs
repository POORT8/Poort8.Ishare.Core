using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace Poort8.Ishare.Core;

public class CertificateProvider : ICertificateProvider
{
    private readonly X509Certificate2 _certificate;
    private readonly X509Certificate2Collection _chainCertificates;
    private readonly ILogger<CertificateProvider> _logger;

    public CertificateProvider(ILogger<CertificateProvider> logger, IConfiguration configuration)
    {
        _logger = logger;

        try
        {
            var keyVaultUrl = configuration["AzureKeyVaultUrl"];
            var certificateName = configuration["CertificateName"];
            if (!string.IsNullOrWhiteSpace(keyVaultUrl) && !string.IsNullOrWhiteSpace(certificateName))
            {
                var certificateClient = new CertificateClient(new Uri(keyVaultUrl), new DefaultAzureCredential());
                _certificate = certificateClient.DownloadCertificate(certificateName);
            }
            else
            {
                _certificate = new X509Certificate2(
                    Convert.FromBase64String(configuration["Certificate"]!),
                    string.IsNullOrEmpty(configuration["CertificatePassword"]) ? null : configuration["CertificatePassword"]);
            }

            _chainCertificates = new X509Certificate2Collection();
            var chain = configuration["CertificateChain"]!.Split(',');
            foreach (var certificate in chain)
            {
                _chainCertificates.Add(new X509Certificate2(Convert.FromBase64String(certificate), string.IsNullOrEmpty(configuration["CertificateChainPassword"]) ? null : configuration["CertificateChainPassword"]));
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
        //iSHARE reference: https://github.com/iSHAREScheme/code-snippets/blob/master/DotNet/CertificateValidator.cs

        var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(_chainCertificates);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        var isValid = chain.Build(_certificate);

        foreach (var chainStatus in chain.ChainStatus)
        {
            _logger.LogWarning("Chain status warning: {chainStatus} with information: {chainStatusInformation}", chainStatus.Status, chainStatus.StatusInformation);
        }

        if (!isValid)
        {
            _logger.LogCritical("Certificate chain is not valid.");
            throw new Exception("Certificate chain is not valid.");
        }

        return chain;
    }

    public IEnumerable<string> GetChainString()
    {
        var chain = GetChain();
        return chain.ChainElements.Select(c => Convert.ToBase64String(c.Certificate.GetRawCertData()));
    }
}
