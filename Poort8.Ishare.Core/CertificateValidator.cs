using Microsoft.Extensions.Logging;
using System.Security.Cryptography.X509Certificates;

namespace Poort8.Ishare.Core;

public class CertificateValidator(
    ILogger<CertificateValidator> logger,
    ISatelliteService satelliteService) : ICertificateValidator
{
    public async Task<X509Certificate2> ValidateX5cChain(string[] chainString)
    {
        var signingCertificate = new X509Certificate2(Convert.FromBase64String(chainString.First()));
        var chainCertificates = new X509Certificate2Collection();
        foreach (var certificate in chainString.Skip(1))
        {
            var chainCertificate = new X509Certificate2(Convert.FromBase64String(certificate));
            await CheckCertificateIsInTrustedList(chainCertificate);
            chainCertificates.Add(chainCertificate);
        }

        _ = ValidateChain(chainCertificates, signingCertificate);

        return signingCertificate;
    }

    public X509Chain ValidateChain(X509Certificate2Collection chainCertificates, X509Certificate2 signingCertificate)
    {
        //iSHARE reference: https://github.com/iSHAREScheme/code-snippets/blob/master/DotNet/CertificateValidator.cs

        var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(chainCertificates);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; //TODO: iSHARE is not clear on whether to check revocation online as well.
        var isValid = chain.Build(signingCertificate);

        foreach (var chainStatus in chain.ChainStatus)
        {
            logger.LogWarning("Chain status warning: {chainStatus} with information: {chainStatusInformation}", chainStatus.Status, chainStatus.StatusInformation);

            if (chainStatus.Status != X509ChainStatusFlags.NoError)
            {
                throw new Exception("Certificate chain validation issue on chain status.");
            }
        }

        var keyUsages = signingCertificate.Extensions.OfType<X509KeyUsageExtension>();
        if (!keyUsages.Any(u =>
            u.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature) || //NOTE: iSHARE uses DigitalSignature and NonRepudiation, should be only NonRepudiation.
            u.KeyUsages.HasFlag(X509KeyUsageFlags.NonRepudiation)))
        {
            throw new Exception("Signing certificate does not have a digital signature or non-repudiation key usage.");
        };

        if (!isValid)
        {
            logger.LogCritical("Certificate chain is not valid.");
            throw new Exception("Certificate chain is not valid.");
        }

        return chain;
    }

    private async Task CheckCertificateIsInTrustedList(X509Certificate2 x509Certificate2)
    {
        var trustedList = await satelliteService.GetValidTrustedList();

        var certificateThumbprint = CertificateProvider.GetSha256Thumbprint(x509Certificate2);

        if (trustedList.Any(c => c.CertificateFingerprint == certificateThumbprint))
        {
            logger.LogInformation("Found root certificate {certSubject} ({certThumbprint}) in trusted list.", x509Certificate2.Subject, certificateThumbprint);
        }
        else
        {
            logger.LogError("Root certificate {certSubject} ({certThumbprint}) is not in trusted list.", x509Certificate2.Subject, certificateThumbprint);
            throw new Exception("Root certificate is not in trusted list.");
        }
    }
}
