using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace Poort8.Ishare.Core;

public interface ICertificateProvider
{
    X509Certificate2 GetSigningCertificate();
    X509SigningCredentials GetSigningCredentials();
    X509Chain GetChain();
    IEnumerable<string> GetChainString();
}
