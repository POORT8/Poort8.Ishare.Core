using System.Security.Cryptography.X509Certificates;

namespace Poort8.Ishare.Core;

public interface ICertificateValidator
{
    X509Chain ValidateChain(X509Certificate2Collection chainCertificates, X509Certificate2 signingCertificate);
    Task<X509Certificate2> ValidateX5cChain(string[] chainString);
}
