using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace Poort8.Ishare.Core.Tests;

public class Fixtures
{
    public static IOptions<IshareCoreOptions> GetCertificateTestOptions()
    {
        var testPassword = "test";
        var testCertificate = new X509Certificate2("test.serviceprovider.pfx", testPassword, X509KeyStorageFlags.Exportable);
        var testRootCertificate = new X509Certificate2("test.root.pfx", testPassword);

        var options = new IshareCoreOptions()
        {
            ClientId = "test",
            AuthorizationRegistryId = "test",
            AuthorizationRegistryUrl = "test",
            SatelliteId = "test",
            SatelliteUrl = "test",
            Certificate = Convert.ToBase64String(testCertificate.Export(X509ContentType.Pfx, testPassword)),
            CertificatePassword = testPassword,
            CertificateChain = Convert.ToBase64String(testRootCertificate.GetRawCertData()),
            CertificateChainPassword = testPassword
        };
        return Options.Create(options);
    }

    public static IOptions<IshareCoreOptions> GetServiceConsumerCertificateTestOptions()
    {
        var testPassword = "test";
        var testCertificate = new X509Certificate2("test.serviceconsumer.pfx", testPassword, X509KeyStorageFlags.Exportable);
        var testRootCertificate = new X509Certificate2("test.root.pfx", testPassword);

        var options = new IshareCoreOptions()
        {
            ClientId = "test",
            AuthorizationRegistryId = "test",
            AuthorizationRegistryUrl = "test",
            SatelliteId = "test",
            SatelliteUrl = "test",
            Certificate = Convert.ToBase64String(testCertificate.Export(X509ContentType.Pfx, testPassword)),
            CertificatePassword = testPassword,
            CertificateChain = Convert.ToBase64String(testRootCertificate.GetRawCertData()),
            CertificateChainPassword = testPassword
        };
        return Options.Create(options);
    }

    public static string CreateServiceConsumerClientAssertion(string issuer, string audience)
    {
        var options = GetServiceConsumerCertificateTestOptions();
        var certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, options);

        var claims = new ClaimsIdentity();
        claims.AddClaim(new Claim("sub", issuer));
        claims.AddClaim(new Claim("jti", Guid.NewGuid().ToString()));

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateJwtSecurityToken(
            issuer: issuer,
            audience: audience,
            subject: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddSeconds(30),
            issuedAt: DateTime.UtcNow,
            signingCredentials: certificateProvider.GetSigningCredentials());

        token.Header.Remove("kid");
        token.Header.Remove("x5t");
        token.Header.Add("x5c", certificateProvider.GetChainString().ToList());

        return tokenHandler.WriteToken(token);
    }
}
