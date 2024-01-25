using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace Poort8.Ishare.Core.Testsv2;

public class CertificateProviderTests
{
    private readonly IConfigurationRoot _configuration;

    public CertificateProviderTests()
    {
        var testPassword = "poort8.ishare.common.tests";
        var testCertificate = new X509Certificate2("poort8.ishare.common.tests.pfx", testPassword);
        var testRootCertificate = new X509Certificate2("poort8.ishare.common.tests.root.pfx", testPassword);

        var config = new Dictionary<string, string>
        {
            { "Certificate", Convert.ToBase64String(testCertificate.GetRawCertData()) },
            { "CertificatePassword", testPassword },
            { "CertificateChain", Convert.ToBase64String(testRootCertificate.GetRawCertData())},
            { "CertificateChainPassword", testPassword}
        };

        _configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(config!)
            .Build();
    }

    [Fact]
    public void GetSigningCertificateReturnsX509Certificate2()
    {
        var certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _configuration);

        var certificate = certificateProvider.GetSigningCertificate();

        certificate.Should().BeOfType<X509Certificate2>();
        certificate.Subject.Should().Be("CN=poort8.ishare.common.tests");
        certificate.Issuer.Should().Be("CN=poort8.ishare.common.tests.root");
    }

    [Fact]
    public void GetSigningCredentialsReturnsX509SigningCredentials()
    {
        var certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _configuration);

        var signingCredentials = certificateProvider.GetSigningCredentials();

        signingCredentials.Should().BeOfType<X509SigningCredentials>();
        signingCredentials.Certificate.Subject.Should().Be("CN=poort8.ishare.common.tests");
        signingCredentials.Certificate.Issuer.Should().Be("CN=poort8.ishare.common.tests.root");
    }

    [Fact]
    public void GetChainReturnsX509Chain()
    {
        var certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _configuration);

        var chain = certificateProvider.GetChain();

        chain.Should().BeOfType<X509Chain>();
        chain.ChainElements.Count.Should().Be(2);
        chain.ChainElements[0].Certificate.Subject.Should().Be("CN=poort8.ishare.common.tests");
        chain.ChainElements[0].Certificate.Issuer.Should().Be("CN=poort8.ishare.common.tests.root");
        chain.ChainElements[1].Certificate.Subject.Should().Be("CN=poort8.ishare.common.tests.root");
        chain.ChainElements[1].Certificate.Issuer.Should().Be("CN=poort8.ishare.common.tests.root");
    }

    [Fact]
    public void GetChainStringReturnsIEnumerableOfString()
    {
        var certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _configuration);

        var chain = certificateProvider.GetChainString();

        chain.Should().BeAssignableTo<IEnumerable<string>>();
        chain.Count().Should().Be(2);
    }

    [Fact]
    public void GetChainShouldFailForWrongCertificate()
    {
        var failCertificate = new X509Certificate2("poort8.ishare.common.tests.fail.pfx", "poort8.ishare.common.tests");
        _configuration.GetSection("Certificate").Value = Convert.ToBase64String(failCertificate.GetRawCertData());
        var certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _configuration);

        Action act = () => certificateProvider.GetChain();

        act.Should().Throw<Exception>();
    }
}