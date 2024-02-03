using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Poort8.Ishare.Core.Tests;

public class CertificateProviderTests
{
    private IOptions<IshareCoreOptions> _options;

    public CertificateProviderTests()
    {
        _options = Fixtures.GetCertificateTestOptions();
    }

    [Fact]
    public void GetSigningCertificateReturnsX509Certificate2()
    {
        var certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _options);

        var certificate = certificateProvider.GetSigningCertificate();

        certificate.Should().BeOfType<X509Certificate2>();
        certificate.Subject.Should().Be("CN=test.serviceprovider");
        certificate.Issuer.Should().Be("CN=test.root");
    }

    [Fact]
    public void GetSigningCredentialsReturnsX509SigningCredentials()
    {
        var certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _options);

        var signingCredentials = certificateProvider.GetSigningCredentials();

        signingCredentials.Should().BeOfType<X509SigningCredentials>();
        signingCredentials.Certificate.Subject.Should().Be("CN=test.serviceprovider");
        signingCredentials.Certificate.Issuer.Should().Be("CN=test.root");
    }

    [Fact]
    public void GetChainReturnsX509Chain()
    {
        var certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _options);

        var chain = certificateProvider.GetChain();

        chain.Should().BeOfType<X509Chain>();
        chain.ChainElements.Count.Should().Be(2);
        chain.ChainElements[0].Certificate.Subject.Should().Be("CN=test.serviceprovider");
        chain.ChainElements[0].Certificate.Issuer.Should().Be("CN=test.root");
        chain.ChainElements[1].Certificate.Subject.Should().Be("CN=test.root");
        chain.ChainElements[1].Certificate.Issuer.Should().Be("CN=test.root");
    }

    [Fact]
    public void GetChainStringReturnsIEnumerableOfString()
    {
        var certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _options);

        var chain = certificateProvider.GetChainString();

        chain.Should().BeAssignableTo<IEnumerable<string>>();
        chain.Count().Should().Be(2);
    }

    [Fact]
    public void GetChainShouldFailForWrongCertificate()
    {
        var failCertificate = new X509Certificate2("test.nonroot.pfx", "test");
        _options.Value.Certificate = Convert.ToBase64String(failCertificate.GetRawCertData());
        var certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _options);

        Action act = () => certificateProvider.GetChain();

        act.Should().Throw<Exception>();
    }

    [Fact]
    public void GetChainShouldFailForExpiredCertificate()
    {
        var failCertificate = new X509Certificate2("test.expired.pfx", "test");
        _options.Value.Certificate = Convert.ToBase64String(failCertificate.GetRawCertData());
        var certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _options);

        Action act = () => certificateProvider.GetChain();

        act.Should().Throw<Exception>();
    }

    [Fact]
    public void ConstructorShouldFailForWrongCertificate()
    {
        _options.Value.Certificate = _options.Value.Certificate!.Substring(8);

        FluentActions.Invoking(() => new CertificateProvider(NullLogger<CertificateProvider>.Instance, _options))
            .Should().Throw<CryptographicException>();
    }

    [Fact]
    public void GetSha256ThumbprintShouldReturnValidHash()
    {
        var certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _options);

        var certificate = certificateProvider.GetSigningCertificate();

        var thumbprint = CertificateProvider.GetSha256Thumbprint(certificate);

        thumbprint.Should().Be("8E41DECA02021E83C8C49DEB99C6431A4A2E379B807EEE4491A805931B87342F");
    }
}
