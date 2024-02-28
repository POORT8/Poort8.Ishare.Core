using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using System.Security.Cryptography.X509Certificates;

namespace Poort8.Ishare.Core.Tests;
public class CertificateValidatorTests
{
    private readonly CertificateValidator _certificateValidator;

    public CertificateValidatorTests()
    {
        var fakeSatelliteService = new FakeSatelliteService();

        _certificateValidator = new CertificateValidator(NullLogger<CertificateValidator>.Instance, fakeSatelliteService);
    }

    [Fact]
    public void ValidateChainShouldPass()
    {
        var testPassword = "test";
        var testCertificate = new X509Certificate2("test.serviceprovider.pfx", testPassword, X509KeyStorageFlags.Exportable);
        var testRootCertificate = new X509Certificate2("test.root.pfx", testPassword);
        var chainCertificates = new X509Certificate2Collection
        {
            testRootCertificate
        };

        Action act = () => _certificateValidator.ValidateChain(chainCertificates, testCertificate);

        act.Should().NotThrow();
    }

    [Fact]
    public void InValidateChainShouldFail()
    {
        var testPassword = "test";
        var testCertificate = new X509Certificate2("test.nonroot.pfx", testPassword, X509KeyStorageFlags.Exportable);
        var testRootCertificate = new X509Certificate2("test.root.pfx", testPassword);
        var chainCertificates = new X509Certificate2Collection
        {
            testRootCertificate
        };

        Action act = () => _certificateValidator.ValidateChain(chainCertificates, testCertificate);

        act.Should().Throw<Exception>();
    }

    [Fact]
    public void ExpiredValidateChainShouldFail()
    {
        var testPassword = "test";
        var testCertificate = new X509Certificate2("test.expired.pfx", testPassword, X509KeyStorageFlags.Exportable);
        var testRootCertificate = new X509Certificate2("test.root.pfx", testPassword);
        var chainCertificates = new X509Certificate2Collection
        {
            testRootCertificate
        };

        Action act = () => _certificateValidator.ValidateChain(chainCertificates, testCertificate);

        act.Should().Throw<Exception>();
    }

    [Fact]
    public void InvalidKeyUsageValidateChainShouldFail()
    {
        var testPassword = "test";
        var testCertificate = new X509Certificate2("test.invalidkeyusage.pfx", testPassword, X509KeyStorageFlags.Exportable);
        var testRootCertificate = new X509Certificate2("test.root.pfx", testPassword);
        var chainCertificates = new X509Certificate2Collection
        {
            testRootCertificate
        };

        Action act = () => _certificateValidator.ValidateChain(chainCertificates, testCertificate);

        act.Should().Throw<Exception>();
    }
}
