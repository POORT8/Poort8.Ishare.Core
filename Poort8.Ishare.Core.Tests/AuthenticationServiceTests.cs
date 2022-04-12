using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;

namespace Poort8.Ishare.Core.Tests;

[TestClass]
public class AuthenticationServiceTests
{
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
    private static Mock<IConfiguration> ConfigMock;
    private static Mock<ILogger<AuthenticationService>> LoggerMock;
    private static X509Certificate2 TestCertificate;
    private static X509Certificate2 TestRootCertificate;
    private static Mock<ICertificateProvider> CertificateProviderMock;
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

    [ClassInitialize]
    public static void ClassInitialize(TestContext testContext)
    {
        ConfigMock = new Mock<IConfiguration>();
        ConfigMock
            .SetupGet(x => x[It.Is<string>(s => s == "ClientId")])
            .Returns("EU.EORI.NL888888881");

        LoggerMock = new Mock<ILogger<AuthenticationService>>();

        TestCertificate = new X509Certificate2("poort8.ishare.common.tests.pfx", "poort8.ishare.common.tests");
        TestRootCertificate = new X509Certificate2("poort8.ishare.common.tests.root.pfx", "poort8.ishare.common.tests");

        var chainArray = new List<string>()
        {
            Convert.ToBase64String(TestCertificate.GetRawCertData()),
            Convert.ToBase64String(TestRootCertificate.GetRawCertData())
        };

        CertificateProviderMock = new Mock<ICertificateProvider>();
        CertificateProviderMock.
            Setup(x => x.GetSigningCredentials()).Returns(new X509SigningCredentials(TestCertificate));
        CertificateProviderMock.
            Setup(x => x.GetChainString()).Returns(chainArray);
    }

    [TestMethod]
    public void TestCreateAndValidateAssertionSuccess()
    {
        var authenticationService = new AuthenticationService(LoggerMock.Object, ConfigMock.Object, CertificateProviderMock.Object);
        var clientAssertion = authenticationService.CreateClientAssertion("EU.EORI.NL888888881");
        authenticationService.ValidateClientAssertion("EU.EORI.NL888888881", clientAssertion);

        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(clientAssertion);

        Assert.AreEqual("RS256", token.Header.Alg);
        Assert.AreEqual("JWT", token.Header.Typ);
        Assert.IsNotNull(token.Header.X5c);
        Assert.IsNotNull(token.Payload.Iss);
        Assert.AreEqual(token.Payload.Iss, token.Payload.Sub);
        Assert.IsNotNull(token.Payload.Aud);
        Assert.IsNotNull(token.Payload.Jti);
        Assert.IsNotNull(token.Payload.Iat);
        Assert.AreEqual(token.Payload.Iat, token.Payload.Nbf);
        Assert.AreEqual(token.Payload.Exp, token.Payload.Iat + 30);
    }

    [TestMethod]
    [ExpectedException(typeof(SecurityTokenInvalidAudienceException))]
    public void TestWrongAudience()
    {
        var authenticationService = new AuthenticationService(LoggerMock.Object, ConfigMock.Object, CertificateProviderMock.Object);
        var clientAssertion = authenticationService.CreateClientAssertion("EU.EORI.FAIL");
        authenticationService.ValidateClientAssertion("EU.EORI.NL888888881", clientAssertion);
    }
}
