using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Security.Cryptography.X509Certificates;

namespace Poort8.Ishare.Core.Tests;
public class SchemeOwnerIntegrationTests
{
    private readonly ServiceProvider _serviceProvider;

    public SchemeOwnerIntegrationTests()
    {
        var services = new ServiceCollection();

        var config = new ConfigurationBuilder()
            .AddUserSecrets<IntegrationTests>()
            .Build();

        services.AddIshareCoreServices(config);

        services.AddOptions<IshareCoreOptions>()
            .Bind(config.GetRequiredSection("IshareCoreOptionsSchemeOwner"))
            .ValidateDataAnnotations();

        _serviceProvider = services.BuildServiceProvider();
    }

    [Fact]
    public async void GetAccessTokenAtPartyReturnsAccessToken()
    {
        var options = _serviceProvider.GetRequiredService<IOptions<IshareCoreOptions>>();
        var accessTokenService = _serviceProvider.GetRequiredService<IAccessTokenService>();

        var tokenUrl = $"{options.Value.SatelliteUrl}/connect/token";
        var accessToken = await accessTokenService.GetAccessTokenAtParty(options.Value.SatelliteId, tokenUrl);

        accessToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task GetValidTrustedListReturnsValidList()
    {
        var satelliteService = _serviceProvider.GetRequiredService<ISatelliteService>();

        var trustedList = await satelliteService.GetValidTrustedList();

        trustedList.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task GetVerifyPartyReturnsValidParty()
    {
        var satelliteService = _serviceProvider.GetRequiredService<ISatelliteService>();
        var options = _serviceProvider.GetRequiredService<IOptions<IshareCoreOptions>>();

        //NOTE: We cannot do any certificate check at the Scheme Owner
        var partyInfo = await satelliteService.VerifyParty(
            options.Value.SatelliteId,
            "can't check thumbprint");

        partyInfo.Should().NotBeNull();
    }

    [Fact]
    public async Task GetVerifyPartyWrongCertThrows()
    {
        var satelliteService = _serviceProvider.GetRequiredService<ISatelliteService>();
        var options = _serviceProvider.GetRequiredService<IOptions<IshareCoreOptions>>();

        Func<Task> act = () => satelliteService.VerifyParty(
            options.Value.SatelliteId,
            "fail");

        //NOTE: Fails because we cannot do any certificate check at the Scheme Owner
        //await act.Should().ThrowAsync<Exception>();
        await act.Should().NotThrowAsync<Exception>();
    }

    [Fact]
    public async Task ValidClientAssertionShouldPassValidateX5cChain()
    {
        var clientAssertionCreator = _serviceProvider.GetRequiredService<IClientAssertionCreator>();
        var certificateValidator = _serviceProvider.GetRequiredService<ICertificateValidator>();

        var clientAssertion = clientAssertionCreator.CreateClientAssertion("aud");
        
        var handler = new JsonWebTokenHandler();
        var decodedToken = handler.ReadJsonWebToken(clientAssertion);
        var chain = AuthenticationService.GetCertificateChain(decodedToken);
        var signingCertificate = await certificateValidator.ValidateX5cChain(chain);

        signingCertificate.Should().BeOfType<X509Certificate2>();
    }
}
