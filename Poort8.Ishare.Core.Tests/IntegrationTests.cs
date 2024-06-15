using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Security.Cryptography.X509Certificates;

namespace Poort8.Ishare.Core.Tests;
public class IntegrationTests
{
    private readonly ServiceProvider _serviceProvider;

    public IntegrationTests()
    {
        var services = new ServiceCollection();

        var config = new ConfigurationBuilder()
            .AddUserSecrets<IntegrationTests>()
            .Build();

        services.AddIshareCoreServices(config);

        _serviceProvider = services.BuildServiceProvider();
    }

    [Fact]
    public async Task GetAccessTokenAtPartyReturnsAccessToken()
    {
        var accessToken = await GetAccessToken();
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

        var partyInfo = await satelliteService.VerifyParty(
            options.Value.SatelliteId,
            "145dd7c41a2f9b989f16f1250c5a9291094c300590db01903efe1fb1de651b48");

        partyInfo.Should().NotBeNull();
    }

    [Fact]
    public async Task GetVerifyPartyWithClientAssertionReturnsValidParty()
    {
        var satelliteService = _serviceProvider.GetRequiredService<ISatelliteService>();
        var options = _serviceProvider.GetRequiredService<IOptions<IshareCoreOptions>>();

        var token = await GetAccessToken();

        var partyInfo = await satelliteService.VerifyPartyWithClientAssertion(
            options.Value.SatelliteId,
            token);

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

        await act.Should().ThrowAsync<Exception>();
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

    private async Task<string> GetAccessToken()
    {
        var options = _serviceProvider.GetRequiredService<IOptions<IshareCoreOptions>>();
        var accessTokenService = _serviceProvider.GetRequiredService<IAccessTokenService>();

        var tokenUrl = $"{options.Value.SatelliteUrl}/connect/token";
        return await accessTokenService.GetAccessTokenAtParty(options.Value.SatelliteId, tokenUrl);
    }

    //TODO: GetDelegationEvidence and VerifyDelegationEvidencePermit
}
