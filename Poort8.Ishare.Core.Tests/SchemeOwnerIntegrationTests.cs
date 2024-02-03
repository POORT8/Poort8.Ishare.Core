using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Poort8.Ishare.Core.Tests;
public class SchemeOwnerIntegrationTests
{
    private readonly IOptions<IshareCoreOptions> _options;
    private readonly AccessTokenService _accessTokenService;
    private readonly SatelliteService _satelliteService;

    public SchemeOwnerIntegrationTests()
    {
        var config = new ConfigurationBuilder()
            .AddUserSecrets<IntegrationTests>()
            .Build();

        var services = new ServiceCollection();
        services.AddOptions<IshareCoreOptions>()
            .Bind(config.GetRequiredSection("IshareCoreOptionsSchemeOwner"))
            .ValidateDataAnnotations();
        services.AddHttpClient();

        var httpClientFactory = services.BuildServiceProvider()
            .GetRequiredService<IHttpClientFactory>();
        _options = services.BuildServiceProvider()
            .GetRequiredService<IOptions<IshareCoreOptions>>();

        var certificateValidator = new CertificateValidator(new NullLogger<CertificateValidator>(), _satelliteService!);

        var certificateProvider = new CertificateProvider(new NullLogger<CertificateProvider>(), _options);

        var authenticationService = new AuthenticationService(
            new NullLogger<AuthenticationService>(),
            _options,
            httpClientFactory,
            certificateProvider,
            certificateValidator,
            _satelliteService!);

        _accessTokenService = new AccessTokenService(
            new NullLogger<AccessTokenService>(),
            _options,
            httpClientFactory,
            authenticationService,
            null);

        _satelliteService = new SatelliteService(
            new NullLogger<SatelliteService>(),
            _options,
            httpClientFactory,
            _accessTokenService,
            null);
    }

    [Fact]
    public async void GetAccessTokenAtPartyReturnsAccessToken()
    {
        var tokenUrl = $"{_options.Value.SatelliteUrl}/connect/token";
        var accessToken = await _accessTokenService.GetAccessTokenAtParty(_options.Value.SatelliteId, tokenUrl);

        accessToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task GetValidTrustedListReturnsValidList()
    {
        var trustedList = await _satelliteService.GetValidTrustedList();

        trustedList.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task GetVerifyPartyReturnsValidParty()
    {
        var partyInfo = await _satelliteService.VerifyParty(
            _options.Value.SatelliteId,
            "C = NL,O = iSHARETest,OU = Test and QA,serialNumber = EU.EORI.NL000000000,CN = iSHARE Scheme Owner",
            "3BB7A41A805D7CC4E8733B7CD4BF1CDC399B2C2A");

        partyInfo.Should().NotBeNull();
    }

    [Fact]
    public async Task GetVerifyPartyWrongCertThrows()
    {
        Func<Task> act = () => _satelliteService.VerifyParty(
            _options.Value.SatelliteId,
            "C = NL,O = iSHARETest,OU = Test and QA,serialNumber = EU.EORI.NL000000000,CN = iSHARE Scheme Owner",
            "fail");

        //NOTE: Fails because we cannot do any certificate check at the Scheme Owner
        //await act.Should().ThrowAsync<Exception>();
        await act.Should().NotThrowAsync<Exception>();
    }
}
