using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Poort8.Ishare.Core.Tests;
public class IntegrationTests
{
    private readonly IOptions<IshareCoreOptions> _options;
    private readonly AccessTokenService _accessTokenService;
    private readonly SatelliteService _satelliteService;

    public IntegrationTests()
    {
        var config = new ConfigurationBuilder()
            .AddUserSecrets<IntegrationTests>()
            .Build();

        var services = new ServiceCollection();
        services.AddOptions<IshareCoreOptions>()
            .Bind(config.GetRequiredSection("IshareCoreOptions"))
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
            "CN=DVU PIR Test 1,SERIALNUMBER=EU.EORI.NLDVUPIRTEST1,OU=Test,O=DVU,C=NL",
            "145dd7c41a2f9b989f16f1250c5a9291094c300590db01903efe1fb1de651b48");

        partyInfo.Should().NotBeNull();
    }

    [Fact]
    public async Task GetVerifyPartyWrongCertThrows()
    {
        Func<Task> act = () => _satelliteService.VerifyParty(
            _options.Value.SatelliteId,
            "CN=DVU PIR Test 1,SERIALNUMBER=EU.EORI.NLDVUPIRTEST1,OU=Test,O=DVU,C=NL",
            "fail");

        await act.Should().ThrowAsync<Exception>();
    }

    //TODO: GetDelegationEvidence and VerifyDelegationEvidencePermit
}
