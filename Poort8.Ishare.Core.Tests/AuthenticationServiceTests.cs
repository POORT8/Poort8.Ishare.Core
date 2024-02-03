using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;

namespace Poort8.Ishare.Core.Tests;
public class AuthenticationServiceTests
{
    private readonly IOptions<IshareCoreOptions> _options;
    private readonly CertificateProvider _certificateProvider;
    private readonly AuthenticationService _authenticationService;

    public AuthenticationServiceTests()
    {
        _options = Fixtures.GetCertificateTestOptions();
        _options.Value.ClientId = "serviceProvider";

        var fakeSatelliteService = new FakeSatelliteService();

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        _certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _options);
        var certificateValidator = new CertificateValidator(NullLogger<CertificateValidator>.Instance, fakeSatelliteService);

        _authenticationService = new AuthenticationService(
            NullLogger<AuthenticationService>.Instance,
            _options,
            httpClientFactory,
            _certificateProvider,
            certificateValidator,
            fakeSatelliteService);
    }

    [Fact]
    public async Task CreateClientAssertionUsingJsonWebTokenHandlerShouldReturnValidToken()
    {
        var token = _authenticationService.CreateClientAssertionUsingJsonWebTokenHandler("aud");

        token.Should().NotBeNullOrEmpty();
        await DoBasicTokenChecks(token);
    }

    [Fact]
    public async Task CreateClientAssertionShouldReturnValidToken()
    {
        var token = _authenticationService.CreateClientAssertion("aud");

        token.Should().NotBeNullOrEmpty();
        await DoBasicTokenChecks(token);
    }

    [Fact]
    public async Task ValidateClientAssertionShouldPass()
    {
        var token = _authenticationService.CreateClientAssertion("serviceProvider");

        //NOTE: The audience is set to "serviceProvider" since validAudience is set to _clientId in ValidateToken.
        Func<Task> act = () => _authenticationService.ValidateClientAssertion(token, "serviceProvider");

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task ValidateClientAssertionWrongClientIdHeaderShouldFail()
    {
        var token = _authenticationService.CreateClientAssertion("serviceProvider");

        Func<Task> act = () => _authenticationService.ValidateClientAssertion(token, "fail");

        await act.Should().ThrowAsync<Exception>();
    }

    [Fact]
    public async Task ValidateClientAssertionWrongAudShouldFail()
    {
        var token = _authenticationService.CreateClientAssertion("fail");

        Func<Task> act = () => _authenticationService.ValidateClientAssertion(token, "serviceProvider");

        await act.Should().ThrowAsync<Exception>();
    }

    [Fact]
    public async Task ValidateServiceConsumerClientAssertionValidationShouldPass()
    {
        var token = Fixtures.CreateServiceConsumerClientAssertion("serviceConsumer", "serviceProvider");

        Func<Task> act = () => _authenticationService.ValidateClientAssertion(token, "serviceConsumer");

        await act.Should().NotThrowAsync();
    }

    private async Task DoBasicTokenChecks(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters()
        {
            ValidAlgorithms = new List<string>() { "RS256" },
            ValidTypes = new List<string>() { "JWT" },
            ValidateIssuer = true,
            ValidIssuer = _options.Value.ClientId,
            ValidateAudience = true,
            ValidAudience = "aud",
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _certificateProvider.GetSigningCredentials().Key,
            RequireExpirationTime = true,
            PropertyBag = new Dictionary<string, object> { { "expSeconds", 30 } },
            LifetimeValidator = AuthenticationService.ClientAssertionLifetimeValidator,
            RequireSignedTokens = true
        };

        var handler = new JsonWebTokenHandler();
        var validationResult = await handler.ValidateTokenAsync(token, tokenValidationParameters);

        validationResult.Claims.TryGetValue("sub", out object? sub).Should().BeTrue();
        sub.Should().Be(_options.Value.ClientId);

        validationResult.IsValid.Should().BeTrue();
    }
}
