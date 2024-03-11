using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace Poort8.Ishare.Core.Tests;
public class ClientAssertionCreatorTests
{
    private readonly IOptions<IshareCoreOptions> _options;
    private readonly CertificateProvider _certificateProvider;
    private readonly ClientAssertionCreator _clientAssertionCreator;

    public ClientAssertionCreatorTests()
    {
        _options = Fixtures.GetCertificateTestOptions();
        _options.Value.ClientId = "serviceProvider";

        _certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _options);

        _clientAssertionCreator = new ClientAssertionCreator(_options, _certificateProvider);
    }

    [Fact]
    public async Task CreateClientAssertionUsingJsonWebTokenHandlerShouldReturnValidToken()
    {
        var token = _clientAssertionCreator.CreateClientAssertionUsingJsonWebTokenHandler("aud");

        token.Should().NotBeNullOrEmpty();
        await DoBasicTokenChecks(token);
    }

    [Fact]
    public async Task CreateClientAssertionShouldReturnValidToken()
    {
        var token = _clientAssertionCreator.CreateClientAssertion("aud");

        token.Should().NotBeNullOrEmpty();
        await DoBasicTokenChecks(token);
    }

    [Fact]
    public async Task CreateTokenShouldReturnValidToken()
    {
        var claims = new List<Claim>{ new("delegation_token", "ey...") };
        var token = _clientAssertionCreator.CreateToken("aud", claims);

        token.Should().NotBeNullOrEmpty();
        await DoBasicTokenChecks(token);

        var handler = new JsonWebTokenHandler();
        var decodedToken = handler.ReadJsonWebToken(token);
        decodedToken.Claims.Select(c => c.Type.Equals("delegation_token")).Should().NotBeEmpty();
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
