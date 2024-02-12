using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;

namespace Poort8.Ishare.Core;

public class AuthenticationService(
    ILogger<AuthenticationService> logger,
    IOptions<IshareCoreOptions> options,
    IHttpClientFactory httpClientFactory,
    ICertificateValidator certificateValidator,
    ISatelliteService satelliteService) : IAuthenticationService
{
    private readonly HttpClient httpClient = httpClientFactory.CreateClient(nameof(AuthenticationService));
    private readonly string clientId = options.Value.ClientId;
    private readonly ITokenReplayCache tokenReplayCache = new TokenReplayCache();

    public async Task ValidateClientAssertion(string token, string clientIdHeader)
    {
        await ValidateToken(token, clientIdHeader);
    }

    public async Task ValidateToken(string token, string validIssuer)
    {
        try
        {
            var handler = new JsonWebTokenHandler();

            //NOTE: The token must be read before it can be validated because the signing certificate is needed.
            var decodedToken = handler.CanReadToken(token) ? handler.ReadJsonWebToken(token) : throw new Exception("CanReadToken fails.");
            var chain = GetCertificateChain(decodedToken);

            var signingCertificate = await certificateValidator.ValidateX5cChain(chain);

            if (validIssuer != clientId)
                await satelliteService.VerifyParty(validIssuer, CertificateProvider.GetSha256Thumbprint(signingCertificate));

            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAlgorithms = new List<string>() { "RS256" },
                ValidTypes = new List<string>() { "JWT" },
                ValidateIssuer = true,
                ValidIssuer = validIssuer,
                ValidateAudience = true,
                ValidAudience = clientId,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new X509SecurityKey(signingCertificate),
                RequireExpirationTime = true,
                PropertyBag = new Dictionary<string, object> { { "expSeconds", 30 } },
                LifetimeValidator = ClientAssertionLifetimeValidator,
                ClockSkew = TimeSpan.FromSeconds(10),
                RequireSignedTokens = true,
                ValidateTokenReplay = true,
                TokenReplayCache = tokenReplayCache
            };

            var validationResult = await handler.ValidateTokenAsync(token, tokenValidationParameters);

            if (validationResult.Claims["sub"].ToString() != validationResult.Claims["iss"].ToString())
            {
                logger.LogError("Token validation error, for valid issuer {validIssuer}, and token {token}. With message: {msg}", validIssuer, token, "The 'iss' claim is not equal to the 'sub' claim.");
                throw new Exception("The 'iss' claim is not equal to the 'sub' claim.");
            }

            //TODO: Except from the alg, typ and x5c parameter, the JWT header SHALL NOT contain other header parameters. Check with iSHARE foundation.
        }
        catch (Exception e)
        {
            logger.LogError("Token validation error, for valid issuer {validIssuer} and token {token}. With message: {msg}", validIssuer, token, e.Message);
            throw;
        }
    }

    public static string[] GetCertificateChain(JsonWebToken token)
    {
        var hasX5c = token.TryGetHeaderValue("x5c", out object? x5c);
        if (hasX5c == false) throw new Exception("No x5c header.");

        var x5cJsonElement = (JsonElement)x5c!;
        return x5cJsonElement.EnumerateArray().Select(c => c.ToString()).ToArray();
    }

    public static bool ClientAssertionLifetimeValidator(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
    {
        validationParameters.PropertyBag.TryGetValue("expSeconds", out object? expSeconds);
        return ((DateTime)expires! - (DateTime)notBefore!).TotalSeconds == (int)expSeconds!;
    }
}
