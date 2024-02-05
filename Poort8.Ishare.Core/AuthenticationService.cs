using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

namespace Poort8.Ishare.Core;

public class AuthenticationService(
    ILogger<AuthenticationService> logger,
    IOptions<IshareCoreOptions> options,
    IHttpClientFactory httpClientFactory,
    ICertificateProvider certificateProvider,
    ICertificateValidator certificateValidator,
    ISatelliteService satelliteService) : IAuthenticationService
{
    private readonly HttpClient httpClient = httpClientFactory.CreateClient(nameof(AuthenticationService));
    private readonly string clientId = options.Value.ClientId;
    private readonly ITokenReplayCache tokenReplayCache = new TokenReplayCache();

    //TODO: Use this implementation for CreateClientAssertion when x5t and kid headers can be removed.
    //System.IdentityModel.Tokens.Jwt can be removed when Microsoft.IdentityModel.JsonWebTokens is used.
    public string CreateClientAssertionUsingJsonWebTokenHandler(string audience)
    {
        var claims = new ClaimsIdentity();
        claims.AddClaim(new Claim("sub", clientId));
        claims.AddClaim(new Claim("jti", Guid.NewGuid().ToString()));

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = audience,
            Subject = claims,
            Expires = DateTime.UtcNow.AddSeconds(30),
            IssuedAt = DateTime.UtcNow,
            SigningCredentials = certificateProvider.GetSigningCredentials(),
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                { "x5c", certificateProvider.GetChainString().ToList() }
            }
        };

        //NOTE: The x5t and kid headers are set by JwtTokenUtilities.DefaultHeaderParameters and cannot be removed.

        var tokenHandler = new JsonWebTokenHandler();
        return tokenHandler.CreateToken(tokenDescriptor);
    }

    //System.IdentityModel.Tokens.Jwt implementation.
    public string CreateClientAssertion(string audience)
    {
        var claims = new ClaimsIdentity();
        claims.AddClaim(new Claim("sub", clientId));
        claims.AddClaim(new Claim("jti", Guid.NewGuid().ToString()));

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateJwtSecurityToken(
            issuer: clientId,
            audience: audience,
            subject: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddSeconds(30),
            issuedAt: DateTime.UtcNow,
            signingCredentials: certificateProvider.GetSigningCredentials());

        token.Header.Remove("kid");
        token.Header.Remove("x5t");
        token.Header.Add("x5c", certificateProvider.GetChainString().ToList());

        return tokenHandler.WriteToken(token);
    }

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
