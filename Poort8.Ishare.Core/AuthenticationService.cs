using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Poort8.Ishare.Core;

public class AuthenticationService : IAuthenticationService
{
    private readonly ILogger<AuthenticationService> _logger;
    private readonly ICertificateProvider _certificateProvider;
    private readonly string _clientId;

    public AuthenticationService(
        ILogger<AuthenticationService> logger,
        IConfiguration configuration,
        ICertificateProvider certificateProvider)
    {
        _logger = logger;
        _certificateProvider = certificateProvider;
        _clientId = configuration["ClientId"];
    }

    public string CreateAccessToken(string audience)
    {
        return CreateClientAssertion(audience, 3600);
    }

    public string CreateClientAssertion(string audience, int expSeconds = 30)
    {
        var claims = new ClaimsIdentity();
        claims.AddClaim(new Claim("sub", _clientId));
        claims.AddClaim(new Claim("jti", Guid.NewGuid().ToString()));

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateJwtSecurityToken(
            issuer: _clientId,
            audience: audience,
            subject: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddSeconds(expSeconds),
            issuedAt: DateTime.UtcNow,
            signingCredentials: _certificateProvider.GetSigningCredentials());

        token.Header.Remove("kid");
        token.Header.Remove("x5t");
        token.Header.Add("x5c", _certificateProvider.GetChainString());

        return tokenHandler.WriteToken(token);
    }

    public void ValidateAccessToken(string validIssuer, string accessToken)
    {
        ValidateToken(validIssuer, accessToken, 3600);
    }

    public void ValidateToken(string validIssuer, string token, int expSeconds = 30, bool verifyChain = false)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);
            var chain = JsonSerializer.Deserialize<string[]>(jwtToken.Header.X5c);
            if (chain is null) { throw new Exception("Empty x5c header."); }
            var signingCertificate = new X509Certificate2(Convert.FromBase64String(chain.First()));

            if (string.IsNullOrEmpty(jwtToken.Payload.Jti)) { throw new Exception("The 'jti' claim is missing from the client assertion."); }
            if (jwtToken.Payload.Exp != jwtToken.Payload.Iat + expSeconds) { throw new Exception("The 'exp' and 'iat' claims do not equal 'exp = iat + 30 or 3600'."); }

            var customValidations = new Dictionary<string, object>() { { "sub", validIssuer } };

            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAlgorithms = new List<string>() { "RS256" },
                ValidTypes = new List<string>() { "JWT" },
                ValidateIssuer = true,
                ValidIssuer = validIssuer,
                ValidateAudience = true,
                ValidAudience = _clientId,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new X509SecurityKey(signingCertificate),
                ValidateLifetime = true,
                RequireExpirationTime = true,
                PropertyBag = customValidations,
                ClockSkew = TimeSpan.FromSeconds(30)
                //TODO: ValidateTokenReplay
            };

            if (verifyChain) { VerifyX5cChain(chain, signingCertificate); }
            
            handler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);
        }
        catch (Exception e)
        {
            _logger.LogError("Token validation error, for client id {clientId} and assertion {assertion}. With message: {msg}", validIssuer, token, e.Message);
            throw;
        }
    }

    private static void VerifyX5cChain(string[] chainString, X509Certificate2 signingCertificate)
    {
        var chainCertificates = new X509Certificate2Collection();
        foreach (var certificate in chainString.Skip(1))
        {
            chainCertificates.Add(new X509Certificate2(Convert.FromBase64String(certificate)));
        }
        var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(chainCertificates);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        var isVerified = chain.Build(signingCertificate);

        var keyUsages = signingCertificate.Extensions.OfType<X509KeyUsageExtension>();
        if (!keyUsages.Any(u => u.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature)))
        {
            throw new Exception("Signing certificate does not have a digital signature key usage.");
        };

        if (!isVerified) { throw new Exception("Certificate chain is not verified."); }
    }
}
