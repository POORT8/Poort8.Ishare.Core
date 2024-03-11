using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Poort8.Ishare.Core;
public class ClientAssertionCreator(
    IOptions<IshareCoreOptions> options,
    ICertificateProvider certificateProvider) : IClientAssertionCreator
{
    private readonly string clientId = options.Value.ClientId;

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

    public string CreateToken(string audience, IReadOnlyList<Claim>? additionalClaims)
    {
        var claims = new ClaimsIdentity();
        claims.AddClaim(new Claim("sub", clientId));
        claims.AddClaim(new Claim("jti", Guid.NewGuid().ToString()));

        foreach (var claim in additionalClaims ?? [])
        {
            claims.AddClaim(claim);
        }

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
}
