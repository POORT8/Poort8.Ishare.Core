using System.Security.Claims;

namespace Poort8.Ishare.Core;

public interface IClientAssertionCreator
{
    string CreateClientAssertion(string audience);
    string CreateClientAssertionUsingJsonWebTokenHandler(string audience);
    string CreateToken(string audience, IReadOnlyList<Claim>? additionalClaims);
}