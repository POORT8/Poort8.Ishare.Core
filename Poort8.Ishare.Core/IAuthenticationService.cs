namespace Poort8.Ishare.Core;

public interface IAuthenticationService
{
    Task ValidateClientAssertion(string token, string clientIdHeader);
    Task ValidateToken(string token, string validIssuer);
}
