namespace Poort8.Ishare.Core;

public interface IAuthenticationService
{
    string CreateClientAssertion(string audience);
    Task ValidateClientAssertion(string token, string clientIdHeader);
    Task ValidateToken(string token, string validIssuer);
}
