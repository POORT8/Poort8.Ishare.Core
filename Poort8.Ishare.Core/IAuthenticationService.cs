namespace Poort8.Ishare.Core;

public interface IAuthenticationService
{
    string CreateAccessToken(string audience, int expSeconds);
    string CreateClientAssertion(string audience, int expSeconds = 30);
    void ValidateClientAssertion(string validIssuer, string clientAssertion);
    void ValidateToken(string validIssuer, string clientAssertion);
}