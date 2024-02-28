namespace Poort8.Ishare.Core;

public interface IClientAssertionCreator
{
    string CreateClientAssertion(string audience);
    string CreateClientAssertionUsingJsonWebTokenHandler(string audience);
}