namespace Poort8.Ishare.Core;

public interface IAccessTokenService
{
    Task<string> GetAccessTokenAtParty(string partyId, string tokenUrl);
}
