using Poort8.Ishare.Core.Models;

namespace Poort8.Ishare.Core;

public interface ISatelliteService
{
    Task<IEnumerable<TrustedListAuthority>> GetValidTrustedList();
    Task<PartyInfo> VerifyParty(string partyId, string certificateSubject, string certificateThumbprint);
}
