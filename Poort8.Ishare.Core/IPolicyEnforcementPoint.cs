namespace Poort8.Ishare.Core;

public interface IPolicyEnforcementPoint
{
    bool VerifyDelegationTokenPermit(string authorizationRegistryId, string delegationToken);
}