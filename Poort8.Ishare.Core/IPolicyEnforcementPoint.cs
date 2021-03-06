namespace Poort8.Ishare.Core;

public interface IPolicyEnforcementPoint
{
    bool VerifyDelegationTokenPermit(string authorizationRegistryId, string delegationToken, string playbook, string minimalPlaybookVersion, string? accessTokenAud = null, string? resourceType = null, string? resourceIdentifier = null);
}