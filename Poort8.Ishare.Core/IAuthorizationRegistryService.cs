using Poort8.Ishare.Core.Models;

namespace Poort8.Ishare.Core;

public interface IAuthorizationRegistryService
{
    Task<DelegationEvidence> GetDelegationEvidence(DelegationMask delegationMask);
    bool VerifyDelegationEvidencePermit(DelegationEvidence delegationEvidence, string? validPolicyIssuer, string? validAccessSubject, string? validServiceProvider, string? validResourceType, string? validResourceIdentifier, string? validAction);
}
