using Microsoft.Extensions.Logging;
using Poort8.Ishare.Core.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace Poort8.Ishare.Core;

public class PolicyEnforcementPoint : IPolicyEnforcementPoint
{
    private readonly ILogger<PolicyEnforcementPoint> _logger;
    private readonly IAuthenticationService _authenticationService;

    public PolicyEnforcementPoint(
        ILogger<PolicyEnforcementPoint> logger,
        IAuthenticationService authenticationService)
    {
        _logger = logger;
        _authenticationService = authenticationService;
    }

    public bool VerifyDelegationTokenPermit(
        string authorizationRegistryId,
        string delegationToken,
        string playbook,
        string minimalPlaybookVersion,
        string? accessTokenAud = null,
        string? resourceType = null,
        string? resourceIdentifier = null)
    {
        _authenticationService.ValidateToken(authorizationRegistryId, delegationToken, 30, true, false);
        return VerifyPermit(delegationToken, playbook, minimalPlaybookVersion, accessTokenAud, resourceType, resourceIdentifier);
    }

    private bool VerifyPermit(
        string delegationToken,
        string playbook,
        string minimalPlaybookVersion,
        string? accessTokenAud,
        string? resourceType,
        string? resourceIdentifier)
    {
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(delegationToken);

        var playbookInClaims = jwtToken.Payload.TryGetValue("playbook", out object? playbookClaim);
        if (!playbookInClaims || playbookClaim is null || !Equals(playbookClaim, playbook))
        {
            _logger.LogWarning("Invalid playbook claim in delegationToken {delegationToken}, should be {playbook}", delegationToken, playbook);
            return false;
        }

        var playbookVersionInClaims = jwtToken.Payload.TryGetValue("playbookVersion", out object? playbookVersionClaim);
        try
        {
            if (!playbookVersionInClaims || playbookVersionClaim is null || new Version((string)playbookVersionClaim) < new Version(minimalPlaybookVersion))
            {
                throw new Exception("Invalid playbook version claim.");
            }
        }
        catch (Exception)
        {
            _logger.LogWarning("Invalid playbook version claim in delegationToken {delegationToken}, should be greater or equal than {minimalPlaybookVersion}", delegationToken, minimalPlaybookVersion);
            return false;
        }
        
        jwtToken.Payload.TryGetValue("delegationEvidence", out object? delegationEvidenceClaim);
        var delegationEvidence = JsonSerializer.Deserialize<DelegationEvidence>(delegationEvidenceClaim?.ToString()!);

        if ((delegationEvidence!.NotBefore > DateTimeOffset.Now.ToUnixTimeSeconds()) ||
            (delegationEvidence!.NotOnOrAfter <= DateTimeOffset.Now.ToUnixTimeSeconds()))
        {
            _logger.LogWarning("NotBefore > now or NotOnOrAfter <= now in delegationToken: {delegationToken}", delegationToken);
            return false;
        }

        var policy = delegationEvidence!.PolicySets![0].Policies![0];
        if (accessTokenAud is not null &&
            !accessTokenAud.Equals(delegationEvidence!.Target!.AccessSubject!) &&
            !policy.Target!.Environment!.ServiceProviders!.Contains(accessTokenAud))
        {
            _logger.LogWarning("Access token aud {accessTokenAud} does not match the target (AccessSubject or ServiceProvider) in delegationToken {delegationToken}", accessTokenAud, delegationToken);
            return false;
        }

        if (delegationEvidence!.PolicySets![0].MaxDelegationDepth < 0)
        {
            _logger.LogWarning("Invalid max delegation depth in delegationToken {delegationToken}, sould be >= 0", delegationToken);
            return false;
        }

        if (resourceType is not null &&
            !string.Equals(policy!.Target!.Resource!.Type, resourceType))
        {
            _logger.LogWarning("Invalid resource type in delegationToken {delegationToken}, sould be {resourceType}", delegationToken, resourceType);
            return false;
        }

        if (resourceIdentifier is not null &&
            !policy!.Target!.Resource!.Identifiers!.Contains(resourceIdentifier))
        {
            if (!delegationEvidence!.PolicySets![0].Policies![0].Target!.Resource!.Identifiers!.Contains("*"))
            {
                _logger.LogWarning("Invalid resource type in delegationToken {delegationToken}, sould be {resourceType}", delegationToken, resourceType);
                return false;
            }
        }

        var rootEffect = policy!.Rules![0].Effect;

        return string.Equals(rootEffect, "Permit", StringComparison.InvariantCultureIgnoreCase);
    }
}
