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

    public bool VerifyDelegationTokenPermit(string authorizationRegistryId, string delegationToken)
    {
        _authenticationService.ValidateToken(authorizationRegistryId, delegationToken, 30, true, false);
        return VerifyPermit(delegationToken);
    }

    private bool VerifyPermit(string delegationToken)
    {
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(delegationToken);
        var delegationEvidenceInClaims = jwtToken.Payload.TryGetValue("delegationEvidence", out object? delegationEvidenceClaim);

        if (!delegationEvidenceInClaims || delegationEvidenceClaim is null)
        {
            _logger.LogError("No delegationEvidence found in delegationToken: {delegationToken}", delegationToken);
            return false;
        }

#pragma warning disable CS8604 // Possible null reference argument.
        var delegationEvidence = JsonSerializer.Deserialize<DelegationEvidence>(delegationEvidenceClaim.ToString());
#pragma warning restore CS8604 // Possible null reference argument.

        var rootEffect = delegationEvidence?.PolicySets?[0].Policies?[0].Rules?[0].Effect;

        //NOTE: We are only checking for a Permit for now, the token validation will handle expiration
        //TODO: Add additional checks
        return string.Equals(rootEffect, "Permit", StringComparison.InvariantCultureIgnoreCase);
    }
}
