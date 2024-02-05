using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Poort8.Ishare.Core.Models;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Poort8.Ishare.Core;

public class AuthorizationRegistryService(
    ILogger<AuthorizationRegistryService> logger,
    IOptions<IshareCoreOptions> options,
    IHttpClientFactory httpClientFactory,
    IAccessTokenService accessTokenService,
    IAuthenticationService authenticationService) : IAuthorizationRegistryService
{
    private readonly HttpClient httpClient = httpClientFactory.CreateClient(nameof(AuthorizationRegistryService));

    public async Task<DelegationEvidence> GetDelegationEvidence(DelegationMask delegationMask)
    {
        try
        {
            await SetAuthorizationHeader(accessTokenService);

            var delegationUrl = GetUrl("delegation");
            var response = await httpClient.PostAsJsonAsync(delegationUrl, delegationMask);
            response.EnsureSuccessStatusCode();
            var delegationResponse = await response.Content.ReadFromJsonAsync<DelegationResponse>();

            await authenticationService.ValidateToken(delegationResponse!.DelegationToken, options.Value.AuthorizationRegistryId!);

            var delegationEvidence = DecodeDelegationToken(delegationResponse!);

            logger.LogInformation("Received delegationEvidence from the authorization registry: {delegationEvidence}", JsonSerializer.Serialize(delegationEvidence));
            return delegationEvidence;
        }
        catch (Exception e)
        {
            logger.LogError("Failed to get valid delegation evidence from the authorization registry: {msg}", e.Message);
            throw;
        }
    }

    public bool VerifyDelegationEvidencePermit(
        DelegationEvidence delegationEvidence,
        string? validPolicyIssuer,
        string? validAccessSubject,
        string? validServiceProvider,
        string? validResourceType,
        string? validResourceIdentifier,
        string? validAction)
    {
        logger.LogInformation("Verifying delegation evidence {delegationEvidence}", JsonSerializer.Serialize(delegationEvidence));

        var policy = delegationEvidence.PolicySets[0].Policies[0];

        if (validPolicyIssuer is not null &&
            !string.Equals(delegationEvidence.PolicyIssuer, validPolicyIssuer, StringComparison.InvariantCultureIgnoreCase))
        {
            logger.LogWarning("Invalid policy issuer in delegation evidence, should be {validPolicyIssuer}", validPolicyIssuer);
            return false;
        }

        if (validAccessSubject is not null &&
            !string.Equals(delegationEvidence.Target.AccessSubject, validAccessSubject, StringComparison.InvariantCultureIgnoreCase))
        {
            logger.LogWarning("Invalid access subject in delegation evidence, should be {validAccessSubject}", validAccessSubject);
            return false;
        }

        if (validServiceProvider is not null &&
            !string.Equals(policy.Target.Environment.ServiceProviders[0], validServiceProvider, StringComparison.InvariantCultureIgnoreCase))
        {
            logger.LogWarning("Invalid service provider in delegation evidence, should be {validServiceProvider}", validServiceProvider);
            return false;
        }

        if (validResourceType is not null &&
            !string.Equals(policy.Target.Resource.Type, validResourceType, StringComparison.InvariantCultureIgnoreCase))
        {
            logger.LogWarning("Invalid resource type in delegation evidence, should be {validResourceType}", validResourceType);
            return false;
        }

        if (validResourceIdentifier is not null &&
            !string.Equals(policy.Target.Resource.Identifiers[0], validResourceIdentifier, StringComparison.InvariantCultureIgnoreCase))
        {
            logger.LogWarning("Invalid resource identifier in delegation evidence, should be {validResourceIdentifier}", validResourceIdentifier);
            return false;
        }

        if (validAction is not null &&
            !string.Equals(policy.Target.Actions[0], validAction, StringComparison.InvariantCultureIgnoreCase))
        {
            logger.LogWarning("Invalid action in delegation evidence, should be {validAction}", validAction);
            return false;
        }

        var permit = policy.Rules[0].Effect.Equals("Permit", StringComparison.InvariantCultureIgnoreCase);

        return permit;
    }

    private async Task SetAuthorizationHeader(IAccessTokenService accessTokenService)
    {
        var tokenUrl = GetUrl("connect/token");
        var token = await accessTokenService.GetAccessTokenAtParty(options.Value.AuthorizationRegistryId!, tokenUrl);
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    private string GetUrl(string relativeUrl)
    {
        var baseUrl = new Uri(options.Value.AuthorizationRegistryUrl!);
        return new Uri(baseUrl, relativeUrl).AbsoluteUri;
    }

    private static DelegationEvidence DecodeDelegationToken(DelegationResponse token)
    {
        var handler = new JsonWebTokenHandler();

        var delegationToken = handler.CanReadToken(token.DelegationToken) ? handler.ReadJsonWebToken(token.DelegationToken) : throw new Exception("CanReadToken fails.");

        return delegationToken.Claims
            .Where(c => c.Type == "delegationEvidence")
            .Select(c => JsonSerializer.Deserialize<DelegationEvidence>(c.Value))
            .First()!;
    }

    public record DelegationResponse(
        [property: JsonPropertyName("delegation_token")] string DelegationToken
    );
}
