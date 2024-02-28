using LazyCache;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Poort8.Ishare.Core.Models;
using System.Net.Http.Json;

namespace Poort8.Ishare.Core;

public class AccessTokenService(
    ILogger<AccessTokenService> logger,
    IOptions<IshareCoreOptions> options,
    IHttpClientFactory httpClientFactory,
    IClientAssertionCreator clientAssertionCreator,
    IAppCache memoryCache) : IAccessTokenService
{
    private readonly HttpClient httpClient = httpClientFactory.CreateClient(nameof(AccessTokenService));

    public async Task<string> GetAccessTokenAtParty(string partyId, string tokenUrl)
    {
        string cacheKey = $"AccessToken-{partyId.Replace('-', '_')}-{tokenUrl.Replace('-', '_')}";
        var accessToken = await memoryCache.GetOrAddAsync(cacheKey, async entry =>
        {
            var tokenResponse = await GetAccessToken(partyId, tokenUrl);
            entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(tokenResponse.ExpiresIn - 60);
            return tokenResponse.AccessToken!;
        });

        return accessToken;
    }

    private async Task<TokenResponse> GetAccessToken(string partyId, string tokenUrl)
    {
        try
        {
            var clientAssertion = clientAssertionCreator.CreateClientAssertion(partyId);
            var formData = new[]
            {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("scope", "iSHARE"),
                new KeyValuePair<string, string>("client_id", options.Value.ClientId),
                new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                new KeyValuePair<string, string>("client_assertion", clientAssertion)
            };

            var response = await httpClient.PostAsync(tokenUrl, new FormUrlEncodedContent(formData));
            response.EnsureSuccessStatusCode();
            var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();

            logger.LogInformation("Received access token from party {party}", partyId);
            return tokenResponse ?? throw new Exception("TokenResponse is null.");
        }
        catch (Exception e)
        {
            logger.LogError("Could not get access token from {partyId}: {msg}", partyId, e.Message);
            throw;
        }
    }
}
