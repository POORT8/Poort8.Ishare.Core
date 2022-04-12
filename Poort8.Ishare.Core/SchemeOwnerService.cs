using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Poort8.Ishare.Core.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Poort8.Ishare.Core;

public class SchemeOwnerService : ISchemeOwnerService
{
    private readonly ILogger<SchemeOwnerService> _logger;
    private readonly IConfiguration _configuration;
    private readonly IMemoryCache _memoryCache;
    private readonly HttpClient _httpClient;
    private readonly AuthenticationService _authenticationService;

    public SchemeOwnerService(
        ILogger<SchemeOwnerService> logger,
        IConfiguration configuration,
        IMemoryCache memoryCache,
        IHttpClientFactory httpClientFactory,
        AuthenticationService authenticationService)
    {
        _logger = logger;
        _configuration = configuration;
        _memoryCache = memoryCache;

        _httpClient = httpClientFactory.CreateClient(nameof(SchemeOwnerService));
        _httpClient.BaseAddress = new Uri(configuration["SchemeOwnerUrl"]);

        _authenticationService = authenticationService;
    }

    private async Task<string> GetAccessTokenAsync()
    {
        if (!_memoryCache.TryGetValue("AccessToken", out TokenResponse accessToken))
        {
            accessToken = await GetAccessTokenAtSchemeOwnerAsync();

            if (accessToken is null) { throw new Exception("Did not receiver an access token from the scheme owner."); }

            var cacheOptions = new MemoryCacheEntryOptions()
                .SetAbsoluteExpiration(TimeSpan.FromSeconds(accessToken.ExpiresIn - 60));

            _memoryCache.Set("AccessToken", accessToken, cacheOptions);
        }

        return accessToken.AccessToken ?? throw new Exception("AccessToken is null.");
    }

    private async Task<TokenResponse> GetAccessTokenAtSchemeOwnerAsync()
    {
        try
        {
            var clientAssertion = _authenticationService.CreateClientAssertion(_configuration["SchemeOwnerIdentifier"]);
            var formData = new[]
            {
                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                    new KeyValuePair<string, string>("scope", "iSHARE"),
                    new KeyValuePair<string, string>("client_id", _configuration["ClientId"]),
                    new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    new KeyValuePair<string, string>("client_assertion", clientAssertion)
                };

            var response = await _httpClient.PostAsync("/connect/token", new FormUrlEncodedContent(formData));
            response.EnsureSuccessStatusCode();
            var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();
            return tokenResponse ?? throw new Exception("TokenResponse is null.");
        }
        catch (Exception e)
        {
            _logger.LogError("Could not get access token from scheme owner: {msg}", e.Message);
            throw;
        }
    }

    private async Task<List<TrustedList>> GetTrustedListAsync()
    {
        if (!_memoryCache.TryGetValue("TrustedList", out List<TrustedList> trustedList))
        {
            trustedList = await GetTrustedListAtSchemeOwnerAsync(); ;

            var cacheOptions = new MemoryCacheEntryOptions()
                .SetAbsoluteExpiration(TimeSpan.FromDays(1));

            _memoryCache.Set("TrustedList", trustedList, cacheOptions);
        }

        return trustedList;
    }

    private async Task<List<TrustedList>> GetTrustedListAtSchemeOwnerAsync()
    {
        try
        {
            var token = await GetAccessTokenAsync();
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var response = await _httpClient.GetFromJsonAsync<TrustedListResponse>("/trusted_list");

            if (response is null || response.TrustedListToken is null) { throw new Exception("TrustedList response is null."); }

            _authenticationService.ValidateToken(_configuration["SchemeOwnerIdentifier"], response.TrustedListToken);

            var handler = new JwtSecurityTokenHandler();
            var trustedListToken = handler.ReadJwtToken(response.TrustedListToken);
            var trustedListClaims = trustedListToken.Claims.Where(c => c.Type == "trusted_list").ToArray();

            var trustedList = new List<TrustedList>();
            foreach (var claim in trustedListClaims)
            {
                var trustedListClaim = JsonSerializer.Deserialize<TrustedList>(claim.Value);
                if (trustedListClaim is not null) { trustedList.Add(trustedListClaim); }
            }
            return trustedList;
        }
        catch (Exception e)
        {
            _logger.LogError("Could not get trusted list from scheme owner: {msg}", e.Message);
            throw;
        }
    }

    private async Task<PartyInfo> GetPartyAsync(string partyId, string certificateSubject)
    {
        var cacheKey = $"Party-{partyId}-{certificateSubject}";
        if (!_memoryCache.TryGetValue(cacheKey, out PartyInfo party))
        {
            party = await GetPartyAtSchemeOwnerAsync(partyId, certificateSubject);

            var cacheOptions = new MemoryCacheEntryOptions()
                .SetAbsoluteExpiration(TimeSpan.FromHours(1));

            _memoryCache.Set(cacheKey, party, cacheOptions);
        }

        return party;
    }

    private async Task<PartyInfo> GetPartyAtSchemeOwnerAsync(string partyId, string certificateSubject)
    {
        try
        {
            var token = await GetAccessTokenAsync();
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var response = await _httpClient.GetFromJsonAsync<PartyResponse>($"/parties/{partyId}?certificate_subject_name={certificateSubject}");

            if (response is null || response.PartyToken is null) { throw new Exception("Party response is null."); }

            _authenticationService.ValidateToken(_configuration["SchemeOwnerIdentifier"], response.PartyToken);

            var handler = new JwtSecurityTokenHandler();
            var partyToken = handler.ReadJwtToken(response.PartyToken);
            var partyTokenClaim = partyToken.Claims.Where(c => c.Type == "party_info").First();
            var partyInfo = JsonSerializer.Deserialize<PartyInfo>(partyTokenClaim.Value);
            return partyInfo ?? throw new Exception("Received empty party info list.");
        }
        catch (Exception e)
        {
            _logger.LogError("Could not get party info from scheme owner: {msg}", e.Message);
            throw;
        }
    }

    public async Task VerifyCertificateIsTrustedAsync(string clientAssertion)
    {
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(clientAssertion);
        var chain = JsonSerializer.Deserialize<string[]>(token.Header.X5c);
        if (chain is null) { throw new Exception("Empty x5c header."); }

        var trustedList = await GetTrustedListAsync();

        var certificate = new X509Certificate2(Convert.FromBase64String(chain.Last()));

        var trustedRoot = trustedList.Where(c => c.CertificateFingerprint == certificate.Thumbprint).FirstOrDefault();

        if (trustedRoot is null ||
            trustedRoot.Status is null ||
            !trustedRoot.Status.Equals("granted", StringComparison.OrdinalIgnoreCase) ||
            trustedRoot.Validity is null ||
            !trustedRoot.Validity.Equals("valid", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogError("Root certificate not in trusted list, or validity/status is invalid. Root certificate: {rootCertificate}", chain.Last());
            //TODO: Certificate root (fingerprint) not in trusted list
            //throw new Exception("Root certificate not trusted.");
        }
    }

    public async Task VerifyPartyAsync(string partyId, string clientAssertion)
    {
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(clientAssertion);
        var chain = JsonSerializer.Deserialize<string[]>(token.Header.X5c);
        if (chain is null) { throw new Exception("Empty x5c header."); }
        var signingCertificate = new X509Certificate2(Convert.FromBase64String(chain.First()));

        var partyInfo = await GetPartyAsync(partyId, signingCertificate.Subject);

        if (partyInfo is null ||
            partyInfo.Adherence?.Status is null ||
            !partyInfo.Adherence.Status.Equals("active", StringComparison.OrdinalIgnoreCase) ||
            partyInfo.Adherence.StartDate > DateTime.Now ||
            partyInfo.Adherence.EndDate <= DateTime.Now)
        {
            _logger.LogError("Party info checks failed for party {partyId} and certificate subject {certificateSubject}", partyId, signingCertificate.Subject);
            throw new Exception("Party info checks failed.");
        }
    }

    private class TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string? AccessToken { get; set; }

        [JsonPropertyName("token_type")]
        public string? TokenType { get; set; }

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }
    }

    private class TrustedListResponse
    {
        [JsonPropertyName("trusted_list_token")]
        public string? TrustedListToken { get; set; }
    }

    private class PartyResponse
    {
        [JsonPropertyName("party_token")]
        public string? PartyToken { get; set; }
    }
}
