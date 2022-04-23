using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Poort8.Ishare.Core.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
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
    private readonly IAuthenticationService _authenticationService;

    public SchemeOwnerService(
        ILogger<SchemeOwnerService> logger,
        IConfiguration configuration,
        IMemoryCache memoryCache,
        IHttpClientFactory httpClientFactory,
        IAuthenticationService authenticationService)
    {
        _logger = logger;
        _configuration = configuration;
        _memoryCache = memoryCache;

        _httpClient = httpClientFactory.CreateClient(nameof(SchemeOwnerService));
        _httpClient.BaseAddress = new Uri(configuration["SchemeOwnerUrl"]);

        _authenticationService = authenticationService;
    }

    private async Task<List<TrustedCertificateAuthority>> GetTrustedListAsync()
    {
        if (!_memoryCache.TryGetValue("TrustedList", out List<TrustedCertificateAuthority> trustedList))
        {
            trustedList = await GetTrustedListAtSchemeOwnerAsync(); ;

            var cacheOptions = new MemoryCacheEntryOptions()
                .SetAbsoluteExpiration(TimeSpan.FromDays(1));

            _memoryCache.Set("TrustedList", trustedList, cacheOptions);
        }

        return trustedList;
    }

    private async Task<List<TrustedCertificateAuthority>> GetTrustedListAtSchemeOwnerAsync()
    {
        try
        {
            var token = await _authenticationService.GetAccessTokenAtPartyAsync(_configuration["SchemeOwnerIdentifier"], _configuration["SchemeOwnerTokenUrl"]);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var response = await _httpClient.GetFromJsonAsync<TrustedListResponse>("/trusted_list");

            if (response is null || response.TrustedListToken is null) { throw new Exception("TrustedList response is null."); }

            _authenticationService.ValidateToken(_configuration["SchemeOwnerIdentifier"], response.TrustedListToken, 30, true);

            var handler = new JwtSecurityTokenHandler();
            var trustedListToken = handler.ReadJwtToken(response.TrustedListToken);
            var trustedListClaims = trustedListToken.Claims.Where(c => c.Type == "trusted_list").ToArray();

            var trustedList = new List<TrustedCertificateAuthority>();
            foreach (var claim in trustedListClaims)
            {
                var trustedListClaim = JsonSerializer.Deserialize<TrustedCertificateAuthority>(claim.Value);
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
            var token = await _authenticationService.GetAccessTokenAtPartyAsync(_configuration["SchemeOwnerIdentifier"], _configuration["SchemeOwnerTokenUrl"]);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var response = await _httpClient.GetFromJsonAsync<PartiesResponse>($"/parties?eori={partyId}&certificate_subject_name={certificateSubject}");

            if (response is null || response.PartiesToken is null) { throw new Exception("Parties response is null."); }

            _authenticationService.ValidateToken(_configuration["SchemeOwnerIdentifier"], response.PartiesToken, 30, true);

            var handler = new JwtSecurityTokenHandler();
            var partiesToken = handler.ReadJwtToken(response.PartiesToken);
            var partiesTokenClaim = partiesToken.Claims.Where(c => c.Type == "parties_info").First();
            var partiesInfoClaim = JsonSerializer.Deserialize<PartiesClaim>(partiesTokenClaim.Value);

            if (partiesInfoClaim is null || partiesInfoClaim.Count > 1 || partiesInfoClaim.PartiesInfo is null) { throw new Exception("Received invalid parties info."); }

            return partiesInfoClaim.PartiesInfo.First() ?? throw new Exception("Received empty party info list.");
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

        foreach (var chainCertificate in chain.Skip(1))
        {
            var certificate = new X509Certificate2(Convert.FromBase64String(chainCertificate));

            var sha256Thumbprint = GetSha256Thumbprint(certificate);

            //NOTE: Find match on SHA1 or SHA256 certificate thumbprint
            var trustedRoot = trustedList.Where(c =>
                c.CertificateFingerprint == certificate.Thumbprint || c.CertificateFingerprint == sha256Thumbprint).FirstOrDefault();

            if (trustedRoot is null ||
                trustedRoot.Status is null ||
                !trustedRoot.Status.Equals("granted", StringComparison.OrdinalIgnoreCase) ||
                trustedRoot.Validity is null ||
                !trustedRoot.Validity.Equals("valid", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogError("Root certificate not in trusted list, or validity/status is invalid. Root certificate: {rootCertificate}", chain.Last());
                throw new Exception("Root certificate not trusted.");
            }
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

    private static string GetSha256Thumbprint(X509Certificate2 certificate)
    {
        var hasher = SHA256.Create();
        return Convert.ToHexString(hasher.ComputeHash(certificate.GetRawCertData()));
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

    private class PartiesResponse
    {
        [JsonPropertyName("parties_token")]
        public string? PartiesToken { get; set; }
    }

    private class PartiesClaim
    {
        [JsonPropertyName("count")]
        public int Count { get; set; }

        [JsonPropertyName("data")]
        public List<PartyInfo>? PartiesInfo { get; set; }
    }
}
