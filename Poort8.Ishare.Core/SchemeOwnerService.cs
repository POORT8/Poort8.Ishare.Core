using LazyCache;
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
    private readonly IAppCache? _memoryCache;
    private readonly HttpClient _httpClient;
    private readonly IAuthenticationService _authenticationService;

    public SchemeOwnerService(
        ILogger<SchemeOwnerService> logger,
        IConfiguration configuration,
        IAppCache? memoryCache,
        IHttpClientFactory httpClientFactory,
        IAuthenticationService authenticationService)
    {
        _logger = logger;
        _configuration = configuration;
        _memoryCache = memoryCache;

        _httpClient = httpClientFactory.CreateClient(nameof(SchemeOwnerService));
        _httpClient.BaseAddress = new Uri(configuration["SchemeOwnerUrl"]!);

        _authenticationService = authenticationService;
    }

    private async Task<List<TrustedCertificateAuthority>> GetTrustedListAsync()
    {
        List<TrustedCertificateAuthority> trustedList;
        if (_memoryCache == null)
        {
            trustedList = await GetTrustedListAtSchemeOwnerAsync();
        }
        else
        {
            trustedList = await _memoryCache.GetOrAddAsync("TrustedList", async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(1);
                return await GetTrustedListAtSchemeOwnerAsync();
            });
        }

        return trustedList;
    }

    private async Task<List<TrustedCertificateAuthority>> GetTrustedListAtSchemeOwnerAsync()
    {
        try
        {
            var tokenUri = new Uri(new Uri(_configuration["SchemeOwnerUrl"]!), "/connect/token");
            var token = await _authenticationService.GetAccessTokenAtPartyAsync(_configuration["SchemeOwnerIdentifier"]!, tokenUri.AbsoluteUri);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var response = await _httpClient.GetFromJsonAsync<TrustedListResponse>("/trusted_list");

            if (response is null || response.TrustedListToken is null) { throw new Exception("TrustedList response is null."); }

            _authenticationService.ValidateToken(_configuration["SchemeOwnerIdentifier"]!, response.TrustedListToken);

            var handler = new JwtSecurityTokenHandler { MaximumTokenSizeInBytes = 1024 * 1024 * 2 };
            var trustedListToken = handler.ReadJwtToken(response.TrustedListToken);
            var trustedListClaims = trustedListToken.Claims.Where(c => c.Type == "trusted_list").ToArray();

            var trustedList = new List<TrustedCertificateAuthority>();
            foreach (var claim in trustedListClaims)
            {
                var trustedListClaim = JsonSerializer.Deserialize<TrustedCertificateAuthority>(claim.Value);
                if (trustedListClaim is not null) { trustedList.Add(trustedListClaim); }
            }

            _logger.LogInformation("Received trusted list from scheme owener.");
            return trustedList;
        }
        catch (Exception e)
        {
            _logger.LogError("Could not get trusted list from scheme owner: {msg}", e.Message);
            throw;
        }
    }

    private async Task<(PartyInfo, bool)> GetPartyAsync(string partyId, string certificateSubject) //TODO: Remove search on certificateSubject and tuple return when migrated to satellites
    {
        return _memoryCache is null ?
            await GetPartyAtSchemeOwnerAsync(partyId, certificateSubject) :
            await _memoryCache.GetOrAddAsync($"Party-{partyId}-{certificateSubject}", async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1);
                return await GetPartyAtSchemeOwnerAsync(partyId, certificateSubject);
            });
    }

    private async Task<(PartyInfo, bool)> GetPartyAtSchemeOwnerAsync(string partyId, string? certificateSubject = null)
    {
        try
        {
            bool hasCertificateSubject = !string.IsNullOrWhiteSpace(certificateSubject);
            var tokenUri = new Uri(new Uri(_configuration["SchemeOwnerUrl"]!), "/connect/token");
            var token = await _authenticationService.GetAccessTokenAtPartyAsync(_configuration["SchemeOwnerIdentifier"]!, tokenUri.AbsoluteUri);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var url = $"/parties?eori={partyId}";
            if (hasCertificateSubject) url += $"&certificate_subject_name={certificateSubject}";
            var response = await _httpClient.GetFromJsonAsync<PartiesResponse>(url);

            if (response?.PartiesToken is null) throw new Exception("Parties response is null.");

            _authenticationService.ValidateToken(_configuration["SchemeOwnerIdentifier"]!, response.PartiesToken);

            var handler = new JwtSecurityTokenHandler { MaximumTokenSizeInBytes = 1024 * 1024 * 2 };
            var partiesToken = handler.ReadJwtToken(response.PartiesToken);
            var partiesTokenClaim = partiesToken.Claims.Where(c => c.Type == "parties_info").First();
            var partiesInfoClaim = JsonSerializer.Deserialize<PartiesClaim>(partiesTokenClaim.Value);

            if (partiesInfoClaim?.PartiesInfo is null || partiesInfoClaim.Count > 1) throw new Exception("Received invalid parties info.");

            _logger.LogInformation("Received party info for party {party} with certificate subject {certificateSubject}", partyId, hasCertificateSubject ? certificateSubject : "NULL");
            var party = partiesInfoClaim.PartiesInfo.FirstOrDefault();

            if (party is not null) return (party, hasCertificateSubject);

            if (!hasCertificateSubject) throw new Exception("Received empty party info list.");

            return await GetPartyAtSchemeOwnerAsync(partyId);
        }
        catch (Exception e)
        {
            _logger.LogError("Could not get party info from scheme owner: {msg}", e.Message);
            throw;
        }
    }

    public async Task VerifyCertificateIsTrustedAsync(string clientAssertion)
    {
        var handler = new JwtSecurityTokenHandler { MaximumTokenSizeInBytes = 1024 * 1024 * 2 };
        var token = handler.ReadJwtToken(clientAssertion);
        var chain = AuthenticationService.GetCertificateChain(token);

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
        var handler = new JwtSecurityTokenHandler { MaximumTokenSizeInBytes = 1024 * 1024 * 2 };
        var token = handler.ReadJwtToken(clientAssertion);
        var chain = AuthenticationService.GetCertificateChain(token);
        var signingCertificate = new X509Certificate2(Convert.FromBase64String(chain.First()));

        var (partyInfo, foundWithCertificateName) = await GetPartyAsync(partyId, signingCertificate.Subject);

        if (partyInfo.Adherence?.Status?.Equals("active", StringComparison.OrdinalIgnoreCase) != true ||
            partyInfo.Adherence.StartDate > DateTime.Now ||
            partyInfo.Adherence.EndDate <= DateTime.Now)
        {
            _logger.LogError("Party info checks failed for party {partyId} and certificate subject {certificateSubject}", partyId, signingCertificate.Subject);
            throw new Exception("Party info checks failed.");
        }

        if (partyInfo.Certificates is null)
        {
            if (!foundWithCertificateName)
            {
                _logger.LogError("Certificate with subject {certificateSubject} for party {partyId} not found and no certificates present in response to do checks", signingCertificate.Subject, partyId);
                throw new Exception("Party info checks on certificates failed: no certificates in response");
            }
        }
        else
        {
            var thumbprint = GetSha256Thumbprint(signingCertificate);
            if (!partyInfo.Certificates.Any(c => thumbprint.Equals(c.X5tS256, StringComparison.OrdinalIgnoreCase)))
            {
                _logger.LogError("Certificate with subject {certificateSubject} and thumbprint {thumbprint} for party {partyId} not registered", signingCertificate.Subject, thumbprint, partyId);
                throw new Exception("Party info checks on certificates failed: certificate not registered");
            }
        }
    }

    private static string GetSha256Thumbprint(X509Certificate2 certificate)
    {
        return Convert.ToHexString(SHA256.HashData(certificate.GetRawCertData()));
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
