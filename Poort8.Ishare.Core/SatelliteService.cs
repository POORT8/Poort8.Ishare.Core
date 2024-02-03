using LazyCache;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Poort8.Ishare.Core.Models;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Web;

namespace Poort8.Ishare.Core;

public class SatelliteService(
    ILogger<SatelliteService> logger,
    IOptions<IshareCoreOptions> options,
    IHttpClientFactory httpClientFactory,
    IAccessTokenService accessTokenService,
    IAppCache? memoryCache) : ISatelliteService
{
    private readonly HttpClient httpClient = httpClientFactory.CreateClient(nameof(SatelliteService));

    public async Task<IEnumerable<TrustedListAuthority>> GetValidTrustedList()
    {
        IEnumerable<TrustedListAuthority> trustedList;
        if (memoryCache == null)
        {
            trustedList = await GetTrustedListAtSatellite();
        }
        else
        {
            trustedList = await memoryCache.GetOrAddAsync("TrustedList", async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(1);
                return await GetTrustedListAtSatellite();
            });
        }

        return trustedList;
    }

    private async Task<IEnumerable<TrustedListAuthority>> GetTrustedListAtSatellite()
    {
        try
        {
            await SetAuthorizationHeader(accessTokenService);

            var trustedListUrl = GetUrl("trusted_list");
            var response = await httpClient.GetFromJsonAsync<TrustedListResponse>(trustedListUrl);

            var trustedList = await DecodeTrustedListToken(response!);

            logger.LogInformation("Received trusted list from satellite with {trustedListCount} values.", trustedList.Count());
            return trustedList!;
        }
        catch (Exception e)
        {
            logger.LogError("Could not get trusted list from satellite: {msg}", e.Message);
            throw;
        }
    }

    private async Task<IEnumerable<TrustedListAuthority?>> DecodeTrustedListToken(TrustedListResponse token)
    {
        var trustedListToken = await SatelliteTokenValidation(token.TrustedListToken);

        return trustedListToken.Claims
            .Where(c => c.Type == "trusted_list")
            .Select(c => JsonSerializer.Deserialize<TrustedListAuthority>(c.Value))
            .Where(a =>
                a!.Status.Equals("granted", StringComparison.OrdinalIgnoreCase) &&
                a.Validity.Equals("valid", StringComparison.OrdinalIgnoreCase));
    }

    public async Task<PartyInfo> VerifyParty(string partyId, string certificateSubject, string certificateThumbprint)
    {
        PartyInfo partyInfo;
        if (memoryCache == null)
        {
            var partyInfos = await GetPartyInfoAtSatellite(partyId, certificateSubject);
            partyInfo = CheckPartyProperties(partyInfos, certificateSubject, certificateThumbprint);
        }
        else
        {
            string cacheKey = $"PartyInfo-{partyId.Replace('-', '_')}-{certificateSubject.Replace('-', '_')}";
            partyInfo = await memoryCache.GetOrAddAsync(cacheKey, async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(1);
                var partyInfos = await GetPartyInfoAtSatellite(partyId, certificateSubject);
                return CheckPartyProperties(partyInfos, certificateSubject, certificateThumbprint);
            });
        }

        return partyInfo;
    }

    private PartyInfo CheckPartyProperties(IEnumerable<PartyInfo> partyInfos, string certificateSubject, string certificateThumbprint)
    {
        try
        {
            if (partyInfos.First().Certifications is not null)
            {
                //NOTE: We cannot do any certificate chechs for the scheme owner.
                return partyInfos.First();
            }

            return partyInfos
                .Where(p => p.Certificates
                    .Any(c =>
                        c.SubjectName.Equals(certificateSubject, StringComparison.OrdinalIgnoreCase) &&
                        c.X5tS256.Equals(certificateThumbprint, StringComparison.OrdinalIgnoreCase)))
                .First();
        }
        catch (Exception e)
        {
            logger.LogError("CheckPartyProperties failed for certificate subject {certificateSubject}: {msg}", certificateSubject, e.Message);
            throw;
        }
    }

    private async Task<IEnumerable<PartyInfo>> GetPartyInfoAtSatellite(string partyId, string certificateSubject)
    {
        try
        {
            await SetAuthorizationHeader(accessTokenService);

            var partiesUrl = GetUrl("parties");

            var builder = new UriBuilder(partiesUrl);
            var queryParameters = HttpUtility.ParseQueryString(string.Empty);
            queryParameters["eori"] = partyId;

            if (!(partiesUrl.StartsWith("https://scheme.isharetest.net", StringComparison.CurrentCultureIgnoreCase) ||
                partiesUrl.StartsWith("https://so.ishareworks.org", StringComparison.CurrentCultureIgnoreCase)))
                queryParameters["certificate_subject_name"] = certificateSubject; //NOTE: This parameter is incompatible with the Scheme Owner.

            queryParameters["active_only"] = "true";
            builder.Query = queryParameters.ToString();

            var response = await httpClient.GetFromJsonAsync<PartiesResponse>(builder.Uri);

            var partyInfos = await DecodePartiesToken(response!);

            logger.LogInformation("Received party info from satellite with {partyInfoCount} values.", partyInfos.Count());
            return partyInfos;
        }
        catch (Exception e)
        {
            logger.LogError("Could not get party info from satellite: {msg}", e.Message);
            throw;
        }
    }

    private async Task<IEnumerable<PartyInfo>> DecodePartiesToken(PartiesResponse token)
    {
        var partiesToken = await SatelliteTokenValidation(token.PartiesToken);

        return partiesToken.Claims
            .Where(c => c.Type == "parties_info")
            .Select(c => JsonSerializer.Deserialize<PartiesInfoClaim>(c.Value))
            .SelectMany(p => p!.PartyInfos);
    }

    private async Task<JsonWebToken> SatelliteTokenValidation(string token)
    {
        var handler = new JsonWebTokenHandler { MaximumTokenSizeInBytes = 1024 * 1024 * 2 };

        //NOTE: As we trust the satellite and get the tokens from a predefined url over HTTPS we only do basic token validation.
        var tokenValidationParameters = new TokenValidationParameters()
        {
            ValidAlgorithms = new List<string>() { "RS256" },
            ValidTypes = new List<string>() { "JWT" },
            ValidateIssuer = true,
            ValidIssuer = options.Value.SatelliteId,
            ValidateAudience = true,
            ValidAudience = options.Value.ClientId,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.FromSeconds(10),
            RequireSignedTokens = true,
        };

        await handler.ValidateTokenAsync(token, tokenValidationParameters);

        return handler.ReadJsonWebToken(token);
    }

    private async Task SetAuthorizationHeader(IAccessTokenService accessTokenService)
    {
        var tokenUrl = GetUrl("connect/token");
        var token = await accessTokenService.GetAccessTokenAtParty(options.Value.SatelliteId, tokenUrl);
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    private string GetUrl(string relativeUrl)
    {
        var baseUrl = new Uri(options.Value.SatelliteUrl);
        return new Uri(baseUrl, relativeUrl).AbsoluteUri;
    }

    public record TrustedListResponse(
        [property: JsonPropertyName("trusted_list_token")] string TrustedListToken
    );

    public record PartiesResponse(
        [property: JsonPropertyName("parties_token")] string PartiesToken
    );

    public record PartiesInfoClaim(
        [property: JsonPropertyName("total_count")] int TotalCount,
        [property: JsonPropertyName("pageCount")] int PageCount,
        [property: JsonPropertyName("count")] int Count,
        [property: JsonPropertyName("data")] IReadOnlyList<PartyInfo> PartyInfos
    );
}
