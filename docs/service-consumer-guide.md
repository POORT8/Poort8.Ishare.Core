# Service Consumer Implementation Guide

⚠️ **This is an example guide for educational purposes only. Do not use this code in production without proper security implementations.**

A step-by-step guide to implement an iSHARE Service Consumer using ASP.NET Core Minimal API and the Poort8.Ishare.Core package.

**What you'll build**: A simple API that consumes smart meter data from iSHARE-compliant Energy Data Providers.

## Production Considerations

🚨 **Important**: This example uses simplified implementations that are **NOT production-ready**:

- **Error handling**: Basic error handling without proper retry logic or fallback mechanisms
- **Token management**: No token caching or automatic renewal
- **Security**: Missing input validation, rate limiting, and proper secrets management
- **Performance**: No connection pooling or request optimization
- **Certificates**: Store certificates securely (Azure Key Vault recommended)

## Prerequisites

- .NET 8.0 SDK or newer
- iSHARE test certificate ([get one here](https://dev.ishare.eu/introduction/test-certificates))
- Participant registration completed
- Basic understanding of ASP.NET Core
- Access to an iSHARE Service Provider (or use our [Service Provider Implementation Guide](service-provider-guide.md))

## 1. Setup Project

Create a new minimal API project:

```bash
dotnet new webapi -minimal -n EnergyConsumerApp
cd EnergyConsumerApp
dotnet add package Poort8.Ishare.Core
```

## 2. Configuration

Update `appsettings.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*",
  "IshareCoreOptions": {
    "ClientId": "EU.EORI.NL000000999",
    "SatelliteId": "EU.EORI.NL000000002", 
    "SatelliteUrl": "https://scheme.isharetest.net",
    "AuthorizationRegistryId": "EU.EORI.NL000000003",
    "AuthorizationRegistryUrl": "https://ar.isharetest.net",
    "Certificate": "your-base64-certificate-here",
    "CertificatePassword": "your-certificate-password",
    "CertificateChain": "your-base64-certificate-chain-here"
  },
  "ServiceProviders": {
    "EnergyDataProvider": {
      "Eori": "EU.EORI.NL000000001",
      "BaseUrl": "https://localhost:7000",
      "TokenEndpoint": "/connect/token"
    }
    }
}
```

## 3. Implementation

Replace the contents of `Program.cs`:

```csharp
using Poort8.Ishare.Core;
using System.Net.Http.Headers;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add iSHARE services
builder.Services.AddIshareCoreServices(builder.Configuration);

var app = builder.Build();

// Get energy data for a specific meter
app.MapGet("/meter/{ean}", async (
    string ean,
    IAccessTokenService tokenService,
    IHttpClientFactory httpClientFactory,
    IConfiguration config) =>
{
    try
    {
        var providerConfig = config.GetSection("ServiceProviders:EnergyDataProvider");
        var providerEori = providerConfig["Eori"];
        var providerBaseUrl = providerConfig["BaseUrl"];
        var tokenEndpoint = providerConfig["TokenEndpoint"];

        // Step 1: Get access token from the Service Provider
        var tokenUrl = $"{providerBaseUrl}{tokenEndpoint}";
        string accessToken = await tokenService.GetAccessTokenAtParty(providerEori, tokenUrl);

        // Step 2: Request specific meter data
        using var httpClient = httpClientFactory.CreateClient();
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var response = await httpClient.GetAsync($"{providerBaseUrl}/api/energy/{ean}");

        if (response.IsSuccessStatusCode)
        {
            var jsonContent = await response.Content.ReadAsStringAsync();
            var reading = JsonSerializer.Deserialize<EnergyReading>(jsonContent, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            return Results.Ok(reading);
        }
        else if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            return Results.Forbid();
        }
        else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return Results.NotFound($"Meter {ean} not found");
        }
        else
        {
            return Results.Problem($"Service Provider error: {response.StatusCode}");
        }
    }
    catch (Exception ex)
    {
        return Results.Problem($"Failed to fetch meter data: {ex.Message}");
    }
});

app.Run();

// Data model (should match Service Provider's model)
public record EnergyReading(string EAN, decimal ConsumptionKwh, DateTime Timestamp);
```

## 4. Test Your Service Consumer

### Start the Service Consumer

```bash
dotnet run
```

### Test Meter Endpoint

```bash
curl https://localhost:7001/meter/871685900012345678
```

## 5. What This Implementation Does

### Meter Endpoint (`/meter/{ean}`)
1. ✅ **Gets access token** from configured Service Provider using `IAccessTokenService`
2. ✅ **Requests specific meter data** from Service Provider
3. ✅ **Handles different response scenarios** (success, forbidden, not found, errors)
4. ✅ **Returns structured data** or appropriate error responses

For more details, see the [iSHARE Service Consumer specification](https://dev.ishare.eu/service-consumer-role/getting-started).
