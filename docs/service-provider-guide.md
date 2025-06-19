# Service Provider Implementation Guide

⚠️ **This is an example guide for educational purposes only. Do not use this code in production without proper security implementations.**

A step-by-step guide to implement an iSHARE Service Provider using ASP.NET Core Minimal API and the Poort8.Ishare.Core package.

**What you'll build**: An energy data API that exposes smart meter readings protected by iSHARE authentication and authorization.

## Production Considerations

🚨 **Important**: This example uses simplified implementations that are **NOT production-ready**:

- **Access tokens**: Uses simple Base64 encoding instead of proper JWT tokens with expiration
- **Token validation**: Simplified token parsing instead of proper JWT validation
- **Security**: Missing input validation, rate limiting, and proper error handling
- **Performance**: No caching of delegation evidence or access tokens
- **Certificates**: Store certificates securely (Azure Key Vault recommended)

## Prerequisites

- .NET 8.0 SDK or newer
- iSHARE test certificate ([get one here](https://dev.ishare.eu/introduction/test-certificates))
- Participant registration completed
- Basic understanding of ASP.NET Core

## 1. Setup Project

Create a new minimal API project:

```bash
dotnet new webapi -minimal -n EnergyDataApi
cd EnergyDataApi
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
    "ClientId": "EU.EORI.NL000000001",
    "SatelliteId": "EU.EORI.NL000000002", 
    "SatelliteUrl": "https://scheme.isharetest.net",
    "AuthorizationRegistryId": "EU.EORI.NL000000003",
    "AuthorizationRegistryUrl": "https://ar.isharetest.net",
    "Certificate": "your-base64-certificate-here",
    "CertificatePassword": "your-certificate-password",
    "CertificateChain": "your-base64-certificate-chain-here"
  }
}
```

## 3. Implementation

Replace the contents of `Program.cs`:

```csharp
using Poort8.Ishare.Core;
using Poort8.Ishare.Core.Models;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add iSHARE services
builder.Services.AddIshareCoreServices(builder.Configuration);

var app = builder.Build();

// Sample energy data
var energyData = new Dictionary<string, EnergyReading>
{
    ["871685900012345678"] = new("871685900012345678", 2547.8m, DateTime.UtcNow.AddHours(-1)),
    ["871685900087654321"] = new("871685900087654321", 1832.4m, DateTime.UtcNow.AddHours(-1)),
    ["871685900055555555"] = new("871685900055555555", 3421.6m, DateTime.UtcNow.AddHours(-1))
};

// Required iSHARE endpoint: Token
app.MapPost("/connect/token", async (TokenRequest request, IAuthenticationService authService) =>
{
    try
    {
        // Validate the client assertion
        await authService.ValidateClientAssertion(request.client_assertion, request.client_id);
        
        // Create a simple access token (in production, use proper JWT with expiration)
        var token = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{request.client_id}:{DateTime.UtcNow:O}"));
        
        return Results.Ok(new { access_token = token, token_type = "Bearer", expires_in = 3600 });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = "invalid_client", error_description = ex.Message });
    }
});

// Protected data endpoint with delegation verification
app.MapGet("/api/energy/{ean}", async (
    string ean,
    HttpContext context,
    IAuthenticationService authService,
    IAuthorizationRegistryService authzService) =>
{
    try
    {
        // Step 1: Validate access token
        var authHeader = context.Request.Headers["Authorization"];
        if (!authHeader.StartsWith("Bearer "))
            return Results.Unauthorized();

        var token = authHeader["Bearer ".Length..];
        await authService.ValidateToken(token, SERVICE_PROVIDER_EORI);

        // Step 2: Extract client ID from token (simplified - in production, decode JWT properly)
        var tokenBytes = Convert.FromBase64String(token);
        var tokenString = System.Text.Encoding.UTF8.GetString(tokenBytes);
        var clientId = tokenString.Split(':')[0];

        // Step 3: Create delegation mask for energy data access
        var delegationMask = new DelegationMask
        {
            DelegationRequest = new DelegationMask.DelegationRequestObject
            {
                PolicyIssuer = "EU.EORI.NL000000004", // Energy data owner
                Target = new DelegationMask.DelegationRequestObject.TargetObject
                {
                    AccessSubject = clientId // The requesting party
                },
                PolicySets = new List<DelegationMask.DelegationRequestObject.PolicySet>
                {
                    new DelegationMask.DelegationRequestObject.PolicySet
                    {
                        Policies = new List<DelegationMask.DelegationRequestObject.PolicySet.Policy>
                        {
                            new DelegationMask.DelegationRequestObject.PolicySet.Policy
                            {
                                Target = new DelegationMask.DelegationRequestObject.PolicySet.Policy.TargetObject
                                {
                                    Resource = new DelegationMask.DelegationRequestObject.PolicySet.Policy.TargetObject.ResourceObject
                                    {
                                        Type = "energy-data",
                                        Identifiers = new List<string> { ean },
                                        Attributes = new List<string> { "consumption" }
                                    },
                                    Actions = new List<string> { "read" },
                                    Environment = new DelegationMask.DelegationRequestObject.PolicySet.Policy.TargetObject.EnvironmentObject
                                    {
                                        ServiceProviders = new List<string> { "EU.EORI.NL000000001" }
                                    }
                                },
                                Rules = new List<DelegationMask.DelegationRequestObject.PolicySet.Policy.Rule>
                                {
                                    new DelegationMask.DelegationRequestObject.PolicySet.Policy.Rule { Effect = "Permit" }
                                }
                            }
                        }
                    }
                }
            }
        };

        // Step 4: Get and verify delegation evidence
        var evidence = await authzService.GetDelegationEvidence(delegationMask);
        
        bool isAuthorized = authzService.VerifyDelegationEvidencePermit(
            evidence,
            "EU.EORI.NL000000004", // Policy issuer
            clientId,               // Access subject
            "EU.EORI.NL000000001", // Service provider (us)
            "energy-data",          // Resource type
            ean,                    // Resource identifier
            "read");                // Action

        if (!isAuthorized)
            return Results.Forbid();

        // Step 5: Return the energy data
        if (energyData.TryGetValue(ean, out var reading))
            return Results.Ok(reading);
        else
            return Results.NotFound();
    }
    catch (Exception ex)
    {
        return Results.Problem($"Authorization failed: {ex.Message}");
    }
});

app.Run();

// Data models
public record TokenRequest(string grant_type, string client_assertion_type, string client_assertion, string client_id);
public record EnergyReading(string EAN, decimal ConsumptionKwh, DateTime Timestamp);
```

## 4. Test Your Service Provider

### Test Token Endpoint

```bash
curl -X POST https://localhost:7000/connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=YOUR_CLIENT_ASSERTION&client_id=EU.EORI.NL000000999"
```

### Test Energy Data Endpoint

```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  https://localhost:7000/api/energy/871685900012345678
```

## 5. What This Implementation Does

### Token Endpoint (`/connect/token`)
1. ✅ **Validates client assertion** using `IAuthenticationService`
2. ✅ **Checks party legitimacy** via satellite
3. ✅ **Returns access token** for authenticated clients

### Energy Data Endpoint (`/api/energy/{ean}`)
1. ✅ **Validates access token** from Authorization header
2. ✅ **Fetches delegation evidence** for the specific EAN and client
3. ✅ **Verifies permissions** before returning data
4. ✅ **Returns energy consumption data** only if authorized

For more details, see the [iSHARE Service Provider specification](https://dev.ishare.eu/service-provider-role/getting-started).
