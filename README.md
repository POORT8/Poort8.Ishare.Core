[![Actions Status](https://github.com/POORT8/Poort8.Ishare.Core/workflows/Build%20and%20test/badge.svg)](https://github.com/POORT8/Poort8.Ishare.Core/actions) [![Nuget](https://img.shields.io/nuget/v/Poort8.Ishare.Core)](https://www.nuget.org/packages/Poort8.Ishare.Core/) [![codecov](https://codecov.io/gh/POORT8/Poort8.Ishare.Core/graph/badge.svg?token=FTVIUQR1XB)](https://codecov.io/gh/POORT8/Poort8.Ishare.Core) [![.NET 8.0](https://img.shields.io/badge/.NET-8.0-blue.svg)](https://dotnet.microsoft.com/download/dotnet/8.0)

# Poort8.Ishare.Core

A .NET library for implementing iSHARE Trust Framework functionality in your applications. This package provides essential services for building iSHARE-compliant Service Providers and Service Consumers.

**Compatible with iSHARE Trust Framework 2.2**

For more information about iSHARE, visit the [iSHARE Developer Portal](https://dev.ishare.eu/).

## Key iSHARE Concepts

This package helps you implement iSHARE functionality for secure data sharing in data ecosystems. For a complete understanding of iSHARE concepts and workflows, please refer to the [iSHARE Getting Started Guide](https://dev.ishare.eu/introduction/getting-started).

Quick terminology reference:
- **EORI**: Your unique identifier (e.g., `EU.EORI.NL000000001`)
- **Service Provider**: You expose APIs with data (implement token validation)
- **Service Consumer**: You call other APIs to get data (use access tokens)
- **M2M**: Machine-to-Machine authorization (system-to-system)
- **H2M**: Human-to-Machine authorization (users acting on behalf of organizations)

For detailed concepts, see [iSHARE Authorization](https://trustbok.ishare.eu/apply-ishare/authorisation) and [Authentication](https://trustbok.ishare.eu/apply-ishare/authentication).

## Before You Start

### Prerequisites

- .NET 8.0 or higher
- Basic understanding of JWT tokens and dependency injection
- iSHARE certificate and participant registration

### Getting iSHARE Ready
1. **Get test certificates**: [Request here](https://dev.ishare.eu/introduction/test-certificates)
2. **Register as participant**: Contact a Participant Registry
3. **Determine your role**: Service Provider, Consumer, or both

## Installation

Install the NuGet package:

```bash
dotnet add package Poort8.Ishare.Core
```

Register the services in your application (e.g., ASP.NET Core):

```csharp
builder.Services.AddIshareCoreServices(builder.Configuration);
```

## Configuration

Add the following configuration section to your `appsettings.json`:

```json
{
  "IshareCoreOptions": {
    "ClientId": "EU.EORI.NLXXXXXXXXX",
    "SatelliteId": "EU.EORI.NLXXXXXXXXX", 
    "SatelliteUrl": "https://satellite.example.com",
    "AuthorizationRegistryId": "EU.EORI.NLXXXXXXXXX",
    "AuthorizationRegistryUrl": "https://ar.example.com"
  }
}
```

### Required Configuration

- **`ClientId`**: Your organization's EORI identifier
- **`SatelliteId`**: The dataspace satellite's EORI identifier  
- **`SatelliteUrl`**: URL of the dataspace satellite

### Optional Configuration

- **`AuthorizationRegistryId`**: Authorization Registry EORI identifier
- **`AuthorizationRegistryUrl`**: Authorization Registry URL

### Certificate Configuration

**You need certificates for**: Authenticating your organization in the iSHARE network.

Choose **either** Azure Key Vault **or** file-based certificates:

#### Azure Key Vault
**Use this if**: You're running in Azure and want centralized certificate management.

```json
{
  "IshareCoreOptions": {
    "AzureKeyVaultUrl": "https://your-keyvault.vault.azure.net/",
    "CertificateName": "your-certificate-name"
  }
}
```

#### File-based Certificates
**Use this if**: You want to store certificates directly in your application configuration.

```json
{
  "IshareCoreOptions": {
    "Certificate": "base64-encoded-pfx-certificate",
    "CertificatePassword": "certificate-password",
    "CertificateChain": "base64-encoded-certificate-chain",
    "CertificateChainPassword": "chain-password"
  }
}
```

## Quick Start

Here's a practical example: You're building a logistics app that needs truck location data from a transport company's API.

```csharp
// Inject the required services in your controller or service class
public class LogisticsService
{
    private readonly IAccessTokenService _accessTokenService;
    private readonly IAuthenticationService _authenticationService;
    private readonly IHttpClientFactory _httpClientFactory;
    
    public LogisticsService(
        IAccessTokenService accessTokenService,
        IAuthenticationService authenticationService,
        IHttpClientFactory httpClientFactory)
    {
        _accessTokenService = accessTokenService;
        _authenticationService = authenticationService;
        _httpClientFactory = httpClientFactory;
    }
    
    // SCENARIO 1: You're consuming data (Service Consumer)
    public async Task<TruckLocation[]> GetTruckLocations()
    {
        // Step 1: Get access token from the transport company
        var transportCompanyEori = "EU.EORI.NL000000123";
        var tokenUrl = "https://transport-api.com/connect/token";
        
        string accessToken = await _accessTokenService.GetAccessTokenAtParty(
            transportCompanyEori, tokenUrl);
        
        // Step 2: Use token to fetch truck data
        using var httpClient = _httpClientFactory.CreateClient();
        httpClient.DefaultRequestHeaders.Authorization = 
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            
        var response = await httpClient.GetAsync("https://transport-api.com/api/trucks/locations");
        // Handle response...
        return Array.Empty<TruckLocation>(); // Your deserialization logic here
    }
    
    // SCENARIO 2: You're providing data (Service Provider)
    // This would be in your API controller's token endpoint
    public async Task ValidateIncomingRequest(string clientAssertion, string clientId)
    {
        try
        {
            // Validate that the requesting party is legitimate
            await _authenticationService.ValidateClientAssertion(clientAssertion, clientId);
            // If this succeeds, create and return an access token
        }
        catch (Exception)
        {
            // Reject the request - invalid client
            throw;
        }
    }
}

public class TruckLocation 
{ 
    public string TruckId { get; set; } = "";
    public double Latitude { get; set; }
    public double Longitude { get; set; }
}
```

## API Reference

### IAccessTokenService

**When to use**: When you need to call another party's API (you're a Service Consumer).

```csharp
// Get access token from a specific party
// Parameters:
// - partyId: The EORI of the party you want to call
// - tokenUrl: Their token endpoint URL (usually ends with /connect/token)
string token = await accessTokenService.GetAccessTokenAtParty(
    "EU.EORI.NL000000123", 
    "https://transport-company.com/connect/token");
```

### IAuthenticationService

**When to use**: When validating incoming requests to your API (you're a Service Provider).

```csharp
// Validate client assertion - use this in your /connect/token endpoint
// This checks if the requesting party is legitimate and their certificate is valid
await authenticationService.ValidateClientAssertion(clientAssertion, clientIdHeader);
```

### IAuthorizationRegistryService

**When to use**: For M2M authorization scenarios requiring delegation evidence validation. See [iSHARE Authorization](https://trustbok.ishare.eu/apply-ishare/authorisation) for complete delegation flows.

```csharp
// Simplified delegation check - just the essence
var delegationMask = new DelegationMask 
{
    DelegationRequest = new DelegationMask.DelegationRequestObject
    {
        PolicyIssuer = "EU.EORI.NL000000001", // Policy issuer (data owner)
        Target = new DelegationMask.DelegationRequestObject.TargetObject
        {
            AccessSubject = "EU.EORI.NL000000002" // Access subject (who wants access)
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
                                Type = "resource-type",
                                Identifiers = new List<string> { "*" },
                                Attributes = new List<string> { "*" }
                            },
                            Actions = new List<string> { "read" },
                            Environment = new DelegationMask.DelegationRequestObject.PolicySet.Policy.TargetObject.EnvironmentObject
                            {
                                ServiceProviders = new List<string> { "EU.EORI.NL000000003" }
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

// Get delegation evidence
var evidence = await authorizationRegistryService.GetDelegationEvidence(delegationMask);
bool hasAccess = authorizationRegistryService.VerifyDelegationEvidencePermit(
    evidence, "EU.EORI.NL000000001", "EU.EORI.NL000000002", "EU.EORI.NL000000003", 
    "resource-type", "resource-id", "read");
```

### IClientAssertionCreator

**When to use**: When you need to authenticate with other parties or when Service Providers collect delegation evidence on behalf of clients.

```csharp
// Create client assertion for authentication with another party
string clientAssertion = clientAssertionCreator.CreateClientAssertion("audience-eori");
```

### ISatelliteService

**When to use**: When you need to verify if parties are legitimate or get trusted certificate authorities.

```csharp
// Verify party using certificate thumbprint
PartyInfo partyInfo = await satelliteService.VerifyParty("EU.EORI.NLXXXXXXXXX", "certificateThumbprint");

// Verify party using client assertion
PartyInfo partyInfo = await satelliteService.VerifyPartyWithClientAssertion("EU.EORI.NLXXXXXXXXX", "clientAssertion");

// Get valid trusted list
IEnumerable<TrustedListAuthority> trustedList = await satelliteService.GetValidTrustedList();
```

## Service Providers

**You're a Service Provider if**: You have data/services that other companies want to access through APIs.

You must implement these required endpoints: **Access Token**, **Capabilities**, and **Return**. 
For complete implementation details, see [Service Provider Role](https://dev.ishare.eu/service-provider-role/getting-started).

### Token Endpoint Implementation

```csharp
// Validate client assertion in your token endpoint
try 
{
    await authenticationService.ValidateClientAssertion(request.ClientAssertion, request.ClientId);
    // Create and return access token
}
catch (Exception ex)
{
    // Handle validation failure
}
```

### Service Data Endpoints

```csharp
// In your data endpoints, validate access token first (your implementation)
// Then optionally validate delegation evidence
bool isAuthorized = authorizationRegistryService.VerifyDelegationEvidencePermit(
    delegationEvidence,
    "policyIssuer",
    "accessSubject", 
    "serviceProvider",
    "resourceType",
    "resourceIdentifier", 
    "action");
```

**Delegation Evidence**: Following [iSHARE M2M authorization patterns](https://trustbok.ishare.eu/apply-ishare/authorisation), the **preferred approach** is for Service Providers to fetch and validate delegation evidence themselves rather than relying on Service Consumers to provide it. This provides better security and control over authorization decisions.

## Service Consumers

**You're a Service Consumer if**: You want to call other companies' APIs to get their data.

For complete implementation scenarios and workflows, see [Service Consumer Role](https://dev.ishare.eu/service-consumer-role/getting-started).

### Basic Flow

```csharp
// 1. Get access token from Service Provider
string accessToken = await accessTokenService.GetAccessTokenAtParty(
    "EU.EORI.NL000000123", 
    "https://service-provider.com/connect/token");

// 2. Use token in HTTP requests to their APIs
using var httpClient = httpClientFactory.CreateClient();
httpClient.DefaultRequestHeaders.Authorization = 
    new AuthenticationHeaderValue("Bearer", accessToken);

var response = await httpClient.GetAsync("https://service-provider.com/api/data");
```

### Advanced Flow (With Delegation)

**You need this if**: You're accessing data on behalf of another organization following [iSHARE M2M authorization](https://trustbok.ishare.eu/apply-ishare/authorisation).

```csharp
public class BrokerService
{
    private readonly IAuthorizationRegistryService _authService;
    
    public async Task<bool> CheckDelegationRights(string dataOwnerEori, string serviceProviderEori)
    {
        // Request delegation evidence to verify access rights
        var delegationMask = new DelegationMask
        {
            DelegationRequest = new DelegationMask.DelegationRequestObject
            {
                PolicyIssuer = dataOwnerEori, // Data owner who issued the policy
                Target = new DelegationMask.DelegationRequestObject.TargetObject
                {
                    AccessSubject = "EU.EORI.NL000000789" // Your organization's EORI
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
                                        Type = "data-container",
                                        Identifiers = new List<string> { "*" },
                                        Attributes = new List<string> { "*" }
                                    },
                                    Actions = new List<string> { "read" },
                                    Environment = new DelegationMask.DelegationRequestObject.PolicySet.Policy.TargetObject.EnvironmentObject
                                    {
                                        ServiceProviders = new List<string> { serviceProviderEori }
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
        
        try
        {
            var evidence = await _authService.GetDelegationEvidence(delegationMask);
            // Verify the evidence contains the required permissions
            return _authService.VerifyDelegationEvidencePermit(
                evidence, dataOwnerEori, "EU.EORI.NL000000789", serviceProviderEori, 
                "data-container", "*", "read");
        }
        catch
        {
            return false; // No delegation rights
        }
    }
}
```

**Note**: Following iSHARE best practices, Service Providers should fetch and validate delegation evidence themselves rather than requiring Service Consumers to provide it.

## Error Handling

**When to use this**: Always wrap iSHARE operations in try-catch blocks for production code following [zero trust principles](https://trustbok.ishare.eu/apply-ishare/authentication).

The library throws exceptions for various error conditions:

```csharp
try 
{
    await authenticationService.ValidateClientAssertion(clientAssertion, clientId);
}
catch (SatelliteException ex)
{
    // Handle satellite-specific errors (party verification, certificate validation)
    logger.LogError("P8.err - Satellite error: {Message}", ex.Message);
}
catch (Exception ex)
{
    // Handle general validation errors (token validation, delegation evidence)
    logger.LogError("P8.err - Validation failed: {Message}", ex.Message);
}
```

## Key Dependencies

This package includes the following key dependencies:

- **System.IdentityModel.Tokens.Jwt**: JWT token handling
- **Azure.Security.KeyVault.Certificates**: Azure Key Vault integration
- **LazyCache.AspNetCore**: Caching functionality
- **Microsoft.Extensions.Http**: HTTP client factory support

## Resources

- [iSHARE Developer Portal](https://dev.ishare.eu/)
- [iSHARE Trust Framework Specification](https://dev.ishare.eu/)
- [Service Provider Implementation Guide](https://dev.ishare.eu/service-provider-role/getting-started)
- [Service Consumer Implementation Guide](https://dev.ishare.eu/service-consumer-role/getting-started)
- [Common Endpoints](https://dev.ishare.eu/common/)
- [iSHARE Authorization Concepts](https://trustbok.ishare.eu/apply-ishare/authorisation)
- [iSHARE Authentication Concepts](https://trustbok.ishare.eu/apply-ishare/authentication)
- [Data Sharing Principles](https://trustbok.ishare.eu/understand-ishare/data-sharing-principles)

## License

This project is licensed under the MPL-2.0 license - see the [LICENSE](LICENSE) file for details.
