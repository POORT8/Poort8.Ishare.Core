[![Actions Status](https://github.com/POORT8/Poort8.Ishare.Core/workflows/Build%20and%20test/badge.svg)](https://github.com/POORT8/Poort8.Ishare.Core/actions) [![Nuget](https://img.shields.io/nuget/v/Poort8.Ishare.Core)](https://www.nuget.org/packages/Poort8.Ishare.Core/)

# Poort8.Ishare.Core

This .NET library encapsulates the core iSHARE functionality, tailored for .NET applications, to interact with an Authorization Registry. It leverages Microsoft's .NET ecosystem, including Azure services, to provide a robust and secure way to handle authorization and authentication via iSHARE standards.

_Disclaimer: This library is intended for prototyping and development purposes. Ensure thorough testing and validation for production deployments._

## Configuration

In the `.NET` environment of `Poort8.Ishare.Core`, configuration is streamlined through the `IshareCoreOptions` class, aligned with settings in `appsettings.json`. Key configuration properties encompass:

- `AuthorizationRegistryUrl`: URL of the Authorization Registry.
- `AuthorizationRegistryId`: EORI of the Authorization Registry (for example, `EU.EORI.NL000000001`).
- `ClientId`: Your EORI (for example, `EU.EORI.NL000000002`).
- Azure KeyVault settings for securely managing certificates and keys.
- `CertificateName`: Name of the certificate stored in Azure KeyVault or locally.
- `Certificate`: The text value of your iSHARE certificate, excluding the `-----BEGIN CERTIFICATE-----` prefix and `-----END CERTIFICATE-----` postfix.
- `CertificatePassword`: The password for your certificate, if applicable.
- `CertificateChain`: The full chain of your iSHARE certificate, excluding the certificate boundaries.
- `CertificateChainPassword`: The password for your certificate chain, if required.

## Certificates and Private Keys Management

Certificates and private keys are crucial for the secure operation of iSHARE functionalities. `Poort8.Ishare.Core` utilizes Azure Key Vault for the secure management of these cryptographic materials, ensuring that sensitive information is stored securely and accessed in a controlled manner.

## Key Classes and Methods

The .NET library provides functionalities essential for interacting with an iSHARE-compliant Authorization Registry:

### AccessTokenService
- **GetAccessTokenAtParty**: Retrieves or caches an access token for interacting with a specific party's Authorization Registry.

### AuthenticationService
- **ValidateToken**: Validates JWT tokens for authenticity and integrity.

### AuthorizationRegistryService
- **GetDelegationEvidence**: Retrieves delegation evidence from the Authorization Registry.
- **VerifyAccess**: Evaluates if the specified access rights to a resource are granted.

## Usage Example

```csharp
var accessTokenService = serviceProvider.GetService<AccessTokenService>();
var authorizationRegistryService = serviceProvider.GetService<AuthorizationRegistryService>();
var partyId = "EU.EORI.NL000000003";
var accessToken = await accessTokenService.GetAccessTokenAtParty(partyId);
var delegationEvidence = await authorizationRegistryService.GetDelegationEvidence(accessToken, "GS1.CONTAINER", "180621.CONTAINER-Z", "ISHARE.READ");
var hasAccess = authorizationRegistryService.VerifyAccess(delegationEvidence, partyId, "GS1.CONTAINER", "180621.CONTAINER-Z", "ISHARE.READ");
Console.WriteLine($"Access Granted: {hasAccess}");
```

## About

`Poort8.Ishare.Core` is a .NET library developed to facilitate secure and standardized authorization mechanisms within the iSHARE scheme, emphasizing integration with Azure services for enhanced security and scalability.

## Resources

- [iSHARE Scheme](https://ishareworks.org)
- [.NET Documentation](https://docs.microsoft.com/en-us/dotnet/)
- [Azure Key Vault Documentation](https://docs.microsoft.com/en-us/azure/key-vault/)

## License

This project is licensed under the MPL-2.0 license - see the LICENSE file for details.
