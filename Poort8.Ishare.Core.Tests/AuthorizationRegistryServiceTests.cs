using Bogus;
using FluentAssertions;
using LazyCache;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Poort8.Ishare.Core.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

namespace Poort8.Ishare.Core.Tests;

public class AuthorizationRegistryServiceTests
{
    private readonly IOptions<IshareCoreOptions> _options;
    private readonly AuthorizationRegistryService _authorizationRegistryService;
    private readonly ClientAssertionCreator _clientAssertionCreator;

    public AuthorizationRegistryServiceTests()
    {
        _options = Fixtures.GetCertificateTestOptions();
        _options.Value.ClientId = "serviceProvider";

        var fakeSatelliteService = new FakeSatelliteService();

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        var memoryCache = Substitute.For<IAppCache>();
        var certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _options);
        var certificateValidator = new CertificateValidator(NullLogger<CertificateValidator>.Instance, fakeSatelliteService);
        _clientAssertionCreator = new ClientAssertionCreator(_options, certificateProvider);

        var authenticationService = new AuthenticationService(
            NullLogger<AuthenticationService>.Instance,
            _options,
            httpClientFactory,
            certificateValidator,
            fakeSatelliteService);

        var accessTokenService = new AccessTokenService(
            new NullLogger<AccessTokenService>(),
            _options,
            httpClientFactory,
            _clientAssertionCreator,
            memoryCache);

        _authorizationRegistryService = new AuthorizationRegistryService(
            NullLogger<AuthorizationRegistryService>.Instance,
            _options,
            httpClientFactory,
            accessTokenService,
            authenticationService);
    }

    [Fact]
    public void VerifyDelegationEvidenceShouldPass()
    {
        var fakeDelegationEvidence = CreateFakeDelegationEvidence();

        var permit = _authorizationRegistryService.VerifyDelegationEvidencePermit(
            fakeDelegationEvidence,
            fakeDelegationEvidence.PolicyIssuer,
            fakeDelegationEvidence.Target.AccessSubject,
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Environment.ServiceProviders[0],
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Resource.Type,
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Resource.Identifiers[0],
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Actions[0]);

        permit.Should().BeTrue();
    }

    [Fact]
    public void VerifyInvalidLifetimeShouldFail()
    {
        var fakeDelegationEvidence = CreateFakeDelegationEvidence(invalidLifetime: true);

        var permit = _authorizationRegistryService.VerifyDelegationEvidencePermit(
            fakeDelegationEvidence,
            fakeDelegationEvidence.PolicyIssuer,
            fakeDelegationEvidence.Target.AccessSubject,
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Environment.ServiceProviders[0],
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Resource.Type,
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Resource.Identifiers[0],
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Actions[0]);

        permit.Should().BeFalse();
    }

    [Fact]
    public void VerifyDelegationEvidencePermit_NotBeforeEqualNow_ShouldPass()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var fakeDelegationEvidence = CreateFakeDelegationEvidence() with
        {
            NotBefore = now,
            NotOnOrAfter = now + 10
        };

        var permit = _authorizationRegistryService.VerifyDelegationEvidencePermit(
            fakeDelegationEvidence,
            fakeDelegationEvidence.PolicyIssuer,
            fakeDelegationEvidence.Target.AccessSubject,
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Environment.ServiceProviders[0],
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Resource.Type,
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Resource.Identifiers[0],
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Actions[0]);

        permit.Should().BeTrue();
    }

    [Fact]
    public void VerifyDelegationEvidencePermit_NotOnOrAfterEqualNow_ShouldFail()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var fakeDelegationEvidence = CreateFakeDelegationEvidence() with
        {
            NotBefore = now - 10,
            NotOnOrAfter = now
        };

        var permit = _authorizationRegistryService.VerifyDelegationEvidencePermit(
            fakeDelegationEvidence,
            fakeDelegationEvidence.PolicyIssuer,
            fakeDelegationEvidence.Target.AccessSubject,
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Environment.ServiceProviders[0],
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Resource.Type,
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Resource.Identifiers[0],
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Actions[0]);

        permit.Should().BeFalse();
    }

    [Fact]
    public void VerifyDelegationEvidencePermit_ValidConditions_ShouldPass()
    {
        var fakeDelegationEvidence = CreateFakeDelegationEvidence(
            policyIssuer: "serviceProvider",
            accessSubject: "accessSubject",
            serviceProvider: "serviceProvider",
            resourceType: "resourceType",
            resourceIdentifier: "resourceIdentifier",
            action: "action");

        var permit = _authorizationRegistryService.VerifyDelegationEvidencePermit(
            fakeDelegationEvidence,
            "serviceProvider",
            "accessSubject",
            "serviceProvider",
            "resourceType",
            "resourceIdentifier",
            "action");

        permit.Should().BeTrue();
    }

    [Fact]
    public void VerifyDelegationEvidencePermit_InvalidPolicyIssuer_ShouldFail()
    {
        var fakeDelegationEvidence = CreateFakeDelegationEvidence();

        var permit = _authorizationRegistryService.VerifyDelegationEvidencePermit(
            fakeDelegationEvidence,
            "invalidPolicyIssuer",
            fakeDelegationEvidence.Target.AccessSubject,
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Environment.ServiceProviders[0],
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Resource.Type,
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Resource.Identifiers[0],
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Actions[0]);

        permit.Should().BeFalse();
    }

    [Fact]
    public void VerifyDelegationEvidencePermit_InvalidAccessSubject_ShouldFail()
    {
        var fakeDelegationEvidence = CreateFakeDelegationEvidence();

        var permit = _authorizationRegistryService.VerifyDelegationEvidencePermit(
            fakeDelegationEvidence,
            fakeDelegationEvidence.PolicyIssuer,
            "invalidAccessSubject",
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Environment.ServiceProviders[0],
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Resource.Type,
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Resource.Identifiers[0],
            fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Actions[0]);

        permit.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyDelegationTokenPermit_ValidToken_ShouldReturnTrue()
    {
        var fakeDelegationEvidence = CreateFakeDelegationEvidence(
            policyIssuer: "validPolicyIssuer",
            accessSubject: "validAccessSubject",
            serviceProvider: "validServiceProvider",
            resourceType: "validResourceType",
            resourceIdentifier: "validResourceIdentifier",
            action: "validAction");
        var fakeDelegationToken = CreateFakeDelegationToken(fakeDelegationEvidence);

        var result = await _authorizationRegistryService.VerifyDelegationTokenPermit(
            fakeDelegationToken,
            _options.Value.ClientId,
            ["validPolicyIssuer"],
            ["validAccessSubject"],
            ["validServiceProvider"],
            ["validResourceType"],
            ["validResourceIdentifier"],
            ["validAction"]);

        result.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyDelegationTokenPermit_InvalidTokenIssuer_ShouldReturnFalse()
    {
        var fakeDelegationEvidence = CreateFakeDelegationEvidence();
        var fakeDelegationToken = CreateFakeDelegationToken(fakeDelegationEvidence);

        var result = await _authorizationRegistryService.VerifyDelegationTokenPermit(
            fakeDelegationToken,
            "invalidTokenIssuer",
            [fakeDelegationEvidence.PolicyIssuer],
            [fakeDelegationEvidence.Target.AccessSubject],
            [fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Environment.ServiceProviders[0]],
            [fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Resource.Type],
            [fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Resource.Identifiers[0]],
            [fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Actions[0]]);

        result.Should().BeFalse();
    }

    [Fact]
    public async Task VerifyDelegationTokenPermit_MismatchedPolicyIssuer_ShouldReturnFalse()
    {
        var fakeDelegationEvidence = CreateFakeDelegationEvidence();
        var fakeDelegationToken = CreateFakeDelegationToken(fakeDelegationEvidence);

        var result = await _authorizationRegistryService.VerifyDelegationTokenPermit(
            fakeDelegationToken,
            _options.Value.ClientId,
            ["mismatchedPolicyIssuer"],
            [fakeDelegationEvidence.Target.AccessSubject],
            [fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Environment.ServiceProviders[0]],
            [fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Resource.Type],
            [fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Resource.Identifiers[0]],
            [fakeDelegationEvidence.PolicySets[0].Policies[0].Target.Actions[0]]);

        result.Should().BeFalse();
    }

    [Theory]
    [InlineData("validPolicyIssuer", "validAccessSubject", "validServiceProvider", "validResourceType", "validResourceIdentifier", "validAction", true)]
    [InlineData("invalidPolicyIssuer", "validAccessSubject", "validServiceProvider", "validResourceType", "validResourceIdentifier", "validAction", false)]
    [InlineData("validPolicyIssuer", "invalidAccessSubject", "validServiceProvider", "validResourceType", "validResourceIdentifier", "validAction", false)]
    [InlineData("validPolicyIssuer", "validAccessSubject", "invalidServiceProvider", "validResourceType", "validResourceIdentifier", "validAction", false)]
    [InlineData("validPolicyIssuer", "validAccessSubject", "validServiceProvider", "invalidResourceType", "validResourceIdentifier", "validAction", false)]
    [InlineData("validPolicyIssuer", "validAccessSubject", "validServiceProvider", "validResourceType", "invalidResourceIdentifier", "validAction", false)]
    [InlineData("validPolicyIssuer", "validAccessSubject", "validServiceProvider", "validResourceType", "validResourceIdentifier", "invalidAction", false)]
    public async Task VerifyDelegationTokenPermit_VariousConditions_ShouldReturnExpectedResult(
        string policyIssuer,
        string accessSubject,
        string serviceProvider,
        string resourceType,
        string resourceIdentifier,
        string action,
        bool expectedResult)
    {
        var fakeDelegationEvidence = CreateFakeDelegationEvidence(
        policyIssuer: "validPolicyIssuer",
        accessSubject: "validAccessSubject",
        serviceProvider: "validServiceProvider",
        resourceType: "validResourceType",
        resourceIdentifier: "validResourceIdentifier",
        action: "validAction");
        var fakeDelegationToken = CreateFakeDelegationToken(fakeDelegationEvidence);

        var result = await _authorizationRegistryService.VerifyDelegationTokenPermit(
            fakeDelegationToken,
            _options.Value.ClientId,
            [policyIssuer],
            [accessSubject],
            [serviceProvider],
            [resourceType],
            [resourceIdentifier],
            [action]);

        result.Should().Be(expectedResult);
    }

    [Theory]
    [InlineData("validPolicyIssuer", "validAccessSubject", "validServiceProvider", "validResourceType", "validResourceIdentifier", "validAction", true)]
    [InlineData("invalidPolicyIssuer", "validAccessSubject", "validServiceProvider", "validResourceType", "validResourceIdentifier", "validAction", false)]
    [InlineData("validPolicyIssuer", "invalidAccessSubject", "validServiceProvider", "validResourceType", "validResourceIdentifier", "validAction", false)]
    [InlineData("validPolicyIssuer", "validAccessSubject", "invalidServiceProvider", "validResourceType", "validResourceIdentifier", "validAction", false)]
    [InlineData("validPolicyIssuer", "validAccessSubject", "validServiceProvider", "invalidResourceType", "validResourceIdentifier", "validAction", false)]
    [InlineData("validPolicyIssuer", "validAccessSubject", "validServiceProvider", "validResourceType", "invalidResourceIdentifier", "validAction", false)]
    [InlineData("validPolicyIssuer", "validAccessSubject", "validServiceProvider", "validResourceType", "validResourceIdentifier", "invalidAction", false)]
    public void VerifyDelegationEvidencePermit_VariousConditions_ShouldReturnExpectedResult(
    string policyIssuer,
    string accessSubject,
    string serviceProvider,
    string resourceType,
    string resourceIdentifier,
    string action,
    bool expectedResult)
    {
        var fakeDelegationEvidence = CreateFakeDelegationEvidence(
            policyIssuer: "validPolicyIssuer",
            accessSubject: "validAccessSubject",
            serviceProvider: "validServiceProvider",
            resourceType: "validResourceType",
            resourceIdentifier: "validResourceIdentifier",
            action: "validAction");

        var result = _authorizationRegistryService.VerifyDelegationEvidencePermit(
            fakeDelegationEvidence,
            policyIssuer,
            accessSubject,
            serviceProvider,
            resourceType,
            resourceIdentifier,
            action);

        result.Should().Be(expectedResult);
    }

    private string CreateFakeDelegationToken(DelegationEvidence delegationEvidence)
    {
        var claims = new List<Claim>
        {
            new("delegationEvidence", JsonSerializer.Serialize(delegationEvidence), JsonClaimValueTypes.Json),
        };
        return _clientAssertionCreator.CreateToken(_options.Value.ClientId, claims);
    }

    private static DelegationEvidence CreateFakeDelegationEvidence(
        string policyIssuer = "defaultPolicyIssuer",
        string accessSubject = "defaultAccessSubject",
        string serviceProvider = "defaultServiceProvider",
        string resourceType = "defaultResourceType",
        string resourceIdentifier = "defaultResourceIdentifier",
        string action = "defaultAction",
        bool invalidLifetime = false)
    {
        var serviceProviderEnvironmentFaker = new Faker<ServiceProviderEnvironment>()
            .CustomInstantiator(f => new ServiceProviderEnvironment(
                new List<string> { serviceProvider }.AsReadOnly()));

        var resourceFaker = new Faker<Resource>()
            .CustomInstantiator(f => new Resource(
                resourceType,
                new List<string> { resourceIdentifier }.AsReadOnly(),
                new List<string> { action }.AsReadOnly()));

        var resourceTargetFaker = new Faker<ResourceTarget>()
            .CustomInstantiator(f => new ResourceTarget(
                resourceFaker.Generate(),
                serviceProviderEnvironmentFaker.Generate(),
                new List<string> { action }.AsReadOnly()));

        var ruleFaker = new Faker<Rule>()
            .CustomInstantiator(f => new Rule("Permit"));

        var policyFaker = new Faker<Policy>()
            .CustomInstantiator(f => new Policy(
                resourceTargetFaker.Generate(),
                new List<Rule> { ruleFaker.Generate() }.AsReadOnly()));

        var licenseEnvironmentFaker = new Faker<LicenseEnvironment>()
            .CustomInstantiator(f => new LicenseEnvironment(
                new List<string> { "defaultLicenseEnvironment" }.AsReadOnly()));

        var licenseTargetFaker = new Faker<LicenseTarget>()
            .CustomInstantiator(f => new LicenseTarget(
                licenseEnvironmentFaker.Generate()));

        var policySetFaker = new Faker<PolicySet>()
            .CustomInstantiator(f => new PolicySet(
                1,
                licenseTargetFaker.Generate(),
                new List<Policy> { policyFaker.Generate() }.AsReadOnly()));

        var accessSubjectTargetFaker = new Faker<AccessSubjectTarget>()
            .CustomInstantiator(f => new AccessSubjectTarget(accessSubject));

        var nbf = DateTimeOffset.UtcNow.AddSeconds(-10).ToUnixTimeSeconds();
        if (invalidLifetime) nbf = DateTimeOffset.UtcNow.AddSeconds(10).ToUnixTimeSeconds();

        var delegationEvidenceFaker = new Faker<DelegationEvidence>()
            .CustomInstantiator(f => new DelegationEvidence(
                nbf,
                DateTimeOffset.UtcNow.AddSeconds(10).ToUnixTimeSeconds(),
                policyIssuer,
                accessSubjectTargetFaker.Generate(),
                new List<PolicySet> { policySetFaker.Generate() }.AsReadOnly()));

        return delegationEvidenceFaker.Generate();
    }
}
