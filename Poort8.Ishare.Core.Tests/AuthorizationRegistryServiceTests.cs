using Bogus;
using FluentAssertions;
using LazyCache;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Poort8.Ishare.Core.Models;

namespace Poort8.Ishare.Core.Tests;

public class AuthorizationRegistryServiceTests
{
    private readonly IOptions<IshareCoreOptions> _options;
    private readonly AuthorizationRegistryService _authorizationRegistryService;

    public AuthorizationRegistryServiceTests()
    {
        _options = Fixtures.GetCertificateTestOptions();
        _options.Value.ClientId = "serviceProvider";

        var fakeSatelliteService = new FakeSatelliteService();

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        var memoryCache = Substitute.For<IAppCache>();
        var certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _options);
        var certificateValidator = new CertificateValidator(NullLogger<CertificateValidator>.Instance, fakeSatelliteService);
        var clientAssertionCreator = new ClientAssertionCreator(_options, certificateProvider);

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
            clientAssertionCreator,
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

    private static DelegationEvidence CreateFakeDelegationEvidence()
    {
        var ruleFaker = new Faker<Rule>()
            .CustomInstantiator(f => new Rule("Permit"));

        var serviceProviderEnvironmentFaker = new Faker<ServiceProviderEnvironment>()
            .CustomInstantiator(f => new ServiceProviderEnvironment(
                new List<string> { f.Company.CompanyName() }.AsReadOnly()));

        var resourceFaker = new Faker<Resource>()
            .CustomInstantiator(f => new Resource(
                f.Lorem.Word(),
                new List<string> { f.Lorem.Word() }.AsReadOnly(),
                new List<string> { f.Lorem.Word() }.AsReadOnly()));

        var resourceTargetFaker = new Faker<ResourceTarget>()
            .CustomInstantiator(f => new ResourceTarget(
                resourceFaker.Generate(),
                serviceProviderEnvironmentFaker.Generate(),
                new List<string> { f.Lorem.Word() }.AsReadOnly()));

        var policyFaker = new Faker<Policy>()
            .CustomInstantiator(f => new Policy(
                resourceTargetFaker.Generate(),
                new List<Rule> { ruleFaker.Generate() }.AsReadOnly()));

        var licenseEnvironmentFaker = new Faker<LicenseEnvironment>()
            .CustomInstantiator(f => new LicenseEnvironment(
                new List<string> { f.Lorem.Word() }.AsReadOnly()));

        var licenseTargetFaker = new Faker<LicenseTarget>()
            .CustomInstantiator(f => new LicenseTarget(
                licenseEnvironmentFaker.Generate()));

        var policySetFaker = new Faker<PolicySet>()
            .CustomInstantiator(f => new PolicySet(
                f.Random.Int(0, 10),
                licenseTargetFaker.Generate(),
                new List<Policy> { policyFaker.Generate() }.AsReadOnly()));

        var accessSubjectTargetFaker = new Faker<AccessSubjectTarget>()
            .CustomInstantiator(f => new AccessSubjectTarget(f.Lorem.Word()));

        var delegationEvidenceFaker = new Faker<DelegationEvidence>()
            .CustomInstantiator(f => new DelegationEvidence(
                f.Random.Int(0, 100),
                f.Random.Int(101, 200),
                f.Company.CompanyName(),
                accessSubjectTargetFaker.Generate(),
                new List<PolicySet> { policySetFaker.Generate() }.AsReadOnly()));

        var fakeDelegationEvidence = delegationEvidenceFaker.Generate();
        return fakeDelegationEvidence;
    }
}
