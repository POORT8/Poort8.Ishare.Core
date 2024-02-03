using Bogus;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Poort8.Ishare.Core.Models;

namespace Poort8.Ishare.Core.Tests;

internal class FakeSatelliteService : ISatelliteService
{
    private readonly IOptions<IshareCoreOptions> _options;

    public FakeSatelliteService()
    {
        _options = Fixtures.GetCertificateTestOptions();
    }

    public Task<IEnumerable<TrustedListAuthority>> GetValidTrustedList()
    {
        var certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _options);
        var rootCertificate = certificateProvider.GetChain().ChainElements.Last().Certificate;

        var trustedList = new List<TrustedListAuthority>()
        {
            new(rootCertificate.Subject, CertificateProvider.GetSha256Thumbprint(rootCertificate), "valid", "granted"),
            new("C = NL,O = TEST Staat der Nederlanden,CN = TEST Staat der Nederlanden Root CA - G3", "D3CDDA4BEBBBF61A4F9BC4AB6B2AEEFE88A496B6", "valid", "granted")
        };

        return Task.FromResult(trustedList.AsEnumerable());
    }

    public Task<PartyInfo> VerifyParty(string partyId, string certificateSubject, string certificateThumbprint)
    {
        var adherenceFaker = new Faker<Adherence>()
            .CustomInstantiator(f => new Adherence(
                f.Lorem.Word(),
                f.Date.Past(),
                f.Date.Future()
            ));

        var additionalInfoFaker = new Faker<AdditionalInfo>()
            .CustomInstantiator(f => new AdditionalInfo(
                f.Lorem.Paragraph(),
                f.Internet.Url(),
                f.Internet.Url(),
                f.Phone.PhoneNumber(),
                f.Internet.Email(),
                f.Lorem.Word(),
                new List<object>(),
                new List<object>(),
                f.Lorem.Word()
            ));

        var agreementFaker = new Faker<Agreement>()
            .CustomInstantiator(f => new Agreement(
                f.Lorem.Word(),
                f.Lorem.Sentence(),
                f.Lorem.Word(),
                f.Date.Past(),
                f.Date.Future(),
                f.Lorem.Word(),
                f.Lorem.Word(),
                f.Random.String(),
                f.Lorem.Sentence(),
                f.Lorem.Word()
            ));

        var certificateFaker = new Faker<Certificate>()
            .CustomInstantiator(f => new Certificate(
                f.Lorem.Word(),
                f.Lorem.Word(),
                f.Date.Past(),
                f.Lorem.Word(),
                f.Lorem.Word()
            ));

        var certificationFaker = new Faker<Certification>()
            .CustomInstantiator(f => new Certification(
                f.Lorem.Word(),
                f.Date.Past(),
                f.Date.Future(),
                f.Random.Int(0, 1)
            ));

        var roleObjectFaker = new Faker<RoleObject>()
            .CustomInstantiator(f => new RoleObject(
                f.Lorem.Word(),
                f.Date.Past(),
                f.Date.Future(),
                f.Lorem.Word(),
                f.Lorem.Word(),
                f.Lorem.Word()
            ));

        var authregisteryFaker = new Faker<Authregistery>()
            .CustomInstantiator(f => new Authregistery(
                f.Lorem.Word(),
                f.Random.String(),
                f.Internet.Url(),
                f.Random.String(),
                f.Lorem.Sentence()
            ));

        var sporFaker = new Faker<Spor>()
            .CustomInstantiator(f => new Spor(
                f.Lorem.Word()
            ));

        var partyInfoFaker = new Faker<PartyInfo>()
            .CustomInstantiator(f => new PartyInfo(
                f.Random.String(),
                f.Company.CompanyName(),
                f.Internet.Url(),
                f.Random.String(),
                adherenceFaker.Generate(),
                additionalInfoFaker.Generate(),
                new List<Agreement> { agreementFaker.Generate() },
                new List<Certificate> { certificateFaker.Generate() },
                new List<Certification> { certificationFaker.Generate() },
                new List<RoleObject> { roleObjectFaker.Generate() },
                new List<Authregistery> { authregisteryFaker.Generate() },
                sporFaker.Generate()
            ));

        var fakePartyInfo = partyInfoFaker.Generate();
        return Task.FromResult(fakePartyInfo);
    }
}
