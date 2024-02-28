using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace Poort8.Ishare.Core.Tests;
public class AuthenticationServiceTests
{
    private readonly IOptions<IshareCoreOptions> _options;
    private readonly CertificateProvider _certificateProvider;
    private readonly AuthenticationService _authenticationService;
    private readonly ClientAssertionCreator _clientAssertionCreator;

    public AuthenticationServiceTests()
    {
        _options = Fixtures.GetCertificateTestOptions();
        _options.Value.ClientId = "serviceProvider";

        var fakeSatelliteService = new FakeSatelliteService();

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        _certificateProvider = new CertificateProvider(NullLogger<CertificateProvider>.Instance, _options);
        var certificateValidator = new CertificateValidator(NullLogger<CertificateValidator>.Instance, fakeSatelliteService);

        _authenticationService = new AuthenticationService(
            NullLogger<AuthenticationService>.Instance,
            _options,
            httpClientFactory,
            certificateValidator,
            fakeSatelliteService);

        _clientAssertionCreator = new ClientAssertionCreator(_options, _certificateProvider);
    }

    [Fact]
    public async Task ValidateClientAssertionShouldPass()
    {
        var token = _clientAssertionCreator.CreateClientAssertion("serviceProvider");

        //NOTE: The audience is set to "serviceProvider" since validAudience is set to _clientId in ValidateToken.
        Func<Task> act = () => _authenticationService.ValidateClientAssertion(token, "serviceProvider");

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task ValidateClientAssertionWrongClientIdHeaderShouldFail()
    {
        var token = _clientAssertionCreator.CreateClientAssertion("serviceProvider");

        Func<Task> act = () => _authenticationService.ValidateClientAssertion(token, "fail");

        await act.Should().ThrowAsync<Exception>();
    }

    [Fact]
    public async Task ValidateClientAssertionWrongAudShouldFail()
    {
        var token = _clientAssertionCreator.CreateClientAssertion("fail");

        Func<Task> act = () => _authenticationService.ValidateClientAssertion(token, "serviceProvider");

        await act.Should().ThrowAsync<Exception>();
    }

    [Fact]
    public async Task ValidateServiceConsumerClientAssertionValidationShouldPass()
    {
        var token = Fixtures.CreateServiceConsumerClientAssertion("serviceConsumer", "serviceProvider");

        Func<Task> act = () => _authenticationService.ValidateClientAssertion(token, "serviceConsumer");

        await act.Should().NotThrowAsync();
    }
}
