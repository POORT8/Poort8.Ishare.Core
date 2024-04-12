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

    [Fact]
    public async Task ValidateServiceConsumerClientAssertionValidationInvalidExpShouldFail()
    {
        var token = Fixtures.CreateServiceConsumerClientAssertionInvalidExp("serviceConsumer", "serviceProvider");

        Func<Task> act = () => _authenticationService.ValidateClientAssertion(token, "serviceConsumer");

        await act.Should().ThrowAsync<Exception>();
    }

    [Fact]
    public async Task ValidateClientAssertionExpiredShouldFail()
    {
        var token = "eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlFZFRDQ0ExMmdBd0lCQWdJVVRlQWczSEZsaUpLcXFCaHRJRER0OVRILzBSUXdEUVlKS29aSWh2Y05BUUVMQlFBd0ZERVNNQkFHQTFVRUF3d0pkR1Z6ZEM1eWIyOTBNQ0FYRFRJME1ERXlOekV3TURJeE9Gb1lEekl4TWpRd01USTNNVEF3TWpBd1dqQWZNUjB3R3dZRFZRUUREQlIwWlhOMExuTmxjblpwWTJWd2NtOTJhV1JsY2pDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTjJRRXBYMjBsZW9uaXJkZ1VSenNIejNTRE1rNFNnR3Fyb2FTZ25QaGhDa2wvVkRiaWNVRUlLTi9uTWo4T2xRMVcxYnUzL1diM2pOWTNJS0dFMHlMQlloV0FHUExHYVRIUW80cldFa0dCUEdBek5aSDJlSy9oSTdoa01aMGxTZGRqdUJjVVkrd1lnRlo0M0QzVDlwdjlXclNXeTBvNU9CVE5FcWZtelpweDR0YVZPanRNNW9LMUJnWFQyaEkvOTBJajFWbXJvN3FMQUtBdSt1anhvK1ZpakZySENBRFMrZHY4Qk1WUFlPY3ZEWmVQUWhONGRzbmVMRVlIbTNJdXRWKzB4OGpVVGYrT1JuaDZVaHgzTk4xZkdULzBlR2R6MGgyb1IrZ0I5M2lSYk9Yc0plTTBWalNWWGlyODhLcTRFdTk4RFJjVmJYSWZJWUtiOEpRdWtTZEhNQ0F3RUFBYU9DQWJBd2dnR3NNQjBHQTFVZERnUVdCQlIrTFh1ZGh2Q05NZmJHS09oWDdERnVwWjBJampBZkJnTlZIU01FR0RBV2dCVHZxQUdvZ1dKZEZySTlxOUd2NEVNaW5jdms3REFMQmdOVkhROEVCQU1DQjRBd0V3WURWUjBsQkF3d0NnWUlLd1lCQlFVSEF3SXdnZHdHQ0NzR0FRVUZCd0VCQklIUE1JSE1NR0VHQ0NzR0FRVUZCekFCaGxWb2RIUndPaTh2Y0d0cExtTmxjblJwWm1sallYUmxkRzl2YkhNdVkyOXRMM0IxWW14cFl5OXZZM053THpGaU0yUXlOalUzWVdFeVlqSTNOVEV3WkdSaU4yRTNOMlV3TmprMVkyWTVMM1JsYzNSeWIyOTBNR2NHQ0NzR0FRVUZCekFDaGx0b2RIUndPaTh2Y0d0cExtTmxjblJwWm1sallYUmxkRzl2YkhNdVkyOXRMM0IxWW14cFl5OXBjM04xWlhJdk1XSXpaREkyTlRkaFlUSmlNamMxTVRCa1pHSTNZVGMzWlRBMk9UVmpaamt2ZEdWemRISnZiM1F1WTNKME1Ha0dBMVVkSHdSaU1HQXdYcUJjb0ZxR1dHaDBkSEE2THk5d2Eya3VZMlZ5ZEdsbWFXTmhkR1YwYjI5c2N5NWpiMjB2Y0hWaWJHbGpMMk55YkM4eFlqTmtNalkxTjJGaE1tSXlOelV4TUdSa1lqZGhOemRsTURZNU5XTm1PUzkwWlhOMGNtOXZkQzVqY213d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFJMUc4UENZWUhYV3RWQytVMWlZMzhaN0J2RVV0TU9jVnFKbDhHeW0vbDlRNWgvbHZFd2s0NDdudUZ5MVEwL1owUENRTW4rcjM1c3BrazF0VHFmcWNpVm1LUURERkVCMGN6THllQzlWeW5tdHdqMEJVdjVUK2gyMnEyajJ2NG01L244c2ZlbXBQM1puOWh3d1FHekNqRkZ4NXJZNTk1TkhYOU8yOVgzUHNoQW5jUUpIZUhJdHYrSWVneXdjSFlJdE56ZmQyMnh3TWxOMDJHMTV6emREUjVOMmR6czNhYmlOWVVqN2ZqbTVVQUs2MTF3NGF6MmVScmZYbVliWko5RG9DNkxQREF0U3pBL0svaTZXeTdkZ2FBeWpBSVdEUzduRTVCQ3RNUE0vV09YT3ZaUktsS0FBYk8xLzVUcHFXUUpHM242Sy8xS0s4blM3d0RPMWoyOEVST009IiwiTUlJREhqQ0NBZ2FnQXdJQkFnSVVXV0syb3pUODZ2Qjh3c3Q1dE4wSjY2VEN1djB3RFFZSktvWklodmNOQVFFTEJRQXdGREVTTUJBR0ExVUVBd3dKZEdWemRDNXliMjkwTUNBWERUSTBNREV5TnpFMk1EQTBNVm9ZRHpJeE1qUXdNVEF6TVRZd01EUXhXakFVTVJJd0VBWURWUVFEREFsMFpYTjBMbkp2YjNRd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURKUzBYYWZGckdWdExxVWF4VXRjMUFZMHVVSU11OENCcWtxUmx6cVlKYTNwejRmNXFhVEhCaDhRMlljRy91ekZCWjF3Rkw5Z2lRWnZrTURld3VhVVRhMjRlNDFiZnBlYlBNaThxeE5FQ2locmt1dmV5cTdFaEVHZi85MDVIUjNzcm9uMVU0eDJxQ0FvR255dG9GT3BaRGpSbkhRUDZNU1F1dUpHd2VkZEdZVlFqcU9BSk1oUW43dEZ4YW5kYW5kYmFFcVMyKzg3THA4UXUvNzRYaVQyajAyblpNbWZGNUt6enc1NGR0eTNQWFVEVitFUk1rRUdWY0RKNUlsZUMwZk4zcW9tdUtXNFlGWFh2d1pVSTJDa3k1cXNmNVV4am0rSHRHeC9VWER6U3dHYUR4UHdoNjR5TjVUOFVhejYrL25WRi8yRUtXeFFaQkdOV1JrcFlpKzQ2N0FnTUJBQUdqWmpCa01CMEdBMVVkRGdRV0JCVHZxQUdvZ1dKZEZySTlxOUd2NEVNaW5jdms3REFmQmdOVkhTTUVHREFXZ0JUdnFBR29nV0pkRnJJOXE5R3Y0RU1pbmN2azdEQU9CZ05WSFE4QkFmOEVCQU1DQVFZd0VnWURWUjBUQVFIL0JBZ3dCZ0VCL3dJQkFUQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFVKzBrUTRYbllZZ0VSVUZVNXZxeGpvY0FuMUs0R015eTdJdStWUG5nSDhBZVBnR0ZWWW9rVzBEcEdaeHdQYWg5ZTVRWlJSQUZPcllnWmNRWkl0aDIvblFJbEVGQVVsalk3ZEFYREhweituN3kzTjYxVGd2Z0tUakJZbVhxQnJYVDNXcElMTmw4NGs0WGtTcHRmWklTMnE2SnYxQytYazArTnR3S0pXQUgyaE1UL2FpK3AxNk5aSW0vYnZSU24ybzQ4WnpHV2F4YS9Kemswemo1NGFnNkNBajZtWVBmQzg0d1R3QzlkWU40WGkweDJtcEJ1aktzV3NGbmhPUVlTQURCeGpHazRrLzNlcndDWnZMSzdsWU82blZ5N0tWUk0vR0tyRDM3UGxPVGFwR0IvN2xXWHRJeGd2REJHVzJwMXZOdFZpbmZwWmxYVUFvUHE1YjhQK25nVFE9PSJdLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJzZXJ2aWNlUHJvdmlkZXIiLCJqdGkiOiIwOGFlNTkyYS1mYTRkLTQ2NjItYTliZC1kMzU2NGY5M2Y3MzIiLCJuYmYiOjE3MTIzMDUzMjcsImV4cCI6MTcxMjMwNTM1NywiaWF0IjoxNzEyMzA1MzI3LCJpc3MiOiJzZXJ2aWNlUHJvdmlkZXIiLCJhdWQiOiJzZXJ2aWNlUHJvdmlkZXIifQ.eC5uuIz_kbedJiFxiccixO0gsFoB_WMuHinnhYAkHY8DMm-2EQpH-7OMeAP__IA7A-_P8W1DIWqFx9eh5ydU9tDS0IuMX5M5NKTu1nO8l5z8lmxBtxkR7iZVZ0qlpa47Kbc5BEzELZngM44cH6HvYUMFit96WulS11NpV7htOccb_8eoT4kTssxBY-IAAs_ofFHIJiBO9oQFNRlMryNCWX__-I11ienfAAR5-0_WuFNRtxu1uPRkAx3AGyIqORUJzXn2iuyxJkF_mRADs33p5QYVRPoJpjq0kL5NT3y_O1XZkbnbF7QunZKF_JTsu1ES4_9wMg_rw5-emEspHVZhWA";

        Func<Task> act = () => _authenticationService.ValidateClientAssertion(token, "serviceProvider");

        await act.Should().ThrowAsync<Exception>();
    }
}
