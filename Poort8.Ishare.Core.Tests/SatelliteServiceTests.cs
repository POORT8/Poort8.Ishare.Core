using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Poort8.Ishare.Core.Models;

namespace Poort8.Ishare.Core.Tests;
public class SatelliteServiceTests
{
    private readonly ServiceProvider _serviceProvider;

    public SatelliteServiceTests()
    {
        var services = new ServiceCollection();

        var config = new ConfigurationBuilder()
            .AddUserSecrets<SatelliteServiceTests>()
            .Build();

        services.AddIshareCoreServices(config);

        services.AddOptions<IshareCoreOptions>()
            .Bind(config.GetRequiredSection("IshareCoreOptionsSatelliteService"))
            .ValidateDataAnnotations();

        _serviceProvider = services.BuildServiceProvider();
    }

    [Fact]
    public async void GetAccessTokenAtPartyThrowsSatelliteException()
    {
        var options = _serviceProvider.GetRequiredService<IOptions<IshareCoreOptions>>();
        var accessTokenService = _serviceProvider.GetRequiredService<IAccessTokenService>();

        var tokenUrl = $"{options.Value.SatelliteUrl}/connect/token";
        Func<Task> act = () => accessTokenService.GetAccessTokenAtParty(options.Value.SatelliteId, tokenUrl);

        await act.Should()
            .ThrowAsync<HttpRequestException>();
    }

    [Fact]
    public async Task GetValidTrustedListThrowsSatelliteException()
    {
        var satelliteService = _serviceProvider.GetRequiredService<ISatelliteService>();

        Func<Task> act = satelliteService.GetValidTrustedList;

        await act.Should()
            .ThrowAsync<SatelliteException>()
            .WithMessage("Satellite exception - HttpRequestException - Could not get access token from satellite: *");
    }

    [Fact]
    public async Task GetVerifyPartyThrowsSatelliteException()
    {
        var satelliteService = _serviceProvider.GetRequiredService<ISatelliteService>();
        var options = _serviceProvider.GetRequiredService<IOptions<IshareCoreOptions>>();

        Func<Task> act = () => satelliteService.VerifyParty(
            options.Value.SatelliteId,
            "145dd7c41a2f9b989f16f1250c5a9291094c300590db01903efe1fb1de651b48");

        await act.Should()
            .ThrowAsync<SatelliteException>()
            .WithMessage("Satellite exception - HttpRequestException - Could not get access token from satellite: *");
    }
}
