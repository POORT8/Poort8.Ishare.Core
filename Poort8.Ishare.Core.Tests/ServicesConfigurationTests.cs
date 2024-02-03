using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Poort8.Ishare.Core.Tests;
public class ServicesConfigurationTests
{
    [Fact]
    public void ServicesConfigurationOptionsShouldSucceed()
    {
        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.Tests.json")
            .Build();

        var services = new ServiceCollection();

        services.AddIshareCoreServices(config);

        var serviceProvider = services.BuildServiceProvider();

        var options = serviceProvider.GetRequiredService<IOptions<IshareCoreOptions>>();

        options.Should().NotBeNull();
        options.Value.Should().BeOfType<IshareCoreOptions>();
    }
}
