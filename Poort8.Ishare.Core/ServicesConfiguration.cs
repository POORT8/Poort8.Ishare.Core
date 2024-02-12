using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Poort8.Ishare.Core;

public static class ServicesConfiguration
{
    public static void AddIshareCoreServices(
        this IServiceCollection services,
        IConfiguration config)
    {
        services.AddOptions<IshareCoreOptions>()
            .Bind(config.GetRequiredSection("IshareCoreOptions"))
            .ValidateDataAnnotations();

        services.AddLogging();
        services.AddHttpClient();
        services.AddLazyCache();
        services.AddSingleton<IAccessTokenService, AccessTokenService>();
        services.AddSingleton<IAuthenticationService, AuthenticationService>();
        services.AddSingleton<IAuthorizationRegistryService, AuthorizationRegistryService>();
        services.AddSingleton<ICertificateProvider, CertificateProvider>();
        services.AddSingleton<ICertificateValidator, CertificateValidator>();
        services.AddSingleton<IClientAssertionCreator, ClientAssertionCreator>();
        services.AddSingleton<ISatelliteService, SatelliteService>();
    }
}
