using Microsoft.Extensions.DependencyInjection;

namespace AspNetCore.HmacAuthentication.Client;

public static class DependencyInjectionExtensions
{
    public static IServiceCollection AddHmacAuthentication(
        this IServiceCollection services,
        Action<HmacAuthenticationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services
            .AddOptions<HmacAuthenticationOptions>()
            .BindConfiguration(HmacAuthenticationOptions.ConfigurationName)
            .ValidateOnStart();

        if (configure != null)
            services.PostConfigure(configure);

        services.AddTransient<HmacAuthenticationHttpHandler>();

        return services;
    }
}
