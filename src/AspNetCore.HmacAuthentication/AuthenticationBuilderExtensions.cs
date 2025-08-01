using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace AspNetCore.HmacAuthentication;

/// <summary>
/// Extension methods for registering HMAC authentication with the <see cref="AuthenticationBuilder"/>.
/// </summary>
/// <example>
/// <para>To add HMAC authentication in your ASP.NET Core application, use the following in <c>Program.cs</c> or <c>Startup.cs</c>:</para>
/// <code language="csharp">
/// builder.Services
///     .AddAuthentication(options => options.DefaultScheme = HmacAuthenticationOptions.DefaultScheme)
///     .AddHmacAuthentication();
/// </code>
/// <para>
/// Example <c>appsettings.json</c> configuration for default section:
/// </para>
/// <code language="json">
/// {
///   "HmacSecrets": {
///     "client1": "supersecretkey1",
///     "client2": "supersecretkey2"
///   }
/// }
/// </code>
/// </example>
public static class AuthenticationBuilderExtensions
{
    /// <summary>
    /// Adds HMAC authentication using the default <see cref="HmacKeyProvider"/> and the default scheme.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/> for chaining.</returns>
    public static AuthenticationBuilder AddHmacAuthentication(this AuthenticationBuilder builder)
        => AddHmacAuthentication<HmacKeyProvider>(builder, HmacAuthenticationOptions.DefaultScheme, null, null);

    /// <summary>
    /// Adds HMAC authentication using the default <see cref="HmacKeyProvider"/> and a custom authentication scheme.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="authenticationScheme">The authentication scheme name.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/> for chaining.</returns>
    public static AuthenticationBuilder AddHmacAuthentication(this AuthenticationBuilder builder, string authenticationScheme)
        => AddHmacAuthentication<HmacKeyProvider>(builder, authenticationScheme, null, null);

    /// <summary>
    /// Adds HMAC authentication using the default <see cref="HmacKeyProvider"/> and the default scheme, with custom options configuration.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="configureOptions">An action to configure <see cref="HmacAuthenticationOptions"/>.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/> for chaining.</returns>
    public static AuthenticationBuilder AddHmacAuthentication(this AuthenticationBuilder builder, Action<HmacAuthenticationOptions>? configureOptions)
        => AddHmacAuthentication<HmacKeyProvider>(builder, HmacAuthenticationOptions.DefaultScheme, null, configureOptions);

    /// <summary>
    /// Adds HMAC authentication using a custom <see cref="IHmacKeyProvider"/> and the default scheme.
    /// </summary>
    /// <typeparam name="TProvider">The type of the <see cref="IHmacKeyProvider"/> to use.</typeparam>
    /// <param name="builder">The authentication builder.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/> for chaining.</returns>
    public static AuthenticationBuilder AddHmacAuthentication<TProvider>(this AuthenticationBuilder builder)
        where TProvider : class, IHmacKeyProvider
        => AddHmacAuthentication<TProvider>(builder, HmacAuthenticationOptions.DefaultScheme, null, null);

    /// <summary>
    /// Adds HMAC authentication using a custom <see cref="IHmacKeyProvider"/> and a custom authentication scheme.
    /// </summary>
    /// <typeparam name="TProvider">The type of the <see cref="IHmacKeyProvider"/> to use.</typeparam>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="authenticationScheme">The authentication scheme name.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/> for chaining.</returns>
    public static AuthenticationBuilder AddHmacAuthentication<TProvider>(this AuthenticationBuilder builder, string authenticationScheme)
        where TProvider : class, IHmacKeyProvider
        => AddHmacAuthentication<TProvider>(builder, authenticationScheme, null, null);

    /// <summary>
    /// Adds HMAC authentication using a custom <see cref="IHmacKeyProvider"/> and the default scheme, with custom options configuration.
    /// </summary>
    /// <typeparam name="TProvider">The type of the <see cref="IHmacKeyProvider"/> to use.</typeparam>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="configureOptions">An action to configure <see cref="HmacAuthenticationOptions"/>.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/> for chaining.</returns>
    public static AuthenticationBuilder AddHmacAuthentication<TProvider>(this AuthenticationBuilder builder, Action<HmacAuthenticationOptions>? configureOptions)
        where TProvider : class, IHmacKeyProvider
        => AddHmacAuthentication<TProvider>(builder, HmacAuthenticationOptions.DefaultScheme, null, configureOptions);

    /// <summary>
    /// Adds HMAC authentication using a custom <see cref="IHmacKeyProvider"/>, authentication scheme, display name, and options configuration.
    /// </summary>
    /// <typeparam name="TProvider">The type of the <see cref="IHmacKeyProvider"/> to use.</typeparam>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="authenticationScheme">The authentication scheme name.</param>
    /// <param name="displayName">The display name for the authentication handler.</param>
    /// <param name="configureOptions">An action to configure <see cref="HmacAuthenticationOptions"/>.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/> for chaining.</returns>
    public static AuthenticationBuilder AddHmacAuthentication<TProvider>(this AuthenticationBuilder builder, string authenticationScheme, string? displayName, Action<HmacAuthenticationOptions>? configureOptions)
        where TProvider : class, IHmacKeyProvider
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddOptions<HmacAuthenticationOptions>(authenticationScheme);
        builder.Services.AddHmacAuthentication<TProvider>();

        return builder.AddScheme<HmacAuthenticationOptions, HmacAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
    }
}
