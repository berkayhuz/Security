using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

using Security.Abstractions;
using Security.Configuration;
using Security.Messaging;

namespace Security.Extensions;

/// <summary>
///     Dependency‑Injection extension methods that register all components required
///     for issuing and validating the <c>X‑Messaging‑Token</c> used in internal
///     service‑to‑service communication.
/// </summary>
/// <remarks>
/// <para>
///     Call <see cref="AddTokenServices"/> once during start‑up (after reading
///     configuration) to expose <see cref="ITokenFactory"/> and
///     <see cref="ITokenValidator"/> implementations via the container.  These
///     implementations are consumed implicitly by MassTransit send/consume
///     filters; application code never has to create or validate tokens
///     manually.
/// </para>
/// <para>
///     The method expects two configuration keys:
///     <list type="bullet">
///         <item>
///             <term><c>Messaging:SystemToken</c></term>
///             <description>
///                 A Base‑64 encoded symmetric key shared between all trusted
///                 services.  Used for HMAC signing of JWTs.
///             </description>
///         </item>
///         <item>
///             <term><c>ServiceName</c></term>
///             <description>
///                 Logical name of the current micro‑service; becomes the <c>iss</c>
///                 (issuer) claim inside generated tokens.
///             </description>
///         </item>
///     </list>
/// </para>
/// </remarks>
public static class TokenServiceCollectionExtensions
{
    /// <summary>
    ///     Registers <see cref="ITokenFactory"/> / <see cref="ITokenValidator"/> and binds
    ///     <see cref="TokenSigningOptions"/> from configuration.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to extend.</param>
    /// <param name="cfg">
    ///     The application configuration root containing <c>Messaging:SystemToken</c>
    ///     and <c>ServiceName</c> settings.
    /// </param>
    /// <returns>The same <paramref name="services"/> instance to enable chaining.</returns>
    /// <exception cref="InvalidOperationException">
    ///     Thrown when <c>Messaging:SystemToken</c> is missing or empty.
    /// </exception>
    public static IServiceCollection AddTokenServices(
        this IServiceCollection services,
        IConfiguration cfg)
    {
        // 1. Retrieve shared secret from configuration ------------------------
        var secret = cfg["Messaging:SystemToken"]
                     ?? throw new InvalidOperationException("Missing token secret");

        // 2. Build signing key -----------------------------------------------
        var keyBytes = Convert.FromBase64String(secret);
        var key = new SymmetricSecurityKey(keyBytes);

        // 3. Expose TokenSigningOptions via IOptions<TokenSigningOptions> ------
        services.Configure<TokenSigningOptions>(o =>
        {
            o.Secret = secret;
            o.ServiceName = cfg["ServiceName"] ?? "unknown-service";
        });

        // 4. Register factory & validator used by messaging filters -----------
        services.AddSingleton<ITokenFactory, MessagingTokenFactory>();
        services.AddSingleton<ITokenValidator>(sp =>
        {
            var p = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidAudience = MessagingTokenDefaults.Audience,
                IssuerSigningKey = key,
                ValidateLifetime = true
            };
            return new MessagingTokenValidator(p);
        });

        return services;
    }
}
