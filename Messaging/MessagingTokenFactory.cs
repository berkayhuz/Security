using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using Security.Abstractions;
using Security.Configuration;
using Security.Jwt;
using Security.Models;

namespace Security.Messaging;

/// <summary>
///     Generates <c>X‑Messaging‑Token</c> values that are attached to every outbound
///     message published over the service bus.  The token is a compact, HMAC‑signed JWT
///     that proves the message originates from the current micro‑service and is intended
///     for a specific destination service.
/// </summary>
/// <remarks>
/// <para>
/// The token helps enforce zero‑trust principles inside the cluster: message consumers
/// reject any payload whose signature cannot be validated with the shared signing key or
/// whose <c>iss</c>/<c>aud</c> claims do not match the expected values.
/// </para>
/// <para>
/// Lifetime is intentionally short (<see cref="MessagingTokenDefaults.Lifetime"/>) to
/// mitigate replay attacks.  Rotate <see cref="TokenSigningOptions.Secret"/> regularly and
/// redeploy services to keep the attack surface minimal.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // DI registration (Program.cs)
/// services.Configure<TokenSigningOptions>(c =>
/// {
///     c.ServiceName = "orders-service";
///     c.Secret      = Environment.GetEnvironmentVariable("MSG_TOKEN_SECRET");
/// });
/// services.AddSingleton<ITokenFactory, MessagingTokenFactory>();
/// </code>
/// </example>
public class MessagingTokenFactory : ITokenFactory
{
    private readonly JwtHmacFactory _inner;
    private readonly string _issuer;

    /// <summary>
    ///     Creates a new factory using options supplied from configuration / secrets.
    /// </summary>
    /// <param name="opt">
    ///     <see cref="TokenSigningOptions"/> resolved from the DI container; must contain
    ///     a base‑64 encoded <see cref="TokenSigningOptions.Secret"/> and the logical
    ///     <see cref="TokenSigningOptions.ServiceName"/>.
    /// </param>
    public MessagingTokenFactory(IOptions<TokenSigningOptions> opt)
    {
        var keyBytes = Convert.FromBase64String(opt.Value.Secret);
        var key = new SymmetricSecurityKey(keyBytes);

        _inner = new JwtHmacFactory(key);
        _issuer = opt.Value.ServiceName;
    }

    /// <inheritdoc />
    public string Create(TokenDescriptor d) => _inner.Create(d);

    /// <summary>
    ///     Convenience wrapper: create a token whose <c>iss</c> claim is the current
    ///     service and whose <c>aud</c> claim is <paramref name="destinationService"/>.
    /// </summary>
    /// <param name="destinationService">Target micro‑service queue prefix (kebab‑case).</param>
    /// <returns>Signed JWT string suitable for <c>X‑Messaging‑Token</c> header.</returns>
    public string CreateFor(string destinationService) =>
        _inner.Create(new TokenDescriptor(
            Issuer: _issuer,
            Audience: destinationService,
            Claims: new Dictionary<string, string>(),
            Lifetime: MessagingTokenDefaults.Lifetime));
}
