using System.Security.Claims;

using Microsoft.IdentityModel.Tokens;

using Security.Abstractions;
using Security.Jwt;

namespace Security.Messaging;

/// <summary>
///     Validates the <c>X-Messaging-Token</c> found in the headers of messages exchanged
///     between micro‑services.  The token is expected to be a short‑lived JWT signed with a
///     shared HMAC key that proves the message originated from a trusted internal service.
/// </summary>
/// <remarks>
/// <para>
///     This validator is normally registered via <c>IServiceCollection.AddTokenServices()</c>
///     and injected into the MassTransit consume pipeline through <see cref="MessageSecurityFilter{T}"/>.
///     It re‑uses <see cref="JwtHmacValidator"/> to perform the actual JWT validation while
///     supplying the pre‑configured <see cref="TokenValidationParameters"/> that specify
///     the expected issuer, audience, signing key and lifetime constraints.
/// </para>
/// <para>
///     Decision matrix:
///     <list type="bullet">
///         <item>✅ Token signature must match the HMAC key.</item>
///         <item>✅ <see cref="TokenValidationParameters.ValidateIssuer"/> is enforced.</item>
///         <item>✅ <see cref="TokenValidationParameters.ValidateAudience"/> is enforced.</item>
///         <item>✅ <see cref="TokenValidationParameters.ValidateLifetime"/> prevents replay.</item>
///     </list>
///     Any failure results in <see cref="SecurityTokenException"/> (or subclass) which the
///     pipeline converts into <see cref="UnauthorizedAccessException"/>, causing the message
///     to be rejected and—depending on retry policy—moved to the dead‑letter queue.
/// </para>
/// </remarks>
public class MessagingTokenValidator : ITokenValidator
{
    private readonly JwtHmacValidator _inner;
    private readonly TokenValidationParameters _p;

    /// <summary>
    ///     Initializes a new instance of the <see cref="MessagingTokenValidator"/> class.
    /// </summary>
    /// <param name="p">
    ///     Pre‑built validation parameters containing the signing key and the rules
    ///     (<c>Issuer</c>, <c>Audience</c>, lifetime) that incoming tokens must satisfy.
    /// </param>
    public MessagingTokenValidator(TokenValidationParameters p)
    {
        _inner = new JwtHmacValidator();
        _p = p;
    }

    /// <summary>
    ///     Validates the specified JWT and returns the associated claims principal.
    /// </summary>
    /// <param name="token">The bearer JWT extracted from the <c>X‑Messaging‑Token</c> header.</param>
    /// <param name="_">
    ///     Unused.  Present to satisfy <see cref="ITokenValidator"/> signature which allows callers
    ///     to override validation parameters per request.  This validator relies on the parameters
    ///     supplied in the constructor instead.
    /// </param>
    /// <returns>The <see cref="ClaimsPrincipal"/> represented by the token if verification succeeds.</returns>
    /// <exception cref="SecurityTokenException">Thrown when the token fails validation.</exception>
    public ClaimsPrincipal Validate(string token, TokenValidationParameters _)
        => _inner.Validate(token, _p);
}
