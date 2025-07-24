using System.Security.Claims;

using Microsoft.IdentityModel.Tokens;

namespace Security.Abstractions;

/// <summary>
///     Represents a component capable of validating JSON&nbsp;Web&nbsp;Tokens (JWT) or
///     other opaque security tokens that are exchanged between micro‑services.
/// </summary>
/// <remarks>
/// <para>
///     The <c>Security</c> building‑block defines two primary abstractions:
///     <list type="bullet">
///         <item><description><see cref="ITokenFactory"/> – creates or signs a token.</description></item>
///         <item><description><see cref="ITokenValidator"/> – proves the token is authentic and not expired.</description></item>
///     </list>
/// </para>
/// <para>
///     Implementations are protocol‑agnostic; all required rules (issuer, audience,
///     lifetime, signing‑key, etc.) are supplied via the
///     <see cref="TokenValidationParameters"/> argument.  In practice the library
///     provides two validators:
/// </para>
/// <list type="bullet">
///     <item><description><c>JwtHmacValidator</c> – validates HMAC‑signed JWTs (used for internal messaging).</description></item>
///     <item><description>Future RSA or ECDSA variants for public‑facing access tokens.</description></item>
/// </list>
/// <para>
///     Because the interface returns a <see cref="ClaimsPrincipal"/>, the consumer can
///     immediately plug the result into standard ASP.NET Core or MassTransit
///     authorization pipelines.
/// </para>
/// </remarks>
public interface ITokenValidator
{
    /// <summary>
    ///     Validates the supplied <paramref name="token"/> using the rules defined by
    ///     <paramref name="parameters"/> and returns a <see cref="ClaimsPrincipal"/>
    ///     that represents the authenticated entity.
    /// </summary>
    /// <param name="token">The encoded JWT or security token.</param>
    /// <param name="parameters">Validation rules (issuer, audience, signing key, etc.).</param>
    /// <returns>A populated <see cref="ClaimsPrincipal"/> if the token is valid.</returns>
    /// <exception cref="SecurityTokenException">Thrown when the token fails any validation rule.</exception>
    ClaimsPrincipal Validate(string token, TokenValidationParameters parameters);
}
