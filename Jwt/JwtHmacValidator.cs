using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

using Microsoft.IdentityModel.Tokens;

using Security.Abstractions;

namespace Security.Jwt;

/// <summary>
///     Validates a JSON Web Token (JWT) that has been signed with a shared
///     <see cref="SecurityAlgorithms.HmacSha256"/> (or other HMAC) symmetric key.
/// </summary>
/// <remarks>
/// <para>
///     This validator is the building block used by the messaging layer to confirm
///     that the <c>X‑Messaging‑Token</c> attached to a message really comes from an
///     authorised internal service. It can, however, be re‑used for any scenario
///     where HMAC‑signed JWT validation is required (e.g. lightweight API access
///     tokens in systems that do not need asymmetric keys).
/// </para>
/// <para>
///     Typical lifecycle:
///     <list type="number">
///         <item>Read the shared secret from secure configuration (Key Vault, Secrets Manager, …).</item>
///         <item>Create a <see cref="TokenValidationParameters"/> instance containing the signing key,
///               issuer & audience rules, and lifetime validation settings.</item>
///         <item>Call <see cref="Validate"/> with the incoming token and those parameters.</item>
///         <item>If the token is invalid an exception is thrown; otherwise a
///               <see cref="ClaimsPrincipal"/> representing the token’s subject is returned.</item>
///     </list>
/// </para>
/// <para>
///     This class deliberately contains <strong>no</strong> caching or state; it is a thin adapter
///     around <see cref="JwtSecurityTokenHandler"/> so it can easily be mocked in unit tests.
/// </para>
/// </remarks>
public class JwtHmacValidator : ITokenValidator
{
    /// <summary>
    ///     Validates the supplied JWT string against the provided <paramref name="p"/> parameters.
    /// </summary>
    /// <param name="token">The compact‑serialised JWT (e.g. <c>eyJhbGciOi…</c>).</param>
    /// <param name="p">Validation rules including signing key, issuer, audience etc.</param>
    /// <returns>The token’s <see cref="ClaimsPrincipal"/> on success.</returns>
    /// <exception cref="SecurityTokenException">
    /// Thrown if the token fails signature, expiry, issuer or any other configured check.
    /// </exception>
    public ClaimsPrincipal Validate(string token, TokenValidationParameters p)
        => new JwtSecurityTokenHandler().ValidateToken(token, p, out _);
}
