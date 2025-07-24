namespace Security.Models;

/// <summary>
///     Immutable value object that carries the data required by an
///     <see cref="Security.Abstractions.ITokenFactory"/> implementation to create a
///     signed security&nbsp;token (typically a JSON&nbsp;Web&nbsp;Token).
/// </summary>
/// <remarks>
/// <para>
///     The <strong>factory pattern</strong> used in the <c>Security</c> package keeps
///     token creation logic de‑coupled from the calling code.  Call‑sites simply
///     construct a <see cref="TokenDescriptor"/> with the desired parameters and
///     pass it to <c>ITokenFactory.Create</c>.  The factory turns those parameters
///     into a compact, signed string while hiding cryptographic details.
/// </para>
/// </remarks>
/// <param name="Issuer">
///     Logical name of the service that issues the token. Becomes the <c>iss</c>
///     claim inside the resulting JWT.
/// </param>
/// <param name="Audience">
///     Intended recipient of the token. Becomes the <c>aud</c> claim.
/// </param>
/// <param name="Claims">
///     Custom key/value pairs to embed as additional claims.
/// </param>
/// <param name="Lifetime">
///     How long the token should remain valid. Converted to the <c>exp</c> claim
///     when minted by the factory.
/// </param>
public readonly record struct TokenDescriptor(
    string Issuer,
    string Audience,
    IDictionary<string, string> Claims,
    TimeSpan Lifetime);
