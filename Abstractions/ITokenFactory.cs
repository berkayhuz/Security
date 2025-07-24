using Security.Models;

namespace Security.Abstractions;

/// <summary>
///     Defines a factory that creates signed security tokens &ndash; typically JSON
///     Web Tokens (JWT) &ndash; used for authenticating requests or messages that
///     travel between micro‑services.
/// </summary>
/// <remarks>
/// <para>
///     The <c>Security</c> package separates token concerns into two core
///     abstractions:
///     <list type="bullet">
///         <item><description>
///             <see cref="ITokenFactory"/> – responsible for <em>issuing</em> (creating)
///             tokens.
///         </description></item>
///         <item><description>
///             <see cref="ITokenValidator"/> – responsible for <em>verifying</em> tokens.
///         </description></item>
///     </list>
/// </para>
/// <para>
///     A concrete implementation (e.g., <c>JwtHmacFactory</c>) will use a signing
///     algorithm such as <c>HMAC‑SHA‑256</c> or <c>RSA‑SHA‑256</c> to return a string
///     representation of the generated token.
/// </para>
/// </remarks>
public interface ITokenFactory
{
    /// <summary>
    ///     Creates a token using the supplied <paramref name="descriptor"/> which
    ///     defines issuer, audience, lifetime and custom claims.
    /// </summary>
    /// <param name="descriptor">
    ///     Structured data that describes how the resulting token should be
    ///     populated (see <see cref="TokenDescriptor"/>).
    /// </param>
    /// <returns>A signed token ready to be sent to another service.</returns>
    string Create(TokenDescriptor descriptor);
}
