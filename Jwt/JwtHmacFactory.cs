using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

using Microsoft.IdentityModel.Tokens;

using Security.Abstractions;
using Security.Models;

namespace Security.Jwt;

/// <summary>
///     Generates compact JSON Web Tokens (JWT) signed with a symmetric HMAC key.
///     Used by internal libraries to create both access‑tokens and bus‑message
///     tokens (<c>X‑Messaging‑Token</c>). The resulting JWT is fully self‑contained
///     and can be validated with <see cref="JwtHmacValidator"/>.
/// </summary>
/// <remarks>
/// <para>
///     Typical usage inside a send‑filter:
///     <code>
///     var factory = sp.GetRequiredService&lt;ITokenFactory&gt;();
///     var token = factory.Create(new TokenDescriptor(
///         Issuer: "orders-service",
///         Audience: "payments-service",
///         Claims: new Dictionary&lt;string,string&gt; { ["sub"] = userId },
///         Lifetime: TimeSpan.FromMinutes(3)));
///     ctx.Headers.Set("X-Messaging-Token", token);
///     </code>
/// </para>
/// <para>
///     <strong>Security note:</strong> Because the same HMAC key is shared by all
///     services, rotate the key periodically and keep it in a secret store such as
///     Azure Key Vault or AWS Secrets Manager. Tokens generated with the old key
///     remain valid until they expire, so short lifetimes (1‑5 minutes) are
///     recommended.
/// </para>
/// </remarks>
public class JwtHmacFactory : ITokenFactory
{
    private readonly SigningCredentials _creds;

    /// <param name="key">
    ///     Symmetric secret key (HMAC‑SHA256 by default) used to sign the JWT.
    ///     Should be at least 256 bits (32 bytes) and supplied via secure
    ///     configuration.
    /// </param>
    public JwtHmacFactory(SymmetricSecurityKey key)
        => _creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    /// <inheritdoc />
    public string Create(TokenDescriptor d)
    {
        var claims = d.Claims.Select(kv => new Claim(kv.Key, kv.Value));
        var token = new JwtSecurityToken(
            issuer: d.Issuer,
            audience: d.Audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow + d.Lifetime,
            signingCredentials: _creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
