namespace Security.Configuration;

/// <summary>
///     Configuration object that defines how the library signs JSON Web Tokens
///     (JWT) for internal messaging. These values are populated from
///     configuration files or environment variables via
///     <see cref="Microsoft.Extensions.Options.IOptions{TOptions}"/>.
/// </summary>
/// <remarks>
/// <para>
///     <strong>Usage</strong>: The object is bound in <c>TokenServiceCollectionExtensions</c>
///     and passed to <see cref="Security.Messaging.MessagingTokenFactory"/> so that all
///     <c>X‑Messaging‑Token</c> values share the same issuer and signing key.
/// </para>
/// </remarks>
public class TokenSigningOptions
{
    /// <summary>
    ///     Logical name of the current micro‑service. Written into the <c>iss</c>
    ///     (issuer) claim of every generated token so that consuming services can
    ///     enforce strict issuer validation.
    /// </summary>
    public string ServiceName { get; set; } = default!;

    /// <summary>
    ///     Base‑64 encoded symmetric key used to sign tokens with HMAC‑SHA256.
    ///     <para>
    ///         <strong>Security Warning:</strong> Store this value in a secure
    ///         secret manager (Azure Key Vault, AWS Secrets Manager, HashiCorp
    ///         Vault, etc.). Exposure of the key compromises the integrity of
    ///         all internal messaging.
    ///     </para>
    /// </summary>
    public string Secret { get; set; } = default!;
}
