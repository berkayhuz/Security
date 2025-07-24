namespace Security.Messaging;

/// <summary>
///     Contains constant settings used when creating the <c>X‑Messaging‑Token</c> that
///     travels with every internal bus message.
/// </summary>
/// <remarks>
/// <para>
///     <strong>Audience</strong> – A fixed string (<c>"internal-bus"</c>) that all
///     consuming services validate against to ensure the token was issued for internal
///     messaging, not for a public API or different communication channel.
/// </para>
/// <para>
///     <strong>Lifetime</strong> – Hard‑coded to <c>3 minutes</c>. This strikes a balance
///     between security (short enough to reduce replay‑attack window) and resilience
///     (long enough for typical message delays or retries).  If you change this value,
///     remember to update the validation parameters in
///     <see cref="MessagingTokenValidator"/> accordingly.
/// </para>
/// </remarks>
public static class MessagingTokenDefaults
{
    /// <summary>
    ///   Audience claim that every internal messaging token is issued for.  Must match the
    ///   <c>ValidAudience</c> field in the token‑validation parameters on the consumer side.
    /// </summary>
    public const string Audience = "internal-bus";

    /// <summary>
    ///   Default validity period for a messaging token.
    /// </summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(3);
}
