namespace HashGate.AspNetCore;

/// <summary>
/// Defines a contract for recording HMAC signatures to prevent replay attacks.
/// </summary>
/// <remarks>
/// The default implementation is <see cref="DefaultHmacReplayProtection"/>, backed by
/// <see cref="Microsoft.Extensions.Caching.Hybrid.HybridCache"/> and registered automatically.
/// For multi-server environments, register a distributed cache (e.g. Redis) alongside
/// <see cref="Microsoft.Extensions.Caching.Hybrid.HybridCache"/> so all nodes share the same
/// seen-signature state — no custom <see cref="IHmacReplayProtection"/> implementation required.
/// </remarks>
public interface IHmacReplayProtection
{
    /// <summary>
    /// Attempts to record a signature. Returns <see langword="true"/> if the signature was new
    /// (not previously seen within its validity window), or <see langword="false"/> if it has
    /// already been recorded, indicating a replay attack.
    /// </summary>
    /// <param name="signature">The HMAC signature string to record.</param>
    /// <param name="expiry">
    /// The absolute UTC time after which the signature would be rejected by the timestamp check
    /// anyway. Implementations use this as the eviction deadline for the stored entry.
    /// </param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
    /// <returns>
    /// <see langword="true"/> if the signature was newly recorded and the request should be allowed;
    /// <see langword="false"/> if the signature was already present and the request should be rejected.
    /// </returns>
    ValueTask<bool> TryStoreAsync(string signature, DateTimeOffset expiry, CancellationToken cancellationToken = default);
}
