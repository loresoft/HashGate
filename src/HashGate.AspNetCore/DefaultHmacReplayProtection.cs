using Microsoft.Extensions.Caching.Hybrid;

namespace HashGate.AspNetCore;

/// <summary>
/// Default <see cref="IHmacReplayProtection"/> implementation backed by
/// <see cref="HybridCache"/> with automatic TTL-based expiry.
/// </summary>
/// <remarks>
/// Uses the <see cref="HybridCache"/> L1 (in-process) cache by default.
/// When a distributed cache (e.g. Redis via <c>StackExchange.Redis</c>) is registered
/// in the container, <see cref="HybridCache"/> automatically promotes it to the L2
/// backing store, extending replay protection across multiple server nodes with no
/// code changes. Each entry's lifetime mirrors the per-request tolerance window,
/// so entries are evicted exactly when the timestamp check would already reject the request.
/// </remarks>
internal sealed class DefaultHmacReplayProtection : IHmacReplayProtection
{
    private readonly HybridCache _cache;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultHmacReplayProtection"/> class.
    /// </summary>
    /// <param name="cache">The <see cref="HybridCache"/> instance used to track seen signatures.</param>
    public DefaultHmacReplayProtection(HybridCache cache)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
    }

    /// <inheritdoc />
    public async ValueTask<bool> TryStoreAsync(string signature, DateTimeOffset expiry, CancellationToken cancellationToken = default)
    {
        var ttl = expiry - DateTimeOffset.UtcNow;
        if (ttl <= TimeSpan.Zero)
            return false;

        bool isNew = false;

        // GetOrCreateAsync only invokes the factory when the key is absent.
        // Factory runs  → signature is new  → allow.
        // Factory skipped (cache hit) → signature was seen before → replay.
        await _cache.GetOrCreateAsync(
            key: signature,
            factory: _ => { isNew = true; return ValueTask.FromResult(true); },
            options: new HybridCacheEntryOptions { Expiration = ttl },
            cancellationToken: cancellationToken
        );

        return isNew;
    }
}
