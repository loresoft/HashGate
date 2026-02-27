namespace HashGate.AspNetCore;

/// <summary>
/// Provides per-client rate limit overrides for the token-bucket rate limiting middleware.
/// </summary>
/// <remarks>
/// When registered via <see cref="RequestLimitExtensions.AddHmacRateLimiter{TProvider}"/>,
/// the middleware calls <see cref="GetAsync"/> on every request to determine the effective limit
/// for the requesting client. Return <see langword="null"/> to fall back to the defaults
/// configured on <see cref="RequestLimitOptions"/>.
/// </remarks>
public interface IRequestLimitProvider
{
    /// <summary>
    /// Returns the rate limit for <paramref name="client"/>, or <see langword="null"/> if the
    /// client should use the defaults from <see cref="RequestLimitOptions"/>.
    /// </summary>
    /// <param name="client">The client identifier extracted from the HMAC Authorization header.</param>
    /// <param name="cancellationToken">A token to cancel the asynchronous operation.</param>
    Task<RequestLimit?> GetAsync(string client, CancellationToken cancellationToken = default);
}
