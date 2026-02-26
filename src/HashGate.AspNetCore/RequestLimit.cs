namespace HashGate.AspNetCore;

/// <summary>
/// Defines the token-bucket rate limit for a client.
/// </summary>
/// <param name="RequestsPerPeriod">
/// Number of tokens replenished each <see cref="RequestLimitOptions.Period"/>.
/// Also sets the steady-state throughput rate.
/// </param>
/// <param name="BurstFactor">
/// Multiplier applied to <see cref="RequestsPerPeriod"/> to set the bucket ceiling:
/// <c>TokenLimit = RequestsPerPeriod × BurstFactor</c>.
/// A value of 1 disables bursting.
/// </param>
public readonly record struct RequestLimit(int RequestsPerPeriod, int BurstFactor);
