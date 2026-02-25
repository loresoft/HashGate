using System.Runtime.InteropServices;
using System.Threading.RateLimiting;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace HashGate.AspNetCore.RateLimiting;


/// <summary>Defines the token bucket rate limit for a client.</summary>
/// <param name="RequestsPerPeriod">Number of tokens replenished each <see cref="RequestLimitOptions.Period"/>.</param>
/// <param name="BurstFactor">
/// Multiplier applied to <see cref="RequestsPerPeriod"/> to set the bucket ceiling
/// (<c>TokenLimit = RequestsPerPeriod × BurstFactor</c>).
/// </param>
public readonly record struct RequestLimit(
    int RequestsPerPeriod,
    int BurstFactor
);
