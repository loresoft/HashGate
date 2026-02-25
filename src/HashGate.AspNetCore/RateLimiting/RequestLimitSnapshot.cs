using System.Runtime.InteropServices;

namespace HashGate.AspNetCore.RateLimiting;

/// <summary>Resolved rate limit configuration for a specific client.</summary>
public record RequestLimitSnapshot
{
    /// <summary>Global limit applied across all endpoints.</summary>
    public required RequestLimit Global { get; init; }

    /// <summary>Per-endpoint limit; each endpoint maintains its own independent token bucket.</summary>
    public required RequestLimit Endpoint { get; init; }

    /// <summary>Deterministic version derived from content; changes trigger limiter recreation.</summary>
    public int Version => ComputeVersion(Global, Endpoint);

    private static int ComputeVersion(RequestLimit global, RequestLimit endpoint)
    {
        uint hash = 2166136261u;
        const uint prime = 16777619u;

        Span<RequestLimit> limits = [global, endpoint];
        foreach (var b in MemoryMarshal.AsBytes((ReadOnlySpan<RequestLimit>)limits))
            hash = (hash ^ b) * prime;

        return (int)hash;
    }
}
