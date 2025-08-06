using System.Security.Claims;

namespace HashGate.AspNetCore;

/// <summary>
/// Provides a contract for retrieving the shared HMAC secret and generating claims for a client identifier.
/// </summary>
/// <remarks>
/// Implementations are responsible for securely supplying the HMAC secret for a given client, which is used to validate and generate HMAC signatures for authentication.
/// If a client identifier is not found, the provider should return <see langword="null"/>.
/// </remarks>
public interface IHmacKeyProvider
{
    /// <summary>
    /// Asynchronously retrieves the HMAC secret associated with the specified client identifier.
    /// </summary>
    /// <param name="client">The client identifier whose HMAC secret is to be retrieved. Must not be <see langword="null"/>, empty, or whitespace.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests. The default is <see cref="CancellationToken.None"/>.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> representing the asynchronous operation. The result contains the HMAC secret as a <see cref="string"/>,
    /// or <see langword="null"/> if the client identifier is not found.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="client"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="client"/> is empty or consists only of whitespace characters.</exception>
    ValueTask<string?> GetSecretAsync(string client, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously generates a <see cref="ClaimsIdentity"/> for the specified client identifier and authentication scheme.
    /// </summary>
    /// <param name="client">The client identifier for which to generate claims. Must not be <see langword="null"/>, empty, or whitespace.</param>
    /// <param name="scheme">The authentication scheme to use for the <see cref="ClaimsIdentity"/>. If <see langword="null"/>, the default scheme is used.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests. The default is <see cref="CancellationToken.None"/>.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> representing the asynchronous operation. The result contains a <see cref="ClaimsIdentity"/> for the client.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="client"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="client"/> is empty or consists only of whitespace characters.</exception>
    ValueTask<ClaimsIdentity> GenerateClaimsAsync(string client, string? scheme = null, CancellationToken cancellationToken = default);
}
