namespace HashGate.AspNetCore;

/// <summary>
/// Represents a provider for retrieving the shared HMAC secret associated with a client identifier.
/// </summary>
/// <remarks>
/// <para>
/// Implementations of this interface are responsible for securely supplying the HMAC secret
/// for a given client. The secret is used to validate and generate HMAC signatures for authentication.
/// </para>
/// <para>
/// The provider should ensure that secrets are retrieved securely and handle cases where
/// a client identifier is not found by returning <see langword="null"/> or an empty string.
/// </para>
/// </remarks>
public interface IHmacKeyProvider
{
    /// <summary>
    /// Asynchronously retrieves the HMAC secret for the specified client identifier.
    /// </summary>
    /// <param name="client">
    /// The client identifier whose HMAC secret is to be retrieved. Must not be <see langword="null"/> or empty.
    /// </param>
    /// <param name="cancellationToken">
    /// A token that can be used to request cancellation of the asynchronous operation.
    /// The default value is <see cref="CancellationToken.None"/>.
    /// </param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> representing the asynchronous operation.
    /// The result contains the HMAC secret as a <see cref="string"/>,
    /// or <see langword="null"/> if the client identifier is not found.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="client"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="client"/> is empty or contains only whitespace characters.
    /// </exception>
    ValueTask<string?> GetSecretAsync(string client, CancellationToken cancellationToken = default);
}
