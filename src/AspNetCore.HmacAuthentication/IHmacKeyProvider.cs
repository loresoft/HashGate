namespace AspNetCore.HmacAuthentication;

/// <summary>
/// Represents a provider for retrieving the shared HMAC secret associated with a client identifier.
/// </summary>
/// <remarks>
/// Implementations of this interface are responsible for securely supplying the HMAC secret
/// for a given client. The secret is used to validate and generate HMAC signatures for authentication.
/// </remarks>
public interface IHmacKeyProvider
{
    /// <summary>
    /// Asynchronously retrieves the HMAC secret for the specified client identifier.
    /// </summary>
    /// <param name="clientId">
    /// The client identifier whose HMAC secret is to be retrieved. Must not be <c>null</c> or empty.
    /// </param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> representing the asynchronous operation. The result contains the HMAC secret as a string,
    /// or <c>null</c> or empty if the client identifier is not found.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="clientId"/> is <c>null</c>.
    /// </exception>
    ValueTask<string?> GetSecretAsync(string clientId);
}
