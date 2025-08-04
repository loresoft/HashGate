using Microsoft.Extensions.Options;

namespace AspNetCore.HmacAuthentication.Client;

public class HmacAuthenticationHttpHandler : DelegatingHandler
{
    private readonly IOptions<HmacAuthenticationOptions> _options;

    public HmacAuthenticationHttpHandler(IOptions<HmacAuthenticationOptions> options)
    {
        _options = options;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // If the request does not already have an Authorization header, add HMAC headers
        if (request.Headers.Authorization == null)
            await request.AddHmacAuthentication(_options.Value);

        return await base.SendAsync(request, cancellationToken);
    }
}
