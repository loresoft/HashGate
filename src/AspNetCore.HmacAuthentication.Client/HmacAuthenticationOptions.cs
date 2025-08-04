using System.ComponentModel.DataAnnotations;

namespace AspNetCore.HmacAuthentication.Client;

public class HmacAuthenticationOptions
{
    public const string ConfigurationName = "HmacAuthentication";

    [Required]
    public required string Client { get; set; }

    [Required]
    public required string Secret { get; set; }

    public IReadOnlyList<string>? SignedHeaders { get; set; } = HmacAuthenticationShared.DefaultSignedHeaders;
}
