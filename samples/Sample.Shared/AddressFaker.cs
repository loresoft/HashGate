using Bogus;

namespace Sample.Shared;

public class AddressFaker : Faker<Address>
{
    public AddressFaker()
    {
        RuleFor(p => p.Line1, f => f.Address.StreetAddress());
        RuleFor(p => p.Line2, f => f.Address.SecondaryAddress());
        RuleFor(p => p.City, f => f.Address.City());
        RuleFor(p => p.State, f => f.Address.State());
        RuleFor(p => p.ZipCode, f => f.Address.ZipCode());
    }

    private static readonly Lazy<AddressFaker> _instance = new();

    public static AddressFaker Instance => _instance.Value;
}
