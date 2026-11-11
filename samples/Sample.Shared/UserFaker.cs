using Bogus;

namespace Sample.Shared;

public class UserFaker : Faker<User>
{
    public UserFaker()
    {
        RuleFor(p => p.First, f => f.Name.FirstName());
        RuleFor(p => p.Last, f => f.Name.LastName());
        RuleFor(p => p.Email, f => f.Internet.Email());
    }

    private static readonly Lazy<UserFaker> _instance = new();

    public static UserFaker Instance => _instance.Value;
}
