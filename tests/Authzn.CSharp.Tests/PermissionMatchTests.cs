using System.Threading.Tasks;
using Xunit;

namespace Authzn.CSharp.Tests;

public class PermissionMatchTests
{
    [Theory]
    [InlineData("invoices:approve", "invoices:approve")]
    [InlineData("invoices:approve", "invoices:*")]
    [InlineData("invoices:approve", "*:approve")]
    [InlineData("invoices:approve", "*:*")]
    [InlineData("invoices:approve", "*")]
    [InlineData("billing:invoices:approve", "billing:invoices:*")]
    public void A_grant_that_covers_the_permission(string required, string grant) =>
        Assert.True(Permission.Matches(required, grant));

    [Theory]
    [InlineData("invoices:approve", "invoices:read")]
    [InlineData("invoices:approve", "orders:approve")]
    [InlineData("invoices:approve", "Invoices:approve")]
    [InlineData("billing:invoices:approve", "invoices:*")]
    public void A_grant_that_does_not(string required, string grant) =>
        Assert.False(Permission.Matches(required, grant));

    [Fact]
    public void A_wildcard_on_the_required_side_is_not_a_permission()
    {
        // Permission.TryParse rejects "invoices:*", so Matches(string, string) returns false for
        // every grant, even "*".
        Assert.False(Permission.Matches("invoices:*", "invoices:approve"));
        Assert.False(Permission.Matches("invoices:*", "*"));
    }

    [Theory]
    [InlineData("", "invoices:*")]
    [InlineData("invoices:approve", "")]
    public void Text_that_is_not_a_permission_matches_nothing(string required, string grant) =>
        Assert.False(Permission.Matches(required, grant));

    [Theory]
    [InlineData("invoices:approve", "invoices:*")]
    [InlineData("invoices:approve", "*")]
    [InlineData("invoices:approve", "invoices:read")]
    [InlineData("billing:invoices:approve", "invoices:*")]
    public async Task The_decision_is_the_one_the_engine_makes(string required, string grant)
    {
        var auth = new AuthorizationBuilder()
            .AddRole("r", "R", r => r.GrantEverywhere(grant))
            .Assign("alice", "r")
            .Build();

        var decision = await auth.AuthorizeAsync("alice", required);

        Assert.Equal(decision.IsAllowed, Permission.Matches(Permission.Parse(required), PermissionPattern.Parse(grant)));
    }
}
