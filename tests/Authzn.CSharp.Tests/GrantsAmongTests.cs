using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Authzn.CSharp;
using Xunit;

namespace Authzn.CSharp.Tests;

public class GrantsAmongTests
{
    private static readonly Dictionary<string, string> Billing = new() { ["database"] = "billing" };

    private static Authorizer AdminAndApprover() =>
        new AuthorizationBuilder()
            .AddRole("admin", "Administrator", r => r.GrantEverywhere("*:*"))
            .AddRole("approver", "Approver", r => r.GrantEverywhere("invoices:approve"))
            .AddRole("invoicer", "Invoicer", r => r.Grant("invoices:*", ("database", new ScopeValue.Literal("billing"))))
            .Assign("alice", "admin")
            .Assign("bob", "approver")
            .Assign("bob", "invoicer")
            .Assign("carol", "admin")
            .Assign("carol", "approver")
            .Build();

    [Fact]
    public async Task An_administrator_holds_every_permission_through_a_wildcard()
    {
        var sources = await AdminAndApprover().GrantsAmongAsync("alice", ["invoices:approve"], Billing);

        var only = Assert.Single(sources["invoices:approve"]);
        Assert.Equal(new RoleRef("admin"), only.Role);
        Assert.True(only.IsWildcard);
    }

    [Fact]
    public async Task A_role_that_names_the_permission_is_not_a_wildcard()
    {
        var sources = await AdminAndApprover().GrantsAmongAsync("bob", ["invoices:approve", "invoices:read"], Billing);

        Assert.Equal(
            [("approver", false), ("invoicer", true)],
            sources["invoices:approve"].Select(s => (s.Role.Value, s.IsWildcard)).OrderBy(s => s.Value));

        Assert.Equal(
            [("invoicer", true)],
            sources["invoices:read"].Select(s => (s.Role.Value, s.IsWildcard)));
    }

    [Fact]
    public async Task An_administrator_who_also_holds_a_named_grant_has_both()
    {
        var sources = await AdminAndApprover().GrantsAmongAsync("carol", ["invoices:approve"]);

        Assert.Equal(["admin", "approver"], sources["invoices:approve"].Select(s => s.Role.Value).OrderBy(r => r));
        Assert.Contains(sources["invoices:approve"], s => !s.IsWildcard);
    }

    [Fact]
    public async Task The_keys_equal_AllowedAmongAsync()
    {
        var auth = AdminAndApprover();
        string[] candidates = ["invoices:approve", "invoices:read", "orders:read", "not a permission"];

        foreach (var principal in new[] { "alice", "bob", "carol", "nobody" })
        {
            var allowed = await auth.AllowedAmongAsync(principal, candidates, Billing);
            var sources = await auth.GrantsAmongAsync(principal, candidates, Billing);

            Assert.Equal(allowed.OrderBy(p => p), sources.Keys.OrderBy(p => p));
        }
    }

    [Fact]
    public async Task A_wildcard_is_not_a_permission_so_it_is_not_a_key()
    {
        var sources = await AdminAndApprover().GrantsAmongAsync("alice", ["*", "*:*", "invoices:approve"]);

        Assert.Equal(["invoices:approve"], sources.Keys);
    }
}
