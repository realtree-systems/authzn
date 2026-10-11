using System.Collections.Generic;
using System.Threading.Tasks;
using RealTree.Authzn.CSharp;
using Xunit;

namespace RealTree.Authzn.CSharp.Tests;

public class AllowedAmongTests
{
    private static readonly Dictionary<string, string> Billing = new() { ["database"] = "billing" };

    [Fact]
    public async Task AllowedAmongAsync_matches_AuthorizeAsync_per_candidate()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("invoicer", "Invoicer", r => r.GrantEverywhere("invoices:*"))
            .AddRole("approver", "Approver", r => r.Grant("*:approve", ("database", new ScopeValue.Literal("billing"))))
            .AddRole("reporter", "Reporter", r => r.Grant("reports:read", ("database", new ScopeValue.Literal("other"))))
            .Assign("alice", "invoicer")
            .Assign("alice", "approver")
            .Assign("alice", "reporter")
            .Build();

        string[] candidates = ["invoices:approve", "invoices:read", "orders:approve", "orders:read", "reports:read"];

        var held = await auth.AllowedAmongAsync("alice", candidates, Billing);

        foreach (var candidate in candidates)
        {
            var alone = await auth.AuthorizeAsync("alice", candidate, Billing);
            Assert.Equal(alone.IsAllowed, held.Contains(candidate));
        }
    }

    [Fact]
    public async Task AllowedAmongAsync_leaves_out_strings_that_are_not_permissions()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("admin", "Administrator", r => r.GrantEverywhere("*:*"))
            .Assign("alice", "admin")
            .Build();

        var held = await auth.AllowedAmongAsync("alice", ["documents:read", "not a permission", ":read", "documents:"]);

        Assert.Equal(new HashSet<string> { "documents:read" }, held);
    }

    [Fact]
    public async Task AllowedAmongAsync_leaves_out_a_wildcard_because_a_wildcard_is_not_a_permission()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("admin", "Administrator", r => r.GrantEverywhere("*:*"))
            .Assign("alice", "admin")
            .Build();

        // Permission.TryParse rejects the patterns "*" and "*:*", and AllowedAmongAsync leaves out
        // a string that does not parse.
        var held = await auth.AllowedAmongAsync("alice", ["*", "*:*", "invoices:approve"]);

        Assert.Equal(new HashSet<string> { "invoices:approve" }, held);
    }

    [Fact]
    public async Task AllowedAmongAsync_holds_nothing_for_a_principal_with_no_assignment()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("admin", "Administrator", r => r.GrantEverywhere("*:*"))
            .Build();

        Assert.Empty(await auth.AllowedAmongAsync("nobody", ["documents:read"]));
    }
}
