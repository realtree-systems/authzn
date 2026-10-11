using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using RealTree.Authzn.CSharp;
using Xunit;

namespace RealTree.Authzn.CSharp.Tests;

/// <summary>
/// Runs scenarios 1 to 7 of samples/Authzn.Sample.CSharp/Program.cs, plus a few edge cases, through
/// the facade and asserts each decision and, for most denials, the deny reason.
/// </summary>
public class BehaviorParityTests
{
    private static Dictionary<string, string> Scope(params (string key, string value)[] pairs)
    {
        var d = new Dictionary<string, string>();
        foreach (var (key, value) in pairs)
        {
            d[key] = value;
        }

        return d;
    }

    [Fact]
    public async Task BasicRbac_allows_granted_and_denies_ungranted()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("reader", "Reader", r => r.GrantEverywhere("documents:read"))
            .Assign("alice", "reader")
            .Build();

        var allowed = await auth.AuthorizeAsync("alice", "documents:read");
        Assert.True(allowed.IsAllowed);
        Assert.Equal(new AuthorizationDecision.Allowed("reader", PermissionPattern.Parse("documents:read")), allowed);

        var denied = await auth.AuthorizeAsync("alice", "documents:delete");
        Assert.False(denied.IsAllowed);
        Assert.Equal(new AuthorizationDecision.Denied(DenyReason.NoMatchingPermission), denied);
    }

    [Fact]
    public async Task Principal_with_no_assignments_is_denied()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("reader", "Reader", r => r.GrantEverywhere("documents:read"))
            .Build();

        var decision = await auth.AuthorizeAsync("nobody", "documents:read");
        Assert.False(decision.IsAllowed);
        Assert.Equal(new AuthorizationDecision.Denied(DenyReason.NoAssignments), decision);
    }

    [Fact]
    public async Task Wildcard_matches_any_action_on_the_resource()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("docs-admin", "Docs Admin", r => r.GrantEverywhere("documents:*"))
            .Assign("bob", "docs-admin")
            .Build();

        Assert.True((await auth.AuthorizeAsync("bob", "documents:read")).IsAllowed);
        Assert.True((await auth.AuthorizeAsync("bob", "documents:delete")).IsAllowed);

        var wrongResource = await auth.AuthorizeAsync("bob", "invoices:read");
        Assert.False(wrongResource.IsAllowed);
        Assert.Equal(new AuthorizationDecision.Denied(DenyReason.NoMatchingPermission), wrongResource);
    }

    [Fact]
    public async Task Scoped_grant_matches_only_in_scope()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("tenant-reader", "Tenant Reader", r => r.Grant("documents:read", ("tenant", new ScopeValue.Literal("acme"))))
            .Assign("carol", "tenant-reader")
            .Build();

        Assert.True((await auth.AuthorizeAsync("carol", "documents:read", Scope(("tenant", "acme")))).IsAllowed);

        var mismatch = await auth.AuthorizeAsync("carol", "documents:read", Scope(("tenant", "other-corp")));
        Assert.False(mismatch.IsAllowed);
        Assert.Equal(new AuthorizationDecision.Denied(DenyReason.ScopeMismatch), mismatch);
    }

    [Fact]
    public async Task Hierarchical_resource_wildcard_matches_subactions()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("task-manager", "Task Manager", r => r.GrantEverywhere("project:task:*"))
            .Assign("dave", "task-manager")
            .Build();

        Assert.True((await auth.AuthorizeAsync("dave", "project:task:read")).IsAllowed);
        Assert.True((await auth.AuthorizeAsync("dave", "project:task:delete")).IsAllowed);
        Assert.False((await auth.AuthorizeAsync("dave", "project:read")).IsAllowed);
    }

    [Fact]
    public async Task Abac_condition_gates_on_attributes()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("approver", "Approver", r => r.GrantIf("orders:approve",
                attrs => attrs.TryGetValue("amount", out var v) && v is int amount && amount < 10_000))
            .Assign("eve", "approver")
            .Build();

        var low = await auth.AuthorizeAsync("eve", "orders:approve",
            attributes: new Dictionary<string, object> { ["amount"] = 5_000 });
        Assert.True(low.IsAllowed);

        var high = await auth.AuthorizeAsync("eve", "orders:approve",
            attributes: new Dictionary<string, object> { ["amount"] = 50_000 });
        Assert.False(high.IsAllowed);
        Assert.Equal(new AuthorizationDecision.Denied(DenyReason.AttributeEvaluationFailed), high);
    }

    [Fact]
    public async Task Abac_condition_that_throws_is_treated_as_deny()
    {
        var auth = new AuthorizationBuilder()
            // The request has no attributes, so attrs["amount"] throws KeyNotFoundException, and
            // the engine treats a condition that throws as AttributeEvaluationFailed.
            .AddRole("approver", "Approver", r => r.GrantIf("orders:approve", attrs => (int)attrs["amount"] < 10))
            .Assign("eve", "approver")
            .Build();

        var decision = await auth.AuthorizeAsync("eve", "orders:approve");
        Assert.False(decision.IsAllowed);
        Assert.Equal(new AuthorizationDecision.Denied(DenyReason.AttributeEvaluationFailed), decision);
    }

    [Fact]
    public async Task Time_window_bounds_the_assignment()
    {
        var now = DateTimeOffset.UtcNow;

        var active = new AuthorizationBuilder()
            .AddRole("contractor", "Contractor", r => r.GrantEverywhere("docs:read"))
            .AssignForWindow("frank", "contractor", now.AddHours(-1), now.AddHours(1))
            .Build();
        Assert.True((await active.AuthorizeAsync("frank", "docs:read")).IsAllowed);

        var expired = new AuthorizationBuilder()
            .AddRole("temp", "Temporary", r => r.GrantEverywhere("docs:read"))
            .AssignForWindow("grace", "temp", now.AddHours(-2), now.AddHours(-1))
            .Build();
        var decision = await expired.AuthorizeAsync("grace", "docs:read");
        Assert.False(decision.IsAllowed);
        Assert.Equal(new AuthorizationDecision.Denied(DenyReason.AssignmentNotActive), decision);
    }

    [Fact]
    public async Task Revoke_removes_access_at_runtime()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("editor", "Editor", r => r.GrantEverywhere("docs:edit"))
            .Assign("hank", "editor")
            .Build();

        Assert.True((await auth.AuthorizeAsync("hank", "docs:edit")).IsAllowed);

        auth.Revoke("hank", "editor");

        var decision = await auth.AuthorizeAsync("hank", "docs:edit");
        Assert.False(decision.IsAllowed);
        Assert.Equal(new AuthorizationDecision.Denied(DenyReason.AssignmentNotActive), decision);
    }

    [Fact]
    public async Task Add_role_and_assignment_at_runtime()
    {
        var auth = new AuthorizationBuilder().Build();

        auth.AddRole("analyst", "Analyst", r => r.GrantEverywhere("report:read"));
        auth.AddAssignment(Assignment.Create("nina", "analyst"));

        Assert.True((await auth.AuthorizeAsync("nina", "report:read")).IsAllowed);
    }

    [Fact]
    public async Task Assignments_are_checked_in_the_order_they_were_added()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("editor", "Editor", r => r.GrantEverywhere("docs:read"))
            .AddRole("reader", "Reader", r => r.GrantEverywhere("docs:read"))
            .Assign("olga", "editor")
            .Assign("olga", "reader")
            .Build();

        var decision = await auth.AuthorizeAsync("olga", "docs:read");
        Assert.Equal(new RoleRef("editor"), Assert.IsType<AuthorizationDecision.Allowed>(decision).Role);
    }

    [Fact]
    public void AddRole_rejects_a_second_role_with_the_same_id()
    {
        var builder = new AuthorizationBuilder().AddRole("editor", "Editor", r => r.GrantEverywhere("docs:read"));

        Assert.Throws<ArgumentException>(() => builder.AddRole("editor", "Editor v2", r => r.GrantEverywhere("docs:write")));
    }
}
