using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Authzn.CSharp;
using Xunit;

namespace Authzn.CSharp.Tests;

/// <summary>
/// Tests the base classes a consumer implements, which the core calls through the F# interfaces:
/// <see cref="ScopeValueResolver"/> (a <c>bool</c> Admits) and <see cref="RoleStore"/> and
/// <see cref="AssignmentStore"/> (a nullable role and an <see cref="IReadOnlyList{T}"/>, converted
/// to an F# option and list).
/// </summary>
public class BridgeTests
{
    private sealed class ConstantResolver(bool result) : ScopeValueResolver
    {
        public override ValueTask<bool> AdmitsAsync(
            PrincipalRef principal,
            string scopeKey,
            string marker,
            string requestValue,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(result);
    }

    private static AuthorizationBuilder ScopedRole(ScopeValueResolver resolver) =>
        new AuthorizationBuilder()
            .AddRole("scoped", "Scoped", r => r.Grant("docs:read", ("tenant", new ScopeValue.Marker("marker"))))
            .UseScopeResolver(resolver)
            .Assign("u", "scoped");

    [Fact]
    public async Task Resolver_returning_true_matches()
    {
        var auth = ScopedRole(new ConstantResolver(true)).Build();
        var decision = await auth.AuthorizeAsync("u", "docs:read",
            new Dictionary<string, string> { ["tenant"] = "anything" });
        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task Resolver_returning_false_does_not_match()
    {
        var auth = ScopedRole(new ConstantResolver(false)).Build();
        var decision = await auth.AuthorizeAsync("u", "docs:read",
            new Dictionary<string, string> { ["tenant"] = "anything" });
        Assert.False(decision.IsAllowed);
        Assert.Equal(new AuthorizationDecision.Denied(DenyReason.ScopeMismatch), decision);
    }

    [Fact]
    public async Task A_marker_the_resolver_does_not_admit_does_not_match_its_own_text()
    {
        var auth = ScopedRole(new ConstantResolver(false)).Build();

        // "@marker" is the text form of the grant's marker "marker".
        var decision = await auth.AuthorizeAsync("u", "docs:read",
            new Dictionary<string, string> { ["tenant"] = "@marker" });
        Assert.Equal(new AuthorizationDecision.Denied(DenyReason.ScopeMismatch), decision);
    }

    [Fact]
    public async Task Without_a_resolver_a_marker_matches_nothing()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("scoped", "Scoped", r => r.Grant("docs:read", ("tenant", new ScopeValue.Marker("marker"))))
            .Assign("u", "scoped")
            .Build();

        var decision = await auth.AuthorizeAsync("u", "docs:read",
            new Dictionary<string, string> { ["tenant"] = "@marker" });
        Assert.Equal(new AuthorizationDecision.Denied(DenyReason.ScopeMismatch), decision);
    }

    [Fact]
    public async Task DelegateScopeResolver_principal_marker()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("self", "Self", r => r.Grant("profile:edit", ("owner", ScopeValue.Principal)))
            .UseScopeResolver(new DelegateScopeResolver((principal, key, grant, req) =>
                grant == ScopeMarkers.Principal && principal.Value == req))
            .Assign("jake", "self")
            .Build();

        Assert.True((await auth.AuthorizeAsync("jake", "profile:edit",
            new Dictionary<string, string> { ["owner"] = "jake" })).IsAllowed);
        Assert.False((await auth.AuthorizeAsync("jake", "profile:edit",
            new Dictionary<string, string> { ["owner"] = "someone-else" })).IsAllowed);
    }

    private sealed class InMemoryRoleStore(params Role[] roles) : RoleStore
    {
        public override Task<Role?> GetRoleAsync(RoleRef id, CancellationToken cancellationToken) =>
            Task.FromResult(roles.FirstOrDefault(r => r.Id.Value == id.Value));
    }

    private sealed class InMemoryAssignmentStore(params Assignment[] assignments) : AssignmentStore
    {
        public override Task<IReadOnlyList<Assignment>> GetAssignmentsForPrincipalAsync(
            PrincipalRef principal,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<Assignment>>(
                assignments.Where(a => a.Principal.Value == principal.Value).ToList());
    }

    [Fact]
    public async Task Custom_stores_are_consumed_by_the_engine()
    {
        var role = Role.Define("reader", "Reader", r => r.GrantEverywhere("docs:read"));

        var auth = new AuthorizationBuilder()
            .UseRoleStore(new InMemoryRoleStore(role))
            .UseAssignmentStore(new InMemoryAssignmentStore(Assignment.Create("dana", "reader")))
            .Build();

        Assert.True((await auth.AuthorizeAsync("dana", "docs:read")).IsAllowed);
        Assert.False((await auth.AuthorizeAsync("dana", "docs:write")).IsAllowed);

        var noAssignment = await auth.AuthorizeAsync("ghost", "docs:read");
        Assert.False(noAssignment.IsAllowed);
        Assert.Equal(new AuthorizationDecision.Denied(DenyReason.NoAssignments), noAssignment);
    }
}
