using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using RealTree.Authzn.CSharp;
using Xunit;

namespace RealTree.Authzn.CSharp.Tests;

public class QueryApiTests
{
    private static readonly HashSet<string> Subtree = new() { "o1", "o2" };

    // Admits "t1" for the principal marker on key "tenant", and the orgs in Subtree for the
    // hierarchy marker.
    private static bool Admits(string scopeKey, string marker, string requestValue) =>
        marker switch
        {
            ScopeMarkers.Principal when scopeKey == "tenant" => requestValue == "t1",
            ScopeMarkers.Hierarchy => Subtree.Contains(requestValue),
            _ => false,
        };

    // Admits and enumerates the values Admits describes.
    private sealed class OrgResolver : ScopeValueResolver
    {
        public override ValueTask<bool> AdmitsAsync(
            PrincipalRef principal,
            string scopeKey,
            string marker,
            string requestValue,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(Admits(scopeKey, marker, requestValue));

        public override ValueTask<ScopeValueSet?> EnumerateScopeAsync(
            PrincipalRef principal,
            string scopeKey,
            string marker,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(marker switch
            {
                ScopeMarkers.Principal when scopeKey == "tenant" => ScopeValueSet.From(new[] { "t1" }),
                ScopeMarkers.Hierarchy => ScopeValueSet.From(Subtree),
                _ => null,
            });
    }

    // Admits the same values as OrgResolver but does not override EnumerateScopeAsync, whose
    // default returns null for every marker.
    private sealed class MatchOnlyResolver : ScopeValueResolver
    {
        public override ValueTask<bool> AdmitsAsync(
            PrincipalRef principal,
            string scopeKey,
            string marker,
            string requestValue,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(Admits(scopeKey, marker, requestValue));
    }

    private static Dictionary<string, string> Scope(params (string key, string value)[] pairs) =>
        pairs.ToDictionary(p => p.key, p => p.value);

    private static IReadOnlyDictionary<string, string> OrgScope(string org) =>
        Scope(("tenant", "t1"), ("org", org));

    // Assigns alice reports:read confined by the principal marker on "tenant" and the hierarchy
    // marker on "org"; with OrgResolver the grant admits tenant "t1" and orgs "o1" and "o2".
    private static Authorizer OrgReader(ScopeValueResolver? resolver = null) =>
        new AuthorizationBuilder()
            .AddRole("org-reader", "Org Reader", r => r.Grant("reports:read", ("tenant", ScopeValue.Principal), ("org", ScopeValue.Hierarchy)))
            .UseScopeResolver(resolver ?? new OrgResolver())
            .Assign("alice", "org-reader")
            .Build();

    private static string[] SortedValues(ScopeValueSet valueSet) =>
        Assert.IsType<ScopeValueSet.Of>(valueSet).Values.OrderBy(v => v, StringComparer.Ordinal).ToArray();

    [Fact]
    public async Task FilterAsync_keeps_only_admitted_candidates()
    {
        var auth = OrgReader();

        var visible = await auth.FilterAsync("alice", "reports:read", new[] { "o1", "o2", "o3" }, OrgScope);

        Assert.Equal(new[] { "o1", "o2" }, visible);
    }

    [Fact]
    public async Task FilterAsync_returns_empty_for_an_unheld_permission()
    {
        var auth = OrgReader();

        var visible = await auth.FilterAsync("alice", "reports:write", new[] { "o1", "o2" }, OrgScope);

        Assert.Empty(visible);
    }

    [Fact]
    public async Task FilterAsync_applies_the_grants_abac_condition()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("low-only", "Low Only", r => r.GrantIf("reports:read",
                attrs => attrs.TryGetValue("level", out var v) && (string)v == "low"))
            .Assign("alice", "low-only")
            .Build();

        var visible = await auth.FilterAsync(
            "alice",
            "reports:read",
            new[] { "o1", "o2" },
            _ => (IReadOnlyDictionary<string, string>)new Dictionary<string, string>(),
            org => new Dictionary<string, object> { ["level"] = org == "o1" ? "low" : "high" });

        Assert.Equal(new[] { "o1" }, visible);
    }

    [Fact]
    public async Task FilterAsync_keeps_a_candidate_exactly_when_AuthorizeAsync_allows_it()
    {
        // In "t1" the "strict" grant's condition fails but the "open" grant allows. In "t3" only the
        // failing "strict" grant matches, and in "t2" no grant matches.
        static Dictionary<string, ScopeValue> Tenant(string tenant) => new() { ["tenant"] = new ScopeValue.Literal(tenant) };

        var auth = new AuthorizationBuilder()
            .AddRole("strict", "Strict", r => r
                .GrantIf("reports:read", _ => false, Tenant("t1"))
                .GrantIf("reports:read", _ => false, Tenant("t3")))
            .AddRole("open", "Open", r => r.Grant("reports:read", Tenant("t1")))
            .Assign("alice", "strict")
            .Assign("alice", "open")
            .Build();

        var candidates = new[] { "t1", "t2", "t3" };
        IReadOnlyDictionary<string, string> TenantOf(string tenant) => Scope(("tenant", tenant));

        var visible = await auth.FilterAsync("alice", "reports:read", candidates, TenantOf);

        var allowed = new List<string>();
        foreach (var tenant in candidates)
        {
            if ((await auth.AuthorizeAsync("alice", "reports:read", TenantOf(tenant))).IsAllowed)
            {
                allowed.Add(tenant);
            }
        }

        Assert.Equal(new[] { "t1" }, visible);
        Assert.Equal(allowed, visible);
    }

    [Fact]
    public async Task MayAnyAsync_gates_on_the_tenant()
    {
        var auth = OrgReader();

        Assert.True(await auth.MayAnyAsync("alice", "reports:read", Scope(("tenant", "t1"))));
        Assert.False(await auth.MayAnyAsync("alice", "reports:read", Scope(("tenant", "t2"))));
        Assert.False(await auth.MayAnyAsync("alice", "reports:write", Scope(("tenant", "t1"))));
    }

    [Fact]
    public async Task VisibleScopeAsync_materialises_a_restricted_constraint()
    {
        var auth = OrgReader();

        var constraint = await auth.VisibleScopeAsync("alice", "reports:read", Scope(("tenant", "t1")));

        var restricted = Assert.IsType<ScopeConstraint.Restricted>(constraint);
        var clause = Assert.Single(restricted.Clauses);
        Assert.Equal(new[] { "t1" }, SortedValues(clause["tenant"]));
        Assert.Equal(new[] { "o1", "o2" }, SortedValues(clause["org"]));
    }

    [Fact]
    public async Task VisibleScopeAsync_returns_Everything_for_an_unscoped_grant()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("super", "Super", r => r.GrantEverywhere("*:*"))
            .UseScopeResolver(new OrgResolver())
            .Assign("root", "super")
            .Build();

        var constraint = await auth.VisibleScopeAsync("root", "reports:read");

        Assert.IsType<ScopeConstraint.Everything>(constraint);
    }

    [Fact]
    public async Task VisibleScopeAsync_returns_Nothing_when_no_grant_admits()
    {
        var auth = OrgReader();

        var constraint = await auth.VisibleScopeAsync("alice", "reports:read", Scope(("tenant", "t2")));

        Assert.IsType<ScopeConstraint.Nothing>(constraint);
    }

    [Fact]
    public async Task VisibleScopeAsync_throws_when_a_relevant_marker_is_not_enumerable()
    {
        var auth = OrgReader(new MatchOnlyResolver());

        await Assert.ThrowsAsync<NotSupportedException>(() =>
            auth.VisibleScopeAsync("alice", "reports:read", Scope(("tenant", "t1"))));
    }
}
