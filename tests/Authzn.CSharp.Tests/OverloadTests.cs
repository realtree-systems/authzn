using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using RealTree.Authzn.CSharp;
using Xunit;

namespace RealTree.Authzn.CSharp.Tests;

/// <summary>
/// Calls every <c>Grant</c>, <c>GrantIf</c>, <c>GrantEverywhere</c> and <c>AuthorizeAsync</c>
/// overload, so an overload change that makes one of these calls ambiguous breaks the build.
/// </summary>
public class OverloadTests
{
    [Fact]
    public async Task Every_grant_overload_resolves_and_works()
    {
        var metadata = new GrantMetadata { Reason = "audited" };

        var auth = new AuthorizationBuilder()
            .AddRole("r", "R", b => b
                .GrantEverywhere("a:read")                                             // (string)
                .GrantEverywhere("a:meta", metadata)                                   // (string, GrantMetadata)
                .Grant("a:write", ("tenant", new ScopeValue.Literal("acme")))                                  // (string, params (string, ScopeValue)[])
                .Grant("a:list", new Dictionary<string, ScopeValue> { ["tenant"] = new ScopeValue.Literal("acme") }) // (string, IReadOnlyDictionary)
                .GrantIf("a:approve", attrs => true)                                   // (string, Func); the condition confines it
                .GrantIf("a:special", attrs => true, new Dictionary<string, ScopeValue> { ["tenant"] = new ScopeValue.Literal("acme") }) // (string, Func, scope)
                .Grant("a:full", metadata, new Dictionary<string, ScopeValue> { ["tenant"] = new ScopeValue.Literal("acme") }, attrs => true)) // (string, GrantMetadata, scope, Func)
            .Assign("u", "r")
            .Build();

        Assert.True((await auth.AuthorizeAsync("u", "a:read")).IsAllowed);
        Assert.True((await auth.AuthorizeAsync("u", "a:write",
            new Dictionary<string, string> { ["tenant"] = "acme" })).IsAllowed);
    }

    [Fact]
    public void A_scoped_Grant_with_no_scope_is_rejected_unconfined_must_be_explicit()
    {
        var b = new RoleBuilder("r", "R");

        // A grant with no scope and no condition would apply to every resource in every tenant, so
        // each Grant overload throws ArgumentException when it ends up with neither.
        Assert.Throws<ArgumentException>(() => b.Grant("a:read"));                                   // params overload, empty
        Assert.Throws<ArgumentException>(() => b.Grant("a:read", new Dictionary<string, ScopeValue>())); // dictionary overload, empty
        Assert.Throws<ArgumentException>(() => b.Grant("a:read", new GrantMetadata()));              // metadata overload, no scope/condition

        // An empty scope throws even with a condition; pass null for a grant confined by its condition alone.
        Assert.Throws<ArgumentException>(() => b.GrantIf("a:read", attrs => true, new Dictionary<string, ScopeValue>()));
        Assert.Throws<ArgumentException>(() => b.Grant("a:read", new GrantMetadata(), new Dictionary<string, ScopeValue>(), attrs => true));

        // None of these throws.
        b.GrantEverywhere("a:read");
        b.Grant("a:read", ("tenant", new ScopeValue.Literal("acme")));
        b.GrantIf("a:read", attrs => true); // the condition confines the grant
    }

    [Fact]
    public async Task AuthorizeAsync_request_overload_and_withers()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("r", "R", b => b.Grant("a:write", ("tenant", new ScopeValue.Literal("acme"))))
            .Assign("u", "r")
            .Build();

        var request = new AuthorizationRequest("u", Permission.Parse("a:write"))
            .WithScope(new Dictionary<string, string> { ["tenant"] = "acme" });

        Assert.True((await auth.AuthorizeAsync(request)).IsAllowed);
    }

    [Fact]
    public void Identifier_and_permission_conversions()
    {
        PrincipalRef principal = "alice";
        Assert.Equal("alice", principal.Value);
        Assert.Equal("alice", principal.ToString());

        RoleRef role = "reader";
        Assert.Equal("reader", role.Value);
        Assert.Equal("reader", role.ToString());

        var permission = (Permission)"documents:read"; // explicit because Parse can throw
        Assert.Equal(new Permission("documents", "read"), permission);
    }

    [Fact]
    public void Build_rejects_two_grants_with_the_same_pattern_and_scope()
    {
        var b = new RoleBuilder("r", "R")
            .GrantIf("invoices:approve", attrs => true)
            .GrantIf("invoices:approve", attrs => false);

        Assert.Throws<ArgumentException>(() => b.Build());
    }
}
