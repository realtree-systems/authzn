using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using RealTree.Authzn.CSharp;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace RealTree.Authzn.CSharp.Tests;

public class GrantPolicyTests
{
    private sealed class SystemConsentPolicy : GrantPolicy
    {
        public override Task<GrantPolicyDecision> EvaluateAsync(GrantPolicyContext context, CancellationToken cancellationToken) =>
            Task.FromResult<GrantPolicyDecision>(context.Grant.Permission.Resource is PermissionSegment.Exactly { Name: "system" }
                ? new GrantPolicyDecision.RequireConsent("Elevated permission", Tier: "elevated")
                : new GrantPolicyDecision.Allow());
    }

    [Fact]
    public void Decision_round_trips_through_the_fsharp_union()
    {
        GrantPolicyDecision[] decisions =
        [
            new GrantPolicyDecision.Allow(),
            new GrantPolicyDecision.Reject("nope", "DENY"),
            new GrantPolicyDecision.RequireConsent("need", "elevated"),
        ];

        foreach (var decision in decisions)
        {
            Assert.Equal(decision, GrantPolicyDecision.FromFs(decision.ToFs()));
        }
    }

    [Fact]
    public async Task Registered_policy_is_invoked_through_the_chain()
    {
        var provider = new ServiceCollection()
            .AddAuthzn(b => b
                .AddRole("admin", "Admin", r => r.GrantEverywhere("system:write"))
                .Assign("u", "admin"))
            .AddGrantPolicy<SystemConsentPolicy>()
            .BuildServiceProvider();

        var chain = provider.GetRequiredService<GrantPolicyChain>();
        var role = Role.Define("ops", "Ops", r => r.GrantEverywhere("system:write").GrantEverywhere("docs:read"));

        // SystemConsentPolicy returns RequireConsent for a grant whose resource is "system".
        var system = await chain.EvaluateAsync(new GrantPolicyContext("u", role.Id, role.Grants[0]));
        var docs = await chain.EvaluateAsync(new GrantPolicyContext("u", role.Id, role.Grants[1]));

        Assert.Equal(new GrantPolicyDecision.RequireConsent("Elevated permission", "elevated"), system);
        Assert.Equal(new GrantPolicyDecision.Allow(), docs);
        Assert.Same(chain, provider.GetRequiredService<GrantPolicyChain>());
    }

    // Records the policies it runs and the tokens they receive, and returns a fixed decision.
    private sealed class FixedPolicy(string name, GrantPolicyDecision decision, List<string> calls, List<CancellationToken> tokens)
        : GrantPolicy
    {
        public override Task<GrantPolicyDecision> EvaluateAsync(GrantPolicyContext context, CancellationToken cancellationToken)
        {
            calls.Add(name);
            tokens.Add(cancellationToken);
            return Task.FromResult(decision);
        }
    }

    [Fact]
    public async Task Chain_runs_policies_in_order_and_stops_at_the_first_decision_that_is_not_Allow()
    {
        var calls = new List<string>();
        var tokens = new List<CancellationToken>();
        var reject = new GrantPolicyDecision.Reject("Not here", "NOT_HERE");

        var chain = new GrantPolicyChain(new GrantPolicy[]
        {
            new FixedPolicy("first", new GrantPolicyDecision.Allow(), calls, tokens),
            new FixedPolicy("second", reject, calls, tokens),
            new FixedPolicy("third", new GrantPolicyDecision.Allow(), calls, tokens),
        });

        var role = Role.Define("r", "R", b => b.GrantEverywhere("docs:read"));
        using var source = new CancellationTokenSource();

        var decision = await chain.EvaluateAsync(
            new GrantPolicyContext("u", role.Id, role.Grants[0], new Dictionary<string, string> { ["tenant"] = "acme" }),
            source.Token);

        Assert.Equal(reject, decision);
        Assert.Equal(new[] { "first", "second" }, calls);
        Assert.All(tokens, token => Assert.Equal(source.Token, token));
        Assert.Equal(new GrantPolicyDecision.Allow(), await new GrantPolicyChain([]).EvaluateAsync(
            new GrantPolicyContext("u", role.Id, role.Grants[0])));
    }

    [Fact]
    public void Context_exposes_what_it_was_created_with()
    {
        var role = Role.Define("r", "R", b => b.GrantEverywhere("docs:read"));

        var context = new GrantPolicyContext("u", role.Id, role.Grants[0], new Dictionary<string, string> { ["tenant"] = "acme" });
        var withoutProperties = new GrantPolicyContext("u", role.Id, role.Grants[0]);

        Assert.Equal(new PrincipalRef("u"), context.Principal);
        Assert.Equal(new RoleRef("r"), context.Role);
        Assert.Equal("docs:read", context.Grant.Permission.ToString());
        Assert.Equal("acme", context.Properties["tenant"]);
        Assert.Empty(withoutProperties.Properties);
        Assert.Throws<ArgumentNullException>(() => new GrantPolicyContext("u", role.Id, null!));
        Assert.Throws<ArgumentException>(() => new GrantPolicyChain(new GrantPolicy[] { null! }));
    }
}
