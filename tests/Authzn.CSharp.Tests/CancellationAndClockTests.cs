using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Authzn.CSharp;
using Xunit;

namespace Authzn.CSharp.Tests;

public class CancellationAndClockTests
{
    private static Dictionary<string, string> Tenant(string tenant) => new() { ["tenant"] = tenant };

    // Records every token it receives, and holds one role granting reports:read for the tenant the
    // principal marker admits.
    private sealed class RecordingStores : ScopeValueResolver
    {
        public ConcurrentBag<CancellationToken> Seen { get; } = new();

        public RoleStore Roles => new RoleStoreImpl(this);

        public AssignmentStore Assignments => new AssignmentStoreImpl(this);

        public override ValueTask<bool> AdmitsAsync(
            PrincipalRef principal,
            string scopeKey,
            string marker,
            string requestValue,
            CancellationToken cancellationToken)
        {
            Seen.Add(cancellationToken);
            return ValueTask.FromResult(requestValue == "t1");
        }

        public override ValueTask<ScopeValueSet?> EnumerateScopeAsync(
            PrincipalRef principal,
            string scopeKey,
            string marker,
            CancellationToken cancellationToken)
        {
            Seen.Add(cancellationToken);
            return ValueTask.FromResult<ScopeValueSet?>(ScopeValueSet.From(new[] { "t1" }));
        }

        private sealed class RoleStoreImpl(RecordingStores owner) : RoleStore
        {
            public override Task<Role?> GetRoleAsync(RoleRef id, CancellationToken cancellationToken)
            {
                owner.Seen.Add(cancellationToken);
                return Task.FromResult<Role?>(Role.Define("tenant-reader", "Tenant Reader", r => r
                    .Grant("reports:read", ("tenant", ScopeValue.Principal))));
            }
        }

        private sealed class AssignmentStoreImpl(RecordingStores owner) : AssignmentStore
        {
            public override Task<IReadOnlyList<Assignment>> GetAssignmentsForPrincipalAsync(
                PrincipalRef principal,
                CancellationToken cancellationToken)
            {
                owner.Seen.Add(cancellationToken);
                return Task.FromResult<IReadOnlyList<Assignment>>(new[] { Assignment.Create(principal, "tenant-reader") });
            }
        }
    }

    // Admits tenant "t1" for every marker, answering only after yielding.
    private sealed class YieldingResolver : ScopeValueResolver
    {
        public override async ValueTask<bool> AdmitsAsync(
            PrincipalRef principal,
            string scopeKey,
            string marker,
            string requestValue,
            CancellationToken cancellationToken)
        {
            await Task.Yield();
            return requestValue == "t1";
        }

        public override async ValueTask<ScopeValueSet?> EnumerateScopeAsync(
            PrincipalRef principal,
            string scopeKey,
            string marker,
            CancellationToken cancellationToken)
        {
            await Task.Yield();
            return ScopeValueSet.From(new[] { "t1" });
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    [Fact]
    public async Task Every_Authorizer_method_passes_its_token_to_the_stores_and_the_resolver()
    {
        var stores = new RecordingStores();
        var auth = new AuthorizationBuilder()
            .UseRoleStore(stores.Roles)
            .UseAssignmentStore(stores.Assignments)
            .UseScopeResolver(stores)
            .Build();

        using var source = new CancellationTokenSource();
        var token = source.Token;

        await auth.AuthorizeAsync("alice", "reports:read", Tenant("t1"), cancellationToken: token);
        await auth.AllowedAmongAsync("alice", new[] { "reports:read" }, Tenant("t1"), cancellationToken: token);
        await auth.GrantsAmongAsync("alice", new[] { "reports:read" }, Tenant("t1"), cancellationToken: token);
        await auth.FilterAsync("alice", "reports:read", new[] { "t1" }, Tenant, cancellationToken: token);
        await auth.MayAnyAsync("alice", "reports:read", Tenant("t1"), token);
        await auth.VisibleScopeAsync("alice", "reports:read", cancellationToken: token);

        Assert.NotEmpty(stores.Seen);
        Assert.All(stores.Seen, received => Assert.Equal(token, received));
    }

    [Fact]
    public async Task A_resolver_that_completes_asynchronously_is_awaited()
    {
        var auth = new AuthorizationBuilder()
            .AddRole("tenant-reader", "Tenant Reader", r => r.Grant("reports:read", ("tenant", ScopeValue.Principal)))
            .UseScopeResolver(new YieldingResolver())
            .Assign("alice", "tenant-reader")
            .Build();

        Assert.True((await auth.AuthorizeAsync("alice", "reports:read", Tenant("t1"))).IsAllowed);
        Assert.Equal(
            new AuthorizationDecision.Denied(DenyReason.ScopeMismatch),
            await auth.AuthorizeAsync("alice", "reports:read", Tenant("t2")));
        Assert.Equal(new[] { "t1" }, await auth.FilterAsync("alice", "reports:read", new[] { "t1", "t2" }, Tenant));

        var constraint = await auth.VisibleScopeAsync("alice", "reports:read");
        var clause = Assert.Single(Assert.IsType<ScopeConstraint.Restricted>(constraint).Clauses);
        Assert.Equal(new[] { "t1" }, Assert.IsType<ScopeValueSet.Of>(clause["tenant"]).Values.ToArray());
    }

    [Fact]
    public async Task UseTimeProvider_sets_the_clock_for_grant_expiry()
    {
        var expiresAt = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);

        Authorizer At(DateTimeOffset now) =>
            new AuthorizationBuilder()
                .AddRole("temp", "Temporary", r => r.GrantEverywhere("reports:read", new GrantMetadata { ExpiresAt = expiresAt }))
                .Assign("alice", "temp")
                .UseTimeProvider(new FixedTimeProvider(now))
                .Build();

        Assert.True((await At(expiresAt.AddSeconds(-1)).AuthorizeAsync("alice", "reports:read")).IsAllowed);
        Assert.Equal(
            new AuthorizationDecision.Denied(DenyReason.GrantNotActive),
            await At(expiresAt).AuthorizeAsync("alice", "reports:read"));
    }
}
