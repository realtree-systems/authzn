using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using RealTree.Authzn.CSharp;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace RealTree.Authzn.CSharp.Tests;

public class ContainerStoreAndGrantRevocationTests
{
    // A dependency the stores below take from the container: one role, assigned to alice.
    private sealed class Directory
    {
        public Role Role { get; } = Role.Define("reader", "Reader", r => r.GrantEverywhere(
            "docs:read",
            new GrantMetadata { ExpiresAt = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero) }));
    }

    private sealed class DirectoryRoleStore(Directory directory) : RoleStore
    {
        public override Task<Role?> GetRoleAsync(RoleRef id, CancellationToken cancellationToken) =>
            Task.FromResult(id == directory.Role.Id ? directory.Role : null);
    }

    private sealed class DirectoryAssignmentStore(Directory directory) : AssignmentStore
    {
        public override Task<IReadOnlyList<Assignment>> GetAssignmentsForPrincipalAsync(
            PrincipalRef principal,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<Assignment>>(
                principal.Value == "alice" ? new[] { Assignment.Create(principal, directory.Role.Id) } : []);
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    [Fact]
    public async Task AddAuthzn_with_store_types_creates_the_stores_and_the_authorizer_from_the_container()
    {
        var configured = 0;
        var services = new ServiceCollection()
            .AddSingleton<Directory>()
            .AddSingleton<TimeProvider>(new FixedTimeProvider(new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero)));

        services.AddAuthzn<DirectoryRoleStore, DirectoryAssignmentStore>((provider, builder) =>
        {
            configured++;
            builder.UseTimeProvider(provider.GetRequiredService<TimeProvider>());
        });

        Assert.Equal(0, configured);

        using var provider = services.BuildServiceProvider();
        var auth = provider.GetRequiredService<Authorizer>();

        // The grant expires at the container's time, so the configured clock is in use.
        Assert.Equal(new AuthorizationDecision.Denied(DenyReason.GrantNotActive), await auth.AuthorizeAsync("alice", "docs:read"));
        Assert.Same(auth, provider.GetRequiredService<Authorizer>());
        Assert.Same(provider.GetRequiredService<global::RealTree.Authzn.AuthorizationHost>().Engine, provider.GetRequiredService<global::RealTree.Authzn.AuthorizationEngine>());
        Assert.NotNull(provider.GetRequiredService<GrantPolicyChain>());
        Assert.Equal(1, configured);
    }

    [Fact]
    public async Task AddAuthzn_with_store_types_uses_a_store_already_registered()
    {
        var registered = new DirectoryRoleStore(new Directory());
        var services = new ServiceCollection()
            .AddSingleton<Directory>()
            .AddSingleton(registered);

        services.AddAuthzn<DirectoryRoleStore, DirectoryAssignmentStore>();

        using var provider = services.BuildServiceProvider();

        Assert.Same(registered, provider.GetRequiredService<DirectoryRoleStore>());
        Assert.True((await provider.GetRequiredService<Authorizer>().AuthorizeAsync("alice", "docs:read")).IsAllowed);
    }

    [Fact]
    public async Task RevokeGrant_and_ReinstateGrant_change_one_grant_of_an_in_memory_role()
    {
        static void Grants(RoleBuilder r) => r.GrantEverywhere("docs:read").GrantEverywhere("docs:write");

        var auth = new AuthorizationBuilder()
            .AddRole("ops", "Ops", Grants)
            .Assign("alice", "ops")
            .Build();

        var readKey = Role.Define("ops", "Ops", Grants).Grants[0].Key;

        auth.RevokeGrant("ops", readKey, "admin");

        Assert.Equal(new AuthorizationDecision.Denied(DenyReason.GrantNotActive), await auth.AuthorizeAsync("alice", "docs:read"));
        Assert.True((await auth.AuthorizeAsync("alice", "docs:write")).IsAllowed);

        auth.ReinstateGrant("ops", readKey);

        Assert.True((await auth.AuthorizeAsync("alice", "docs:read")).IsAllowed);
    }

    [Fact]
    public void RevokeGrant_and_ReinstateGrant_throw_with_a_custom_role_store()
    {
        var auth = new AuthorizationBuilder()
            .UseRoleStore(new DirectoryRoleStore(new Directory()))
            .Build();

        var key = new GrantRef("deadbeef");

        Assert.Throws<InvalidOperationException>(() => auth.RevokeGrant("reader", key, "admin"));
        Assert.Throws<InvalidOperationException>(() => auth.ReinstateGrant("reader", key));
    }
}
