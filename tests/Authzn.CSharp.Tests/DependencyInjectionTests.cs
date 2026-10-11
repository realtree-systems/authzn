using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using RealTree.Authzn.CSharp;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace RealTree.Authzn.CSharp.Tests;

public class DependencyInjectionTests
{
    private sealed class RoleStoreStub(params Role[] roles) : RoleStore
    {
        public override Task<Role?> GetRoleAsync(RoleRef id, CancellationToken cancellationToken) =>
            Task.FromResult(roles.FirstOrDefault(r => r.Id.Value == id.Value));
    }

    private sealed class AssignmentStoreStub(params Assignment[] assignments) : AssignmentStore
    {
        public override Task<IReadOnlyList<Assignment>> GetAssignmentsForPrincipalAsync(
            PrincipalRef principal,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<Assignment>>(
                assignments.Where(a => a.Principal.Value == principal.Value).ToList());
    }

    [Fact]
    public async Task AddAuthzn_with_builder_registers_authorizer_and_supporting_services()
    {
        var provider = new ServiceCollection()
            .AddAuthzn(b => b
                .AddRole("reader", "Reader", r => r.GrantEverywhere("docs:read"))
                .Assign("u", "reader"))
            .BuildServiceProvider();

        Assert.NotNull(provider.GetService<Authorizer>());
        Assert.NotNull(provider.GetService<global::RealTree.Authzn.AuthorizationHost>());
        Assert.NotNull(provider.GetService<global::RealTree.Authzn.AuthorizationEngine>());
        Assert.NotNull(provider.GetService<global::RealTree.Authzn.IGrantPolicyChain>());

        var decision = await provider.GetRequiredService<Authorizer>().AuthorizeAsync("u", "docs:read");
        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task AddAuthzn_with_custom_stores()
    {
        var role = Role.Define("reader", "Reader", r => r.GrantEverywhere("docs:read"));

        var provider = new ServiceCollection()
            .AddAuthzn(new RoleStoreStub(role), new AssignmentStoreStub(Assignment.Create("dana", "reader")))
            .BuildServiceProvider();

        var decision = await provider.GetRequiredService<Authorizer>().AuthorizeAsync("dana", "docs:read");
        Assert.True(decision.IsAllowed);
    }
}
