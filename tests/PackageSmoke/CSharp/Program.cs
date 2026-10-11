using System.Reflection;
using RealTree.Authzn.CSharp;
using Microsoft.Extensions.DependencyInjection;

// Installs RealTree.Authzn.CSharp from the packed packages, which brings RealTree.Authzn and its FSharp.Core floor
// transitively, and checks one allowed and one denied decision through the DI registration.
var provider = new ServiceCollection()
    .AddAuthzn(builder => builder
        .AddRole("reader", "Reader", role => role.Grant("documents:read", ("tenant", new ScopeValue.Literal("acme"))))
        .Assign("alice", "reader"))
    .BuildServiceProvider();

var authorizer = provider.GetRequiredService<Authorizer>();
var inTenant = await authorizer.AuthorizeAsync("alice", "documents:read", new Dictionary<string, string> { ["tenant"] = "acme" });
var otherTenant = await authorizer.AuthorizeAsync("alice", "documents:read", new Dictionary<string, string> { ["tenant"] = "globex" });

string VersionOf(string assembly) =>
    AppDomain.CurrentDomain.GetAssemblies().First(a => a.GetName().Name == assembly)
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";

if (inTenant is not AuthorizationDecision.Allowed || otherTenant is not AuthorizationDecision.Denied { Reason: DenyReason.ScopeMismatch })
{
    Console.Error.WriteLine($"RealTree.Authzn.CSharp smoke test failed: acme -> {inTenant}, globex -> {otherTenant}");
    return 1;
}

Console.WriteLine($"RealTree.Authzn.CSharp smoke test passed: RealTree.Authzn.CSharp {VersionOf("RealTree.Authzn.CSharp")}, FSharp.Core {VersionOf("FSharp.Core")}");
return 0;
