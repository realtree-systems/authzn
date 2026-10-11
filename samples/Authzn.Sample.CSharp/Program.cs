using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Authzn.CSharp;
using Microsoft.Extensions.DependencyInjection;

// This sample runs the usage scenarios from README.md (the F# package's README) through the C#
// facade. It needs no `using Microsoft.FSharp.*` or `using Authzn;` directive because every Authzn
// type it uses is in the Authzn.CSharp namespace.

static void PrintResult(string scenario, AuthorizationDecision decision)
{
    var (status, detail) = decision switch
    {
        AuthorizationDecision.Allowed allowed => ("ALLOWED", $"via role '{allowed.Role.Value}'"),
        AuthorizationDecision.Denied denied => ("DENIED", $"reason: {denied.Reason}"),
        _ => throw new InvalidOperationException($"Unknown decision '{decision}'."),
    };

    Console.WriteLine($"  {scenario,-48} {status,-8} ({detail})");
}

static Dictionary<string, string> Scope(params (string key, string value)[] pairs)
{
    var d = new Dictionary<string, string>();
    foreach (var (key, value) in pairs)
    {
        d[key] = value;
    }

    return d;
}

Console.WriteLine("1. Basic RBAC");
Console.WriteLine(new string('-', 60));

var basic = new AuthorizationBuilder()
    .AddRole("reader", "Reader", r => r.GrantEverywhere("documents:read"))
    .Assign("alice", "reader")
    .Build();

PrintResult("Alice reads documents", await basic.AuthorizeAsync("alice", "documents:read"));
PrintResult("Alice deletes documents", await basic.AuthorizeAsync("alice", "documents:delete"));

Console.WriteLine();

Console.WriteLine("2. Wildcard Permissions");
Console.WriteLine(new string('-', 60));

var wildcard = new AuthorizationBuilder()
    .AddRole("docs-admin", "Docs Admin", r => r.GrantEverywhere("documents:*"))
    .Assign("bob", "docs-admin")
    .Build();

PrintResult("Bob reads documents (wildcard)", await wildcard.AuthorizeAsync("bob", "documents:read"));
PrintResult("Bob deletes documents (wildcard)", await wildcard.AuthorizeAsync("bob", "documents:delete"));
PrintResult("Bob reads invoices (wrong resource)", await wildcard.AuthorizeAsync("bob", "invoices:read"));

Console.WriteLine();

Console.WriteLine("3. Scoped Permissions");
Console.WriteLine(new string('-', 60));

var scoped = new AuthorizationBuilder()
    .AddRole("tenant-reader", "Tenant Reader", r => r.Grant("documents:read", ("tenant", new ScopeValue.Literal("acme"))))
    .Assign("carol", "tenant-reader")
    .Build();

PrintResult("Carol reads docs in 'acme'",
    await scoped.AuthorizeAsync("carol", "documents:read", Scope(("tenant", "acme"))));
PrintResult("Carol reads docs in 'other-corp'",
    await scoped.AuthorizeAsync("carol", "documents:read", Scope(("tenant", "other-corp"))));

Console.WriteLine();

Console.WriteLine("4. Hierarchical Resources");
Console.WriteLine(new string('-', 60));

var hierarchical = new AuthorizationBuilder()
    .AddRole("task-manager", "Task Manager", r => r.GrantEverywhere("project:task:*"))
    .Assign("dave", "task-manager")
    .Build();

PrintResult("Dave reads project tasks", await hierarchical.AuthorizeAsync("dave", "project:task:read"));
PrintResult("Dave deletes project tasks", await hierarchical.AuthorizeAsync("dave", "project:task:delete"));
PrintResult("Dave reads project (wrong resource)", await hierarchical.AuthorizeAsync("dave", "project:read"));

Console.WriteLine();

Console.WriteLine("5. ABAC Conditions");
Console.WriteLine(new string('-', 60));

var abac = new AuthorizationBuilder()
    .AddRole("approver", "Approver", r => r.GrantIf("orders:approve",
        attrs => attrs.TryGetValue("amount", out var amount) && amount is int value && value < 10000))
    .Assign("eve", "approver")
    .Build();

PrintResult("Eve approves order ($5,000)",
    await abac.AuthorizeAsync("eve", "orders:approve", attributes: new Dictionary<string, object> { ["amount"] = 5000 }));
PrintResult("Eve approves order ($50,000)",
    await abac.AuthorizeAsync("eve", "orders:approve", attributes: new Dictionary<string, object> { ["amount"] = 50000 }));

Console.WriteLine();

Console.WriteLine("6. Time-Bounded Assignments");
Console.WriteLine(new string('-', 60));

var withinWindow = new AuthorizationBuilder()
    .AddRole("contractor", "Contractor", r => r.GrantEverywhere("docs:read"))
    .AssignForWindow("frank", "contractor", DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(1))
    .Build();

PrintResult("Frank reads docs (within window)", await withinWindow.AuthorizeAsync("frank", "docs:read"));

var expiredWindow = new AuthorizationBuilder()
    .AddRole("temp", "Temporary", r => r.GrantEverywhere("docs:read"))
    .AssignForWindow("grace", "temp", DateTimeOffset.UtcNow.AddHours(-2), DateTimeOffset.UtcNow.AddHours(-1))
    .Build();

PrintResult("Grace reads docs (expired window)", await expiredWindow.AuthorizeAsync("grace", "docs:read"));

Console.WriteLine();

Console.WriteLine("7. Revocation");
Console.WriteLine(new string('-', 60));

var revocable = new AuthorizationBuilder()
    .AddRole("editor", "Editor", r => r.GrantEverywhere("docs:edit"))
    .Assign("hank", "editor")
    .Build();

PrintResult("Hank edits docs (before revoke)", await revocable.AuthorizeAsync("hank", "docs:edit"));

revocable.Revoke("hank", "editor");

PrintResult("Hank edits docs (after revoke)", await revocable.AuthorizeAsync("hank", "docs:edit"));

Console.WriteLine();

Console.WriteLine("8. Dependency Injection");
Console.WriteLine(new string('-', 60));

var services = new ServiceCollection();
services.AddAuthzn(b => b
    .AddRole("viewer", "Viewer", r => r.GrantEverywhere("pages:view"))
    .Assign("iris", "viewer"));

var provider = services.BuildServiceProvider();
var authorizer = provider.GetRequiredService<Authorizer>();

PrintResult("Iris views pages (via DI)", await authorizer.AuthorizeAsync("iris", "pages:view"));

Console.WriteLine();

Console.WriteLine("9. Custom Scope Resolver (@principal)");
Console.WriteLine(new string('-', 60));

var selfService = new AuthorizationBuilder()
    .AddRole("self-service", "Self Service", r => r.Grant("profile:edit", ("owner", ScopeValue.Principal)))
    .UseScopeResolver(new DelegateScopeResolver((principal, scopeKey, marker, requestValue) =>
        marker == ScopeMarkers.Principal && principal.Value == requestValue))
    .Assign("jake", "self-service")
    .Build();

PrintResult("Jake edits own profile",
    await selfService.AuthorizeAsync("jake", "profile:edit", Scope(("owner", "jake"))));
PrintResult("Jake edits someone else's profile",
    await selfService.AuthorizeAsync("jake", "profile:edit", Scope(("owner", "someone-else"))));

Console.WriteLine();
