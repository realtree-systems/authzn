# Authzn.CSharp

An idiomatic C# API for [Authzn](https://www.nuget.org/packages/RealTree.Authzn), a lightweight role-based access control (RBAC) engine for .NET with optional attribute-based (ABAC) conditions.

`Authzn` is written in F#. Consuming it directly from C# means working with `FSharpMap`, `FSharpOption`, and `FSharpFunc`. **Authzn.CSharp** wraps the same engine in a surface that feels native to C#: fluent builders, plain `Func<>` conditions, nullable types, dictionaries, and PascalCase methods. No `FSharp*` type ever appears in your code.

```bash
dotnet add package RealTree.Authzn.CSharp
```

Requires .NET 10 or later. The package depends on `RealTree.Authzn`, so the core engine comes with it.

## Quick start

```csharp
using RealTree.Authzn.CSharp;

var authorizer = new AuthorizationBuilder()
    .AddRole("reader", "Reader", role => role.GrantEverywhere("documents:read"))
    .Assign("alice", "reader")
    .Build();

var decision = await authorizer.AuthorizeAsync("alice", "documents:read");

switch (decision)
{
    case AuthorizationDecision.Allowed allowed:
        // proceed; allowed.Role and allowed.Permission name the first grant that allowed it
        break;
    case AuthorizationDecision.Denied denied:
        Console.WriteLine($"Denied: {denied.Reason}"); // a plain enum
        break;
}
```

## Concepts

A **principal** (user, service, group) is assigned **roles**; a role contains **permission grants**. A request names a **permission**, a concrete `resource:action` pair such as `documents:read` or `project:task:write` (the last `:` separates the action). A grant covers a **permission pattern**, which may use `*` for the resource or the action (`documents:*`, `project:task:*`, `*:read`), or `*` alone for everything. `AuthorizeAsync` throws `ArgumentException` for text that is not a permission, including any wildcard.

A grant can be confined by a **scope** (a key/value bag such as `tenant=acme`) and by an **ABAC condition** over runtime attributes. The model is purely additive: a request is allowed when any grant from any of the principal's active assignments covers the permission, is active (see [Grant metadata and expiry](#grant-metadata-and-expiry)), matches the scope, and has no condition or a condition that returns `true`. A grant that does not apply never blocks another, and there are no deny rules. Beyond the yes/no check, the same engine answers *which* resources a principal may act on - see [Querying visible resources](#querying-visible-resources).

## Common scenarios

### Scoped permissions

```csharp
var auth = new AuthorizationBuilder()
    .AddRole("tenant-reader", "Tenant Reader", r => r.Grant("documents:read", ("tenant", new ScopeValue.Literal("acme"))))
    .Assign("carol", "tenant-reader")
    .Build();

// Allowed - scope matches
await auth.AuthorizeAsync("carol", "documents:read",
    scope: new Dictionary<string, string> { ["tenant"] = "acme" });

// Denied (ScopeMismatch) - wrong tenant
await auth.AuthorizeAsync("carol", "documents:read",
    scope: new Dictionary<string, string> { ["tenant"] = "other" });
```

A grant's scope keys must all be present (with matching values) in the request scope; extra request keys are allowed.

### ABAC conditions

Pass a plain predicate over the request attributes. Use guarded lookups: a condition that throws counts as `false`, the same as returning `false`. A grant whose condition fails does not apply, but another grant can still allow the request. When no grant allows it and a grant failed only on its condition, the decision is `Denied` with `AttributeEvaluationFailed`.

```csharp
var auth = new AuthorizationBuilder()
    .AddRole("approver", "Approver", r => r.GrantIf("orders:approve",
        attrs => attrs.TryGetValue("amount", out var v) && v is int amount && amount < 10_000))
    .Assign("eve", "approver")
    .Build();

await auth.AuthorizeAsync("eve", "orders:approve",
    attributes: new Dictionary<string, object> { ["amount"] = 5_000 }); // ALLOWED
```

`GrantIf` takes an optional scope. Pass `null` (the default) for a grant confined by its condition alone: an empty dictionary throws `ArgumentException`, because a scope built at run time that comes out empty has usually lost its keys. `Grant` throws for an empty scope too; `GrantEverywhere` is the only way to add an unconfined grant.

### Time-bounded assignments and revocation

```csharp
var auth = new AuthorizationBuilder()
    .AddRole("contractor", "Contractor", r => r.GrantEverywhere("docs:read"))
    .AssignForWindow("frank", "contractor",
        notBefore: DateTimeOffset.UtcNow,
        notAfter: DateTimeOffset.UtcNow.AddDays(30))
    .Build();

// Revoke at runtime (in-memory stores)
auth.Revoke("frank", "contractor");
```

`notBefore` is inclusive and `notAfter` exclusive; pass `null` to leave either end open. `Authorizer.Revoke` revokes every assignment of the role to the principal in the in-memory assignment store, and throws `InvalidOperationException` when the authorizer uses a custom `AssignmentStore`. `AuthorizationBuilder.Revoke` revokes only the assignments added before it:

```csharp
var auth = new AuthorizationBuilder()
    .AddRole("contractor", "Contractor", r => r.GrantEverywhere("docs:read"))
    .Assign("frank", "contractor")
    .Revoke("frank", "contractor")   // revokes the assignment above
    .Assign("frank", "contractor")   // added after Revoke, so still active
    .Build();
```

### Defining roles and adding them at runtime

`Role.Define(id, name, configure)` builds a role outside an `AuthorizationBuilder`, for a custom `RoleStore` or to add at runtime. With the in-memory stores, `Authorizer.AddRole`, `AddAssignment` and `Revoke` can run while other requests are being evaluated; with a custom store they throw `InvalidOperationException`.

`AuthorizationBuilder.AddRole` throws `ArgumentException` for a role id that is already configured. `RoleBuilder.Build`, and so `Role.Define` and `AddRole`, throws `ArgumentException` when two grants in one role have the same permission pattern and scope; merge their conditions into one grant, or move one grant to another role.

```csharp
var auditor = Role.Define("auditor", "Auditor", r => r
    .Grant("ledger:read", ("tenant", new ScopeValue.Literal("acme"))));

var auth = new AuthorizationBuilder().Build();

auth.AddRole(auditor);                                    // replaces any role with the same id
auth.AddAssignment(Assignment.Create("gail", "auditor")); // added after gail's existing assignments
auth.Revoke("gail", "auditor");                           // revokes every assignment of auditor to gail
```

### Grant metadata and expiry

`Grant(permission, metadata, scope, condition)` and `GrantEverywhere(permission, metadata)` attach a `GrantMetadata`: who added the grant and why, who consented, and when it ends. A grant whose `ExpiresAt` has passed, or whose `RevokedAt` is set, does not apply; a request that only such a grant would allow is denied with `GrantNotActive` (see [Deny reasons](#deny-reasons)).

```csharp
var auth = new AuthorizationBuilder()
    .AddRole("on-call", "On-call", r => r.Grant("prod:deploy",
        new GrantMetadata { Reason = "Incident 4211", ExpiresAt = DateTimeOffset.UtcNow.AddHours(8) },
        scope: new Dictionary<string, ScopeValue> { ["env"] = new ScopeValue.Literal("prod") }))
    .Assign("hana", "on-call")
    .Build();
```

### Revoking one grant

`Authorizer.RevokeGrant(role, grant, revokedBy)` revokes one grant of a role in the in-memory role store, without removing the role. A grant is named by its `PermissionGrant.Key`, a `GrantRef` computed from its permission pattern and scope. The grant's `RevokedAt` becomes the authorizer's current time and its `RevokedBy` the given principal, so a request that only this grant would allow is denied with `GrantNotActive`. A grant that is already revoked keeps its first revocation, and an unknown role or key changes nothing. `ReinstateGrant(role, grant)` clears the revocation. Both throw `InvalidOperationException` when the authorizer uses a custom `RoleStore`; such a store revokes a grant by returning it with `GrantMetadata.RevokedAt` set.

```csharp
var ops = Role.Define("ops", "Operations", r => r
    .GrantEverywhere("deploy:run")
    .GrantEverywhere("logs:read"));

var auth = new AuthorizationBuilder()
    .AddRole(ops)
    .Assign("ivan", "ops")
    .Build();

GrantRef deploy = ops.Grants[0].Key;

auth.RevokeGrant("ops", deploy, revokedBy: "security-team");
await auth.AuthorizeAsync("ivan", "deploy:run"); // Denied (GrantNotActive)
await auth.AuthorizeAsync("ivan", "logs:read");  // Allowed

auth.ReinstateGrant("ops", deploy);
await auth.AuthorizeAsync("ivan", "deploy:run"); // Allowed
```

### Testing with a fixed clock

The authorizer reads the current time from a `TimeProvider`: `TimeProvider.System` unless `AuthorizationBuilder.UseTimeProvider` sets another. That time decides which assignments and grants are active, so a test can check expiry and assignment windows without waiting. `FakeTimeProvider`, from the `Microsoft.Extensions.TimeProvider.Testing` package, holds a fixed time until the test advances it:

```csharp
using RealTree.Authzn.CSharp;
using Microsoft.Extensions.Time.Testing;

var clock = new FakeTimeProvider(new DateTimeOffset(2026, 3, 1, 9, 0, 0, TimeSpan.Zero));

var auth = new AuthorizationBuilder()
    .AddRole("on-call", "On-call", r => r.GrantEverywhere("prod:deploy",
        new GrantMetadata { ExpiresAt = clock.GetUtcNow().AddHours(8) }))
    .Assign("hana", "on-call")
    .UseTimeProvider(clock)
    .Build();

await auth.AuthorizeAsync("hana", "prod:deploy"); // Allowed

clock.Advance(TimeSpan.FromHours(8));
await auth.AuthorizeAsync("hana", "prod:deploy"); // Denied (GrantNotActive): inactive from ExpiresAt on
```

### Scope values: literals and markers

Each value in a grant's scope is a `ScopeValue`:

- `new ScopeValue.Literal("acme")`: the requested value must be exactly this text.
- A marker: `ScopeValue.Principal`, `ScopeValue.Hierarchy`, or `new ScopeValue.Marker("name")`.

A marker is resolved at evaluation time by a `ScopeValueResolver`. `AdmitsAsync` receives the marker's name
(`ScopeMarkers.Principal` is `"principal"`) and returns `true` when the marker, resolved for the principal,
admits the requested value. It returns `false` otherwise, including for a marker it does not recognise. A
marker is never compared as text: without a resolver that admits it, it matches nothing. A request's scope
stays a plain `Dictionary<string, string>`.

For configuration and storage, `ScopeValue.Parse` reads the text form and `ToString()` writes it:
`@principal` is the `principal` marker, `@@acme` is the literal `@acme`, and anything else is a literal.

```csharp
var auth = new AuthorizationBuilder()
    .AddRole("self-service", "Self Service",
        r => r.Grant("profile:edit", ("owner", ScopeValue.Principal)))
    .UseScopeResolver(new DelegateScopeResolver((principal, key, marker, requestValue) =>
        marker == ScopeMarkers.Principal && principal.Value == requestValue))
    .Assign("jake", "self-service")
    .Build();

// Allowed - Jake edits his own profile
await auth.AuthorizeAsync("jake", "profile:edit",
    scope: new Dictionary<string, string> { ["owner"] = "jake" });
```

`DelegateScopeResolver` wraps a synchronous delegate, for a resolver that answers from memory. A resolver that needs I/O, such as a database lookup, derives from `ScopeValueResolver`, overrides `AdmitsAsync`, and passes the `CancellationToken` on. The engine can call `AdmitsAsync` once per grant and candidate, so an override that answers from memory returns `ValueTask.FromResult(...)` rather than being an `async` method. The `OrgResolver` under [Querying visible resources](#querying-visible-resources) does both.

## Querying visible resources

`AuthorizeAsync` answers "**may** this principal do X **here**?" — a yes/no for one resource. Its dual is "**which** resources may this principal do X to?" — the question a list or search endpoint asks. Three methods answer it with the same permission and scope matching as `AuthorizeAsync`. `FilterAsync` returns exactly the resources `AuthorizeAsync` would allow. `MayAnyAsync` and `VisibleScopeAsync` do not evaluate ABAC conditions, so when a grant has a condition they can admit resources that `AuthorizeAsync` denies.

### `FilterAsync` — which of these?

Return the subset of a collection the principal may act on. Supply a function from each candidate to its scope (and, optionally, its ABAC attributes); the candidates `AuthorizeAsync` would allow come back in their original order. A candidate is kept when any active grant that covers the permission and matches its scope has no condition, or a condition that returns `true` for the candidate's attributes; a condition that throws counts as `false`. It reads the principal's assignments and roles once per call, however many candidates there are.

```csharp
// Of the orgs on this page, which may Alice read?
IReadOnlyList<Org> visible = await auth.FilterAsync(
    "alice",
    "organizations:read",
    pageOfOrgs,
    org => new Dictionary<string, string> { ["tenant"] = org.TenantId, ["org"] = org.Id });
```

This is the post-filter for a list page: load the page, then drop what the caller may not see, without re-deriving scope rules in your handler.

### `MayAnyAsync` — any at all?

A reachability gate: does the principal hold a grant that could admit anything within a partial scope? Use it to decide whether a list endpoint runs at all (a `403` versus an empty `200`).

```csharp
bool canList = await auth.MayAnyAsync("alice", "organizations:read",
    new Dictionary<string, string> { ["tenant"] = "acme" });
```

`MayAnyAsync` is structural — it tests whether a grant *could* apply, not whether the concrete set is non-empty (an org-admin who is a member of no orgs still "may list"; `FilterAsync` then returns an empty list). It does not evaluate ABAC conditions.

### `VisibleScopeAsync` — the pushable predicate

Materialise what the principal may act on as a `ScopeConstraint` you push into a query (a `WHERE` clause or id-set), so the database filters instead of your handler:

```csharp
var constraint = await auth.VisibleScopeAsync("alice", "organizations:read",
    new Dictionary<string, string> { ["tenant"] = "acme" });

switch (constraint)
{
    case ScopeConstraint.Everything:
        // no restriction — select all in scope
        break;
    case ScopeConstraint.Nothing:
        // no access — return empty without querying
        break;
    case ScopeConstraint.Restricted r:
        // r.Clauses is a disjunction (OR) of clauses. Each clause maps a key to a ScopeValueSet.Of
        // holding the allowed values, ANDed across keys; a key the grant leaves open is not in it.
        // e.g. { ["tenant"] = Of {"acme"}, ["org"] = Of {"sales-west","sales-east"} }
        // translates to: WHERE tenant = 'acme' AND org IN ('sales-west','sales-east')
        break;
}
```

The clauses are not narrowed to the partial scope you pass, so apply it in the query too. ABAC conditions are not evaluated: a grant with a condition contributes its clause as if the condition passed, so apply the condition yourself, or use `FilterAsync`.

`VisibleScopeAsync` builds each clause by **enumerating** the grant's scope markers (`hierarchy` → the principal's subtree ids, `principal` → the principal's own value), so override `EnumerateScopeAsync` on your `ScopeValueResolver` for the markers you understand, and make `AdmitsAsync` accept the same values. Return `ScopeValueSet.Anything` for a marker that admits every value; `VisibleScopeAsync` then leaves that key out of the clause, and a clause with no keys left makes the result `Everything`. In this resolver, `PrincipalValue` and `OrgSubtreeAsync` stand for your own lookups: the first answers from memory, the second queries a database.

```csharp
public sealed class OrgResolver : ScopeValueResolver
{
    // The membership test used by AuthorizeAsync, FilterAsync, MayAnyAsync and the batch methods.
    public override ValueTask<bool> AdmitsAsync(
        PrincipalRef principal, string scopeKey, string marker, string requestValue,
        CancellationToken cancellationToken) =>
        marker switch
        {
            // Answered from memory: return a completed ValueTask.
            ScopeMarkers.Principal => ValueTask.FromResult(requestValue == PrincipalValue(principal, scopeKey)),
            // Needs I/O: await it, passing the token on.
            ScopeMarkers.Hierarchy => InSubtreeAsync(principal, requestValue, cancellationToken),
            _ => ValueTask.FromResult(false), // a marker this resolver does not recognise admits nothing
        };

    // The same sets, listed, for VisibleScopeAsync.
    public override async ValueTask<ScopeValueSet?> EnumerateScopeAsync(
        PrincipalRef principal, string scopeKey, string marker, CancellationToken cancellationToken) =>
        marker switch
        {
            ScopeMarkers.Principal => ScopeValueSet.From([PrincipalValue(principal, scopeKey)]),
            ScopeMarkers.Hierarchy => ScopeValueSet.From(await OrgSubtreeAsync(principal, cancellationToken)),
            _ => null, // marker not enumerable — VisibleScopeAsync throws for it
        };

    private async ValueTask<bool> InSubtreeAsync(
        PrincipalRef principal, string org, CancellationToken cancellationToken) =>
        (await OrgSubtreeAsync(principal, cancellationToken)).Contains(org);
}
```

A marker that `EnumerateScopeAsync` returns `null` for cannot be pushed down soundly, so `VisibleScopeAsync` throws `NotSupportedException` for it, as it does for any marker when no resolver is configured. It throws even when another grant would make the result `Everything`. `DelegateScopeResolver` does not override `EnumerateScopeAsync`, so with it `VisibleScopeAsync` works only when the grants it uses hold no markers. Fall back to `FilterAsync` for scopes that are not enumerable. `AuthorizeAsync`, `FilterAsync`, `MayAnyAsync`, `AllowedAmongAsync` and `GrantsAmongAsync` never call `EnumerateScopeAsync`; a resolver that overrides only `AdmitsAsync` works with all of them.

| Question | Method | Returns | Resolver needs |
|---|---|---|---|
| May I, on this one? | `AuthorizeAsync` | `AuthorizationDecision` | `AdmitsAsync` |
| Which of these may I? | `FilterAsync` | the admitted subset | `AdmitsAsync` |
| May I on anything here? | `MayAnyAsync` | `bool` | `AdmitsAsync` |
| What may I, as a query predicate? | `VisibleScopeAsync` | `ScopeConstraint` | `AdmitsAsync` + `EnumerateScopeAsync` |
| Which of these permissions do I hold here? | `AllowedAmongAsync` | `IReadOnlySet<string>` | `AdmitsAsync` |
| Which grants give me each one? | `GrantsAmongAsync` | `IReadOnlyDictionary<string, IReadOnlyList<GrantSource>>` | `AdmitsAsync` |

### `AllowedAmongAsync` and `GrantsAmongAsync` — many permissions at once

`AllowedAmongAsync` returns the members of a list of permissions that the principal holds in one scope, for example to decide which actions a page offers. A permission is in the result exactly when `AuthorizeAsync` would allow it on its own, and the principal's assignments are read once for the whole list. A string that is not a concrete `resource:action` permission, including a wildcard such as `invoices:*`, is left out without an exception.

`GrantsAmongAsync` returns, for each permission the principal holds, every grant that allows it and the role that carries it, in assignment and grant order; its keys are `AllowedAmongAsync`'s result. `AuthorizeAsync` names only the first such grant. `GrantSource.IsWildcard` tells a grant that names the permission from one that covers it through `*`.

```csharp
// Which of these may Kim do in tenant acme? One read of Kim's assignments answers all three.
IReadOnlySet<string> held = await auth.AllowedAmongAsync("kim",
    new[] { "invoices:read", "invoices:approve", "invoices:delete" },
    scope: new Dictionary<string, string> { ["tenant"] = "acme" });

// Which grants allow invoices:approve, and does a wildcard such as * provide it?
var sources = await auth.GrantsAmongAsync("kim", new[] { "invoices:approve" },
    scope: new Dictionary<string, string> { ["tenant"] = "acme" });

if (sources.TryGetValue("invoices:approve", out var grants))
{
    foreach (var source in grants)
    {
        Console.WriteLine($"{source.Role}: {source.Grant.Permission} (wildcard: {source.IsWildcard})");
    }
}
```

## Dependency injection

```csharp
using RealTree.Authzn.CSharp;
using Microsoft.Extensions.DependencyInjection;

services.AddAuthzn(b => b
    .AddRole("admin", "Admin", r => r.GrantEverywhere("system:*"))
    .AddRole("reader", "Reader", r => r.GrantEverywhere("system:read"))
    .Assign("user:1", "admin"));
```

```csharp
public sealed class InvoiceService(Authorizer authorizer, ILogger<InvoiceService> logger)
{
    public async Task<Invoice> GetAsync(string principalId, string invoiceId, CancellationToken cancellationToken)
    {
        var decision = await authorizer.AuthorizeAsync(principalId, "invoice:read",
            scope: new Dictionary<string, string> { ["tenant"] = TenantOf(invoiceId) },
            cancellationToken: cancellationToken);

        if (decision is AuthorizationDecision.Denied denied)
        {
            // Keep the reason in the server log, out of the message the caller sees.
            logger.LogWarning("{Principal} may not read invoice {Invoice}: {Reason}", principalId, invoiceId, denied.Reason);
            throw new UnauthorizedAccessException("Not authorized to read this invoice.");
        }

        return await LoadAsync(invoiceId, cancellationToken);
    }
}
```

Every `Authorizer` query method (`AuthorizeAsync`, `AllowedAmongAsync`, `GrantsAmongAsync`, `FilterAsync`, `MayAnyAsync`, `VisibleScopeAsync`) takes an optional last `CancellationToken` and passes it to every store and resolver call. The in-memory stores do not observe it; a custom store or resolver passes it on to its database or HTTP calls. `FilterAsync` also checks it before each candidate. In ASP.NET Core, pass `HttpContext.RequestAborted`, which is cancelled when the client disconnects:

```csharp
using System.Security.Claims;

app.MapGet("/invoices/{id}", (string id, HttpContext http, InvoiceService invoices) =>
    invoices.GetAsync(http.User.FindFirstValue(ClaimTypes.NameIdentifier)!, id, http.RequestAborted))
    .RequireAuthorization();
```

`GetAsync` throws `UnauthorizedAccessException` for a denied request, which ASP.NET Core answers with `500` unless your exception handling maps it to `403`.

`AddAuthzn` runs the builder action during the call, builds the authorizer, and registers the `Authorizer` and the `GrantPolicyChain` (and the core's `AuthorizationHost`, `AuthorizationEngine` and `IGrantPolicyChain`) as singletons. For stores backed by a database, see [Custom persistence](#custom-persistence).

## Custom persistence

Derive from `RoleStore` and `AssignmentStore` - they return nullable types and `IReadOnlyList<T>`, never F# options or lists. The engine calls them for every request, possibly on several threads at once, and does not cache the results, so the overrides must be safe for concurrent calls. `GetAssignmentsForPrincipalAsync` may return revoked or expired assignments; the engine skips them. Its order decides which role an `Allowed` decision names when more than one role allows the request. `GetRoleAsync` returns `null` for an unknown role, and the engine skips that assignment. Both receive the `CancellationToken` passed to the `Authorizer` method; pass it on to your database calls.

A store replaces the builder's in-memory store: with `UseRoleStore`, the builder's `AddRole` calls are ignored, and with `UseAssignmentStore`, its `Assign`, `AssignForWindow` and `Revoke` calls are ignored.

```csharp
using RealTree.Authzn.CSharp;
using Microsoft.EntityFrameworkCore;

public sealed class DbRoleStore(IDbContextFactory<MyDbContext> contexts) : RoleStore
{
    public override async Task<Role?> GetRoleAsync(RoleRef id, CancellationToken cancellationToken)
    {
        // The engine calls stores concurrently, so each call uses its own context.
        await using var db = await contexts.CreateDbContextAsync(cancellationToken);

        var entity = await db.Roles
            .AsNoTracking()
            .Include(r => r.Grants)
            .SingleOrDefaultAsync(r => r.Id == id.Value, cancellationToken);

        if (entity is null)
        {
            return null;
        }

        return Role.Define(entity.Id, entity.Name, role =>
        {
            foreach (var g in entity.Grants)
            {
                // Permissions and scope values are stored as text; both forms read back exactly.
                var scope = g.Scope.ToDictionary(kv => kv.Key, kv => ScopeValue.Parse(kv.Value));

                if (scope.Count == 0)
                    role.GrantEverywhere(g.Permission); // an unconfined grant must be asked for by name
                else
                    role.Grant(g.Permission, scope);
            }
        });
    }
}
```

`Role.Define` throws `ArgumentException` when the stored rows hold two grants with the same permission pattern and scope, so reject such rows when you write them. To keep expiry and revocation, store the grant's `GrantMetadata` and pass it to `Grant(permission, metadata, scope)` or `GrantEverywhere(permission, metadata)`.

Register the stores with `AddAuthzn<TRoleStore, TAssignmentStore>`. The container creates them, so they take their dependencies from it. Each store type is registered as a singleton unless the container already has a registration for it. The engine calls the stores from concurrent requests, so a store must not hold a scoped dependency such as a `DbContext`; that is why `DbRoleStore` takes an `IDbContextFactory`. The authorizer is built when it is first resolved, and the optional callback then receives the service provider and the builder, for a scope resolver or a clock from the container. A `DbAssignmentStore` follows the same pattern as `DbRoleStore`:

```csharp
using RealTree.Authzn.CSharp;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

services.AddDbContextFactory<MyDbContext>(options => options.UseSqlServer(connectionString));
services.AddSingleton(TimeProvider.System);

services.AddAuthzn<DbRoleStore, DbAssignmentStore>((provider, authz) =>
    authz.UseTimeProvider(provider.GetRequiredService<TimeProvider>()));
```

`AddAuthzn(roleStore, assignmentStore, scopeResolver?)` takes store instances instead, for stores created before the container is built.

## Write-time grant policies

`GrantPolicy` is a write-time check for code that adds grants; neither the engine nor `RoleBuilder` calls it. Register policies with `services.AddGrantPolicy<T>()`. The `GrantPolicyChain` that `AddAuthzn` registers runs them in registration order, passing its `CancellationToken` to each, and returns the first decision that is not `Allow` without calling the rest, or `Allow` when every policy allows. `new GrantPolicyChain(policies)` builds one without dependency injection.

```csharp
public sealed class SandboxPolicy : GrantPolicy
{
    public override Task<GrantPolicyDecision> EvaluateAsync(GrantPolicyContext context, CancellationToken cancellationToken) =>
        Task.FromResult<GrantPolicyDecision>(context.Grant.Permission.Resource is PermissionSegment.Exactly { Name: "system" }
            ? new GrantPolicyDecision.RequireConsent("Elevated permission", Tier: "elevated")
            : new GrantPolicyDecision.Allow());
}

// services.AddGrantPolicy<SandboxPolicy>();
```

Your grant-write code builds the role as it will be written, runs the chain on each of its grants, and enforces the decision. A caller with no consent step treats `RequireConsent` as `Reject`. Here `IRoleRepository` stands for your own persistence, and `GrantPolicyChain` comes from the container:

```csharp
public sealed class RoleWriter(GrantPolicyChain policies, IRoleRepository roles)
{
    // Saves the role only when every grant is allowed. Returns Allow, or the decision that stopped it.
    public async Task<GrantPolicyDecision> SaveAsync(PrincipalRef actor, Role role, CancellationToken cancellationToken)
    {
        foreach (var grant in role.Grants)
        {
            var decision = await policies.EvaluateAsync(new GrantPolicyContext(actor, role.Id, grant), cancellationToken);

            // This path has no consent step, so RequireConsent stops the write as Reject does.
            if (decision is not GrantPolicyDecision.Allow)
            {
                return decision;
            }
        }

        await roles.SaveAsync(role, cancellationToken);
        return new GrantPolicyDecision.Allow();
    }
}
```

```csharp
var role = Role.Define("ops", "Operations", r => r.GrantEverywhere("system:restart"));

var decision = await writer.SaveAsync("alice", role, cancellationToken);
// RequireConsent: SandboxPolicy flags the system:restart grant, so the role is not saved
```

## Testing permission patterns

`Permission.Matches` and `PermissionPattern.Covers` apply the engine's pattern rule without a principal or a store, for example to list which known permissions a wildcard covers. They do not consider scope, conditions or grant metadata; use the `Authorizer` to decide for a principal.

```csharp
bool covered = Permission.Matches("documents:read", "documents:*");                  // true
bool alsoCovered = PermissionPattern.Parse("*:read").Covers(Permission.Parse("documents:read")); // true
bool notAPermission = Permission.Matches("documents:*", "*");                        // false: a wildcard is not a permission
```

## Deny reasons

`AuthorizationDecision` is `Allowed(Role, Permission)` or `Denied(Reason)`; `IsAllowed` tests which. `Allowed` names the first grant that allows the request, in assignment order and then grant order: `Role` is its role and `Permission` its `PermissionPattern`, which can be wider than the requested permission (`PermissionPattern.Everything`, written `*`, for a grant of `*` or `*:*`). `Reason` is a plain enum. When no grant allows the request, it is the first of these that applies:

| Reason | Value | When |
|---|---|---|
| `NoAssignments` | 1 | The assignment store returns no assignments for the principal. |
| `AssignmentNotActive` | 4 | Every assignment is revoked, expired or not yet valid. |
| `AttributeEvaluationFailed` | 6 | A grant covers the permission, is active and matches the scope, but its condition returned `false` or threw. |
| `GrantNotActive` | 5 | A grant covers the permission and matches the scope, but its `GrantMetadata` marks it revoked or expired. |
| `ScopeMismatch` | 3 | A grant covers the permission, but none that does matches the request's scope. |
| `NoMatchingPermission` | 2 | No grant in the principal's active roles covers the permission. |

The values are stable, so a stored reason keeps its meaning. No member is zero, so `default(DenyReason)` is not a reason.

## Relationship to the F# package

`RealTree.Authzn.CSharp` is a thin facade: it converts arguments and results between C# and F# types and delegates every decision to the `Authzn` engine, reimplementing no authorization logic. The two packages are released together with the same version number. F# consumers should use [`RealTree.Authzn`](https://www.nuget.org/packages/RealTree.Authzn) directly; see the [Authzn README](https://github.com/RealTree-Systems/authzn#readme) for the F# API.

## License

MIT
