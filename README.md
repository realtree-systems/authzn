# Authzn

A lightweight, role-based access control (RBAC) with optional ABAC (attribute-based access control) authorization library for .NET applications.

## Overview

Authzn provides a drop-in authorization engine that answers a single question: "Can this principal perform this action in this scope, right now?" It also answers that question's dual — *which* resources a principal may act on — so list and search endpoints can filter to exactly what the caller may see (see [Querying Visible Resources](#querying-visible-resources)). The library ships with in-memory stores for immediate use and exposes interfaces for custom persistence implementations.

The authorization model is purely additive. Permissions are granted through roles, and roles are assigned to principals. No deny rules or negative permissions are supported.

## Installation

Requires .NET 10 or later. The package depends on `FSharp.Core` 6.0.7 or later and `Microsoft.Extensions.DependencyInjection.Abstractions` 8.0.0 or later, so it does not force newer versions on your project.

```bash
dotnet add package RealTree.Authzn
```

C# projects should use [RealTree.Authzn.CSharp](https://www.nuget.org/packages/RealTree.Authzn.CSharp), which wraps the same engine in an idiomatic C# API; see [README.CSharp.md](https://github.com/RealTree-Systems/authzn/blob/main/README.CSharp.md).

## Core Concepts

### Principal

An actor in the system, represented by a `PrincipalId`. Principals can be users, services, or groups. All identity metadata (name, email, department) is maintained externally in the identity system. Authzn does not expand group membership: a principal holds only the assignments made to its own id.

### Role

A reusable definition of authority: a named list of permission grants. A role has no time bounds or revocation of its own; those are set on assignments (`NotBefore`, `NotAfter`, `Revoked`) and on individual grants through their metadata (`ExpiresAt`, `RevokedAt`; see [Grant Metadata, Revocation, and Policies](#grant-metadata-revocation-and-policies)).

### Permission

A permission consists of a **resource** and an **action**, expressed as `resource:action`. The library supports both simple and hierarchical resources:

- Simple: `documents:read`, `invoices:write`, `users:delete`
- Hierarchical: `project:task:read`, `api:v1:endpoints:create`

The rightmost segment after the final colon is the action; everything before it is the resource.

Wildcards are supported using `*`:
- `documents:*` - All actions on documents
- `project:task:*` - All actions on project tasks
- `*:read` - The read action on all resources
- `*:*` (or just `*`) - All actions on all resources

Wildcards belong to grants only, so there are two types:

- `PermissionId` is what a request asks for: a concrete resource and action, never a wildcard.
  `PermissionId.parse "invoices:*"` is an error.
- `PermissionPattern` is what a grant covers: each of its two segments is a `Segment`, either
  `Segment.Any` (written `*`) or `Segment.Exactly name`.

`PermissionPattern.covers permission pattern` returns true when the pattern covers the permission. It
is the rule every `Engine` function applies to a grant's pattern (see
[Permission Matching](#permission-matching)).

Names are validated when they are created (`PermissionId.create`, `PermissionId.parse`,
`PermissionPattern.parse`, `ResourceName.create`, `ActionName.create`), which throw `ArgumentException`
for an invalid name; `PermissionId.tryParse`, `PermissionPattern.tryParse`, `ResourceName.tryCreate`
and `ActionName.tryCreate` return `None` instead. Each colon-separated part is non-empty and holds no
whitespace and no `*`, and an action holds no colon. `PermissionId.format` and `PermissionPattern.format`
write the text form, which `ToString()` also returns, and `parse` reads it back as the same value, so a
pattern stored as text reads back as the same pattern. A `*` is only ever a whole segment: `project:*`
covers `project:read`, not `project:task:read`. Names are compared as exact, case-sensitive text.

Reading permissions right-to-left provides natural semantics:
- `project:task:read` - "For project, when dealing with task, may read"
- `api:v1:user:update` - "For api, in v1, when dealing with user, may update"

### Scope

A key-value collection that constrains where a permission applies. Common scope keys include `tenant`, `project`, or `resource`.

A grant with an empty scope applies to every request, so add one deliberately with
`RoleBuilder.grantEverywhere` (or `grantEverywhereWith`). `RoleBuilder.grant` and `grantWith` throw
`ArgumentException` for `Some Map.empty`, and for a `None` scope with no condition; pass `None` as the
scope only for a grant confined by its condition alone.

A grant's scope (`GrantScope`) maps each key to a `ScopeValue`:

- `ScopeValue.Literal "acme"`: the requested value must be exactly this text.
- `ScopeValue.Marker name`: a **marker** resolved at evaluation time by a custom `IScopeValueResolver`.
  This enables dynamic, context-dependent scoping such as "the current user's tenant"
  (`ScopeValue.principal`) or "organizations in the user's hierarchy" (`ScopeValue.hierarchy`).

A request's scope (`ScopeBag`) is plain text: the resource's own values.

For configuration and storage, a scope value has a text form: `ScopeValue.format` writes it and
`ScopeValue.parse` reads it back. `@name` is a marker, `@@text` is the literal `@text`, and anything else
is a literal. `ScopeValue.parseScope` and `ScopeValue.formatScope` do the same for a whole scope.
`ScopeValue.tryParse` returns `None` for text that is not a valid scope value, such as `@` followed by an
invalid marker name, and `ToString()` returns the same text as `format`.

### Assignment

The link between a principal and a role. An assignment can:

- Start in the future via `NotBefore`
- Expire via `NotAfter`
- Be revoked via the `Revoked` flag

A single grant can also expire or be revoked through its metadata (see [Grant Metadata, Revocation, and Policies](#grant-metadata-revocation-and-policies)). `NotBefore` is inclusive and `NotAfter` exclusive; both are compared with the current UTC time, read from the engine's `TimeProvider`, at each evaluation (see [Testing Expiry with a Fixed Clock](#testing-expiry-with-a-fixed-clock)).

### Authorization Decision

The result of an evaluation, a discriminated union:

```fsharp
type AuthorizationDecision =
    | Allowed of Role: RoleId * Permission: PermissionPattern // the role and the pattern of the first grant that allowed
    | Denied of Reason: DenyReason                            // why access was denied
```

`decision.IsAllowed` tests the case. Match on the decision to get at the role, the permission or the
reason; the compiler then checks that both cases are handled.

## Authorization Rule

A principal may perform an action when any of its active assignments is to a role holding a grant that covers the requested permission, is active (not revoked or expired by its metadata), matches the requested scope, and has no ABAC condition or a condition that returns true. A condition that throws counts as false. A grant that does not apply withholds only itself; it never blocks another grant. When several grants allow, the `Allowed` decision names the first, in the order the assignment store returns the assignments and each role lists its grants.

## Deny Reasons

`Denied` carries a `DenyReason`, a discriminated union with one case per cause. When no grant allows, the reason is the first of these that applies:

1. `NoAssignments` - The assignment store returns no assignments for the principal
2. `AssignmentNotActive` - The principal has assignments, but each is expired, not yet valid, or revoked
3. `AttributeEvaluationFailed` - A grant matches on permission, metadata and scope, but its ABAC condition returned false or threw an exception
4. `GrantNotActive` - A grant covers the permission and matches the scope, but its metadata marks it revoked or expired
5. `ScopeMismatch` - A grant covers the permission, but no grant that covers it matches the request scope
6. `NoMatchingPermission` - No grant in the roles of the principal's active assignments covers the permission

`DenyReason` requires qualified access: match `Denied DenyReason.ScopeMismatch`. An unqualified `Denied ScopeMismatch` compiles with only warning FS0049, binds a variable, and matches every reason.

## Basic Usage

### Simple Authorization

```fsharp
open System.Threading
open RealTree.Authzn

let host =
    AuthorizationConfig.defaultConfig
    |> AuthorizationConfig.addRole (
        RoleBuilder.create "role:reader" "Reader"
        |> RoleBuilder.grantEverywhere "invoice:read"
        |> RoleBuilder.build)
    |> AuthorizationConfig.assign "user:42" "role:reader"
    |> AuthorizationHost.build

let decision =
    AuthorizationRequest.create (PrincipalId "user:42") (PermissionId.parse "invoice:read")
    |> Engine.evaluateAsync host.Engine CancellationToken.None
    |> Async.AwaitTask
    |> Async.RunSynchronously

if decision.IsAllowed then
    // Proceed with action
    ()
```

Start from `AuthorizationConfig.defaultConfig` and pipe it through the `AuthorizationConfig` functions; `AuthorizationHost.build` creates the stores and the engine, which `host.Engine` returns. Every `Engine` function takes a `CancellationToken` after the engine and passes it to each store and resolver call. The samples pass `CancellationToken.None`; a request handler passes the request's token.

### Wildcard Permissions

```fsharp
let host =
    AuthorizationConfig.defaultConfig
    |> AuthorizationConfig.addRole (
        RoleBuilder.create "role:admin" "Admin"
        |> RoleBuilder.grantEverywhere "invoice:*"
        |> RoleBuilder.build)
    |> AuthorizationConfig.assign "user:1" "role:admin"
    |> AuthorizationHost.build

// Matches invoice:read, invoice:write, invoice:delete, etc.
let decision =
    AuthorizationRequest.create (PrincipalId "user:1") (PermissionId.parse "invoice:delete")
    |> Engine.evaluateAsync host.Engine CancellationToken.None
```

### Scoped Permissions

```fsharp
let host =
    AuthorizationConfig.defaultConfig
    |> AuthorizationConfig.addRole (
        RoleBuilder.create "role:tenant-admin" "Tenant Admin"
        |> RoleBuilder.grant "invoice:*" (Some (Map.ofList [ "tenant", ScopeValue.Literal "acme" ])) None
        |> RoleBuilder.build)
    |> AuthorizationConfig.assign "user:99" "role:tenant-admin"
    |> AuthorizationHost.build

// Allowed - scope matches
let decision1 =
    AuthorizationRequest.create (PrincipalId "user:99") (PermissionId.parse "invoice:read")
    |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "acme" ])
    |> Engine.evaluateAsync host.Engine CancellationToken.None

// Denied - scope mismatch
let decision2 =
    AuthorizationRequest.create (PrincipalId "user:99") (PermissionId.parse "invoice:read")
    |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "other" ])
    |> Engine.evaluateAsync host.Engine CancellationToken.None
```

### Hierarchical Resources

Resources can be hierarchical using multiple colon-separated segments:

```fsharp
let host =
    AuthorizationConfig.defaultConfig
    |> AuthorizationConfig.addRole (
        RoleBuilder.create "role:project-lead" "Project Lead"
        |> RoleBuilder.grant "project:task:*"
            (Some (Map.ofList [ "tenant", ScopeValue.Literal "acme"; "project", ScopeValue.Literal "alpha" ])) None
        |> RoleBuilder.build)
    |> AuthorizationConfig.addRole (
        RoleBuilder.create "role:developer" "Developer"
        |> RoleBuilder.grant "project:task:read"
            (Some (Map.ofList [ "tenant", ScopeValue.Literal "acme"; "project", ScopeValue.Literal "alpha" ])) None
        |> RoleBuilder.grant "project:task:update"
            (Some (Map.ofList [ "tenant", ScopeValue.Literal "acme"; "project", ScopeValue.Literal "alpha" ])) None
        |> RoleBuilder.build)
    |> AuthorizationConfig.assign "user:lead" "role:project-lead"
    |> AuthorizationConfig.assign "user:dev" "role:developer"
    |> AuthorizationHost.build

let scope = Map.ofList [ "tenant", "acme"; "project", "alpha" ]

// Project lead can delete tasks (via wildcard) - Allowed
let decision1 =
    AuthorizationRequest.create (PrincipalId "user:lead") (PermissionId.parse "project:task:delete")
    |> AuthorizationRequest.withScope scope
    |> Engine.evaluateAsync host.Engine CancellationToken.None

// Developer cannot delete tasks (only read and update) - Denied
let decision2 =
    AuthorizationRequest.create (PrincipalId "user:dev") (PermissionId.parse "project:task:delete")
    |> AuthorizationRequest.withScope scope
    |> Engine.evaluateAsync host.Engine CancellationToken.None
```

### Scope Hierarchies

Granted scopes apply to equal or more specific requested scopes:

```fsharp
let host =
    AuthorizationConfig.defaultConfig
    |> AuthorizationConfig.addRole (
        RoleBuilder.create "role:project-admin" "Project Admin"
        |> RoleBuilder.grant "task:manage"
            (Some (Map.ofList [ "tenant", ScopeValue.Literal "acme"; "project", ScopeValue.Literal "alpha" ])) None
        |> RoleBuilder.build)
    |> AuthorizationConfig.assign "user:200" "role:project-admin"
    |> AuthorizationHost.build

// Allowed - more specific scope
let decision =
    AuthorizationRequest.create (PrincipalId "user:200") (PermissionId.parse "task:manage")
    |> AuthorizationRequest.withScope
        (Map.ofList [ "tenant", "acme"; "project", "alpha"; "sprint", "sprint-1" ])
    |> Engine.evaluateAsync host.Engine CancellationToken.None
```

### Dynamic Scope Resolution

Scope markers enable role definitions that adapt to the principal's context without hardcoding specific values. The library names two well-known markers; your `IScopeValueResolver` gives them their meaning:

- `ScopeValue.principal` (name `ScopeMarkers.Principal`, text `@principal`) - By convention, the principal's own value for that scope key
- `ScopeValue.hierarchy` (name `ScopeMarkers.Hierarchy`, text `@hierarchy`) - By convention, membership in the principal's hierarchy (e.g., an org tree)

`ScopeValue.marker "name"` makes any other. A marker is never compared as text: it matches a requested
value only when the resolver admits it. A marker the resolver does not recognise, or any marker when no
resolver is configured, matches nothing. So a resource whose scope value is literally `"@principal"` is
not admitted by a `principal` grant, and `ScopeValue.Literal "@acme"` is an ordinary literal.

To use markers, implement `IScopeValueResolver`. `AdmitsAsync` returns a `ValueTask<bool>`, so a
resolver may do I/O. One that answers from memory should return a completed `ValueTask<bool>(result)`,
as below; the engine then continues without allocating a `Task` for the check.

```fsharp
open System.Threading.Tasks

let myScopeResolver =
    { new IScopeValueResolver with
        member _.AdmitsAsync(principal, scopeKey, marker, requestedValue, cancellationToken) =
            // The marker is a MarkerName; its Value is the bare name, e.g. "principal".
            let admits =
                if marker.Value = ScopeMarkers.Principal then
                    // Resolve @principal to the user's actual value
                    let principalValue = getPrincipalScopeValue principal scopeKey
                    principalValue = requestedValue
                elif marker.Value = ScopeMarkers.Hierarchy && scopeKey = "org" then
                    // Check if requested org is in the principal's org hierarchy
                    let userOrgHierarchy = getUserOrgHierarchy principal
                    userOrgHierarchy |> List.contains requestedValue
                else
                    false // A marker this resolver does not recognise admits nothing

            ValueTask<bool>(admits) }
```

A resolver that needs I/O wraps a task and passes the token on:

```fsharp
let dbScopeResolver =
    { new IScopeValueResolver with
        member _.AdmitsAsync(principal, scopeKey, marker, requestedValue, cancellationToken) =
            if marker.Value = ScopeMarkers.Hierarchy && scopeKey = "org" then
                ValueTask<bool>(
                    task {
                        let! orgs = loadOrgHierarchyAsync principal cancellationToken
                        return orgs |> Set.contains requestedValue
                    })
            else
                ValueTask<bool>(false) }
```

Register the resolver with the builder:

```fsharp
let host =
    AuthorizationConfig.defaultConfig
    |> AuthorizationConfig.useScopeResolver myScopeResolver
    |> AuthorizationConfig.addRole (
        RoleBuilder.create "role:tenant-admin" "Tenant Admin"
        |> RoleBuilder.grant "*" (Some (Map.ofList [ "tenant", ScopeValue.principal ])) None
        |> RoleBuilder.build)
    |> AuthorizationConfig.addRole (
        RoleBuilder.create "role:org-admin" "Org Admin"
        |> RoleBuilder.grant "person:*"
            (Some (Map.ofList [ "tenant", ScopeValue.principal; "org", ScopeValue.hierarchy ])) None
        |> RoleBuilder.build)
    |> AuthorizationConfig.assign "user:alice" "role:org-admin"
    |> AuthorizationHost.build

// Alice can manage people in her org hierarchy
let decision =
    AuthorizationRequest.create (PrincipalId "user:alice") (PermissionId.parse "person:create")
    |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "acme"; "org", "sales-west" ])
    |> Engine.evaluateAsync host.Engine CancellationToken.None
```

When no resolver is configured, a marker matches nothing.

### Attribute-Based Access Control (ABAC)

Permission grants can include runtime conditions:

```fsharp
let host =
    AuthorizationConfig.defaultConfig
    |> AuthorizationConfig.addRole (
        RoleBuilder.create "role:approver" "Approver"
        |> RoleBuilder.grant "invoice:approve"
            (Some (Map.ofList [ "tenant", ScopeValue.Literal "acme" ]))
            (Some (fun attrs ->
                let amount = attrs |> Map.find "amount" |> unbox<decimal>
                let level = attrs |> Map.find "managerLevel" |> unbox<int>
                level >= 3 && amount <= 100000m))
        |> RoleBuilder.build)
    |> AuthorizationConfig.assign "user:77" "role:approver"
    |> AuthorizationHost.build

let decision =
    AuthorizationRequest.create (PrincipalId "user:77") (PermissionId.parse "invoice:approve")
    |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "acme" ])
    |> AuthorizationRequest.withAttributes
        (Map.ofList [ "amount", box 50000m; "managerLevel", box 3 ])
    |> Engine.evaluateAsync host.Engine CancellationToken.None
```

### Time-Bounded Assignments

```fsharp
open System

let startDate = DateTimeOffset.UtcNow
let endDate = startDate.AddDays(30.0)

let host =
    AuthorizationConfig.defaultConfig
    |> AuthorizationConfig.addRole (
        RoleBuilder.create "role:contractor" "Contractor"
        |> RoleBuilder.grantEverywhere "project:read"
        |> RoleBuilder.build)
    |> AuthorizationConfig.assignForWindow "user:50" "role:contractor" (Some startDate) (Some endDate)
    |> AuthorizationHost.build
```

### Testing Expiry with a Fixed Clock

The engine reads the current UTC time from a `TimeProvider`, once per call, to decide which
assignments and grants are active. It uses `TimeProvider.System` unless
`AuthorizationConfig.useTimeProvider` (or `AuthorizationEngine.withTimeProvider`) sets another, so a
test can move the clock instead of waiting:

```fsharp
open System
open System.Threading
open RealTree.Authzn

/// A clock the test sets by hand.
type FixedClock(start: DateTimeOffset) =
    inherit TimeProvider()
    member val Now = start with get, set
    override this.GetUtcNow() = this.Now

let clock = FixedClock(DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero))

let host =
    AuthorizationConfig.defaultConfig
    |> AuthorizationConfig.useTimeProvider clock
    |> AuthorizationConfig.addRole (
        RoleBuilder.create "role:contractor" "Contractor"
        |> RoleBuilder.grantEverywhere "project:read"
        |> RoleBuilder.build)
    |> AuthorizationConfig.assignForWindow "user:50" "role:contractor" None (Some (clock.Now.AddDays 30.0))
    |> AuthorizationHost.build

let decide () =
    AuthorizationRequest.create (PrincipalId "user:50") (PermissionId.parse "project:read")
    |> Engine.evaluateAsync host.Engine CancellationToken.None
    |> Async.AwaitTask
    |> Async.RunSynchronously

let beforeExpiry = decide () // Allowed

clock.Now <- clock.Now.AddDays 30.0
let atExpiry = decide () // Denied DenyReason.AssignmentNotActive: NotAfter is exclusive
```

The same clock decides grant expiry (`GrantMetadata.ExpiresAt`). `FakeTimeProvider` from the
`Microsoft.Extensions.TimeProvider.Testing` package works the same way.

### Revocation

```fsharp
let host =
    AuthorizationConfig.defaultConfig
    |> AuthorizationConfig.addRole (
        RoleBuilder.create "role:editor" "Editor"
        |> RoleBuilder.grantEverywhere "document:edit"
        |> RoleBuilder.build)
    |> AuthorizationConfig.assign "user:25" "role:editor"
    |> AuthorizationHost.build

// Later, revoke access
host.Revoke(PrincipalId "user:25", RoleId "role:editor")
```

## Querying Visible Resources

`Engine.evaluateAsync` answers "**may** this principal do X **here**?" — a yes/no for one resource. Its dual is "**which** resources may this principal do X to?" — the question a list, search, or export endpoint asks. Three functions answer it. They match permissions and scopes as evaluation does and consider only active assignments and active grants. `filterAsync` also evaluates ABAC conditions, so it returns exactly the candidates `evaluateAsync` would allow. `mayAnyAsync` and `visibleScopeAsync` have no per-resource attributes, so they ignore conditions: they can admit a resource that a grant's condition would deny.

### `filterAsync` — which of these?

Given a collection already in hand, return the subset the principal may act on. You supply a function from each candidate to its scope (and, optionally, to its ABAC attributes); the engine keeps exactly the ones `evaluateAsync` would allow: a candidate is kept when some active grant covers the permission, matches the candidate's scope, and has no condition or a condition that returns true for the candidate's attributes. A condition that throws counts as false.

```fsharp
// Of the orgs on this page, which may Alice read?
let! visible =
    Engine.filterAsync
        host.Engine
        CancellationToken.None
        (PrincipalId "user:alice")
        (PermissionId.parse "organizations:read")
        candidateOrgs
        (fun org -> Map.ofList [ "tenant", org.TenantId; "org", org.Id ]) // scope of each candidate
        (fun _ -> Map.empty)                                              // ABAC attributes (none here)
```

This is the post-filter for a list page: load the page, then drop what the caller may not see, without re-deriving scope rules in the handler. A candidate is returned exactly when evaluating it on its own would allow. `filterAsync` reads the stores once per call, however many candidates there are, and throws `OperationCanceledException` between candidates once the token is cancelled.

### `mayAnyAsync` — any at all?

A reachability gate for a collection: does the principal hold a grant that could admit **anything** within a partial scope? Use it to decide whether a list endpoint runs at all — a `403` versus an empty `200`.

```fsharp
let! canList =
    Engine.mayAnyAsync
        host.Engine
        CancellationToken.None
        (PrincipalId "user:alice")
        (PermissionId.parse "organizations:read")
        (Map.ofList [ "tenant", "acme" ])
```

`mayAnyAsync` is structural: it tests whether a grant *could* apply, not whether the concrete set is non-empty (an org-admin who is a member of no orgs still "may list" — `filterAsync` then returns `[]`). It does not evaluate ABAC conditions, since no per-resource attributes exist yet.

### `visibleScopeAsync` — the pushable predicate

Instead of post-filtering a page already loaded, materialise the set of resources the principal may act on as a `ScopeConstraint` to push into a query (a `WHERE` clause or id-set), so the data store does the filtering:

```fsharp
let! constraint' =
    Engine.visibleScopeAsync
        host.Engine
        CancellationToken.None
        (PrincipalId "user:alice")
        (PermissionId.parse "organizations:read")
        (Map.ofList [ "tenant", "acme" ])

match constraint' with
| Everything -> () // no restriction — select all in scope
| Nothing -> ()    // no access — return empty without querying
| Restricted clauses ->
    // A disjunction of clauses; each clause is a conjunction of key -> value-set constraints.
    // e.g. [ Map [ "tenant", Values (set ["acme"]); "org", Values (set ["sales-west"; "sales-east"]) ] ]
    // translates to: WHERE tenant = 'acme' AND org IN ('sales-west', 'sales-east')
    ()
```

The constraint ignores ABAC conditions: a grant with a condition contributes its clause as if the condition passed, so apply the condition yourself or use `filterAsync`. A grant confined only by a condition has no scope, so it makes the result `Everything`. The clauses are not narrowed to the partial scope's values, so apply the partial scope in the query as well (here, `tenant = 'acme'`).

`visibleScopeAsync` turns each contributing grant into a clause by **enumerating** its scope markers — `hierarchy` becomes the principal's subtree ids, `principal` becomes the principal's own value — so the resolver must produce those sets, not merely test one value. Implement `IScopeValueEnumerator` alongside `IScopeValueResolver`:

```fsharp
let resolver =
    { new IScopeValueResolver with
        member _.AdmitsAsync(principal, scopeKey, marker, requestValue, cancellationToken) =
            // ...the membership test used by evaluateAsync / filterAsync / mayAnyAsync...
            ValueTask<bool>(false)
      interface IScopeValueEnumerator with
          member _.EnumerateScopeAsync(principal, scopeKey, marker, cancellationToken) =
              match marker.Value with
              | ScopeMarkers.Principal -> ValueTask<_>(Some(Values(Set.singleton (principalValue principal scopeKey))))
              | ScopeMarkers.Hierarchy -> ValueTask<_>(Some(Values(orgSubtree principal)))
              | _ -> ValueTask<_>(None) } // marker not enumerable — visibleScopeAsync raises for it
```

A marker the enumerator returns `None` for cannot be pushed down soundly, so `visibleScopeAsync` raises `NotSupportedException` for it. It does the same when no resolver is configured or the resolver does not implement `IScopeValueEnumerator`, even when another grant would make the result `Everything`. Fall back to `filterAsync` for collections whose scopes are not enumerable. `evaluateAsync`, `allowedAmongAsync`, `grantsAmongAsync`, `filterAsync`, and `mayAnyAsync` never require enumeration; a resolver that implements only `AdmitsAsync` works with all of them.

### Choosing among them

| Question | Function | Returns | Resolver needs |
|---|---|---|---|
| May I, on this one? | `evaluateAsync` | `AuthorizationDecision` | `AdmitsAsync` |
| Which of these may I? | `filterAsync` | the admitted subset | `AdmitsAsync` |
| May I on anything here? | `mayAnyAsync` | `bool` | `AdmitsAsync` |
| What may I, as a query predicate? | `visibleScopeAsync` | `ScopeConstraint` | `AdmitsAsync` + `EnumerateScopeAsync` |

`filterAsync` filters a collection you already hold; `visibleScopeAsync` produces a predicate to fetch only the matching rows. Reach for `filterAsync` (or a `mayAnyAsync` gate) when the candidates are already loaded or their scopes are not enumerable; reach for `visibleScopeAsync` to push the restriction into the data store.

## Checking Many Permissions

`Engine.allowedAmongAsync` answers `evaluateAsync` for many permissions in one scope, such as which actions of a page to enable. It returns the candidates that `evaluateAsync`, given the same principal, scope and attributes, would allow. It reads the assignment store once and the role store at most once per active assignment, however many candidates there are. `Engine.grantsAmongAsync` returns the same permissions, each with every grant that allows it and that grant's role, in assignment and grant order, so a caller can tell a permission a role names from one a wildcard such as `*` covers.

```fsharp
let permissions = [ PermissionId.parse "organizations:read"; PermissionId.parse "organizations:delete" ]
let orgScope = Map.ofList [ "tenant", "acme"; "org", "sales-west" ]

// Which of these actions may Alice take on this org?
let! held =
    Engine.allowedAmongAsync
        host.Engine
        CancellationToken.None
        (PrincipalId "user:alice")
        permissions
        orgScope
        Map.empty // ABAC attributes passed to grant conditions

// Every grant that allows each held permission, and its role.
let! sources =
    Engine.grantsAmongAsync host.Engine CancellationToken.None (PrincipalId "user:alice") permissions orgScope Map.empty

for KeyValue(permission, grants) in sources do
    for source in grants do
        printfn "%s via %s (%s)" (PermissionId.format permission) source.Role.Value (PermissionPattern.format source.Grant.Permission)
```

## Grant Metadata, Revocation, and Policies

A grant is a `(permission, scope, condition)` triple plus `GrantMetadata` (`GrantMetadata.empty` when none is needed). Metadata is the seam for the audit and lifecycle concerns every consumer eventually invents sideways: who added the grant, why, who consented, when it expires, when it was revoked.

### Metadata

```fsharp
type GrantMetadata =
    { Source: string option              // who added it ("app:foo@1.0.0", "user:alice", "bootstrap")
      Reason: string option              // human-readable justification at write time
      ConsentedBy: PrincipalId option    // who clicked Grant
      ConsentedAt: DateTimeOffset option
      ExpiresAt: DateTimeOffset option   // per-grant time bound; engine treats expired grants as inactive
      RevokedAt: DateTimeOffset option   // non-None marks the grant inactive
      RevokedBy: PrincipalId option }
```

`GrantMetadata.empty` for callers that don't need it. `GrantMetadata.isActiveAt now metadata` returns false when `RevokedAt` is set or `now >= ExpiresAt`; the engine passes the current time from its `TimeProvider`. Every `Engine` function skips an inactive grant, as if it were absent. When no grant allows a request and no grant failed only on its condition, an inactive grant that covers the permission and matches the scope makes the deny reason `DenyReason.GrantNotActive`.

Attach metadata with `RoleBuilder.grantWith` (or `grantEverywhereWith` for an unscoped grant):

```fsharp
let auditor =
    RoleBuilder.create "role:auditor" "Auditor"
    |> RoleBuilder.grantWith
        "invoice:read"
        (Some (Map.ofList [ "tenant", ScopeValue.Literal "acme" ]))
        None
        { GrantMetadata.empty with
            Source = Some "user:alice"
            Reason = Some "Quarterly audit"
            ExpiresAt = Some (DateTimeOffset.UtcNow.AddDays 90.0) }
    |> RoleBuilder.build
```

The library does not interpret `Source` or `Reason` - they are caller free-form. Conventions emerge per consumer (e.g. `"app:{slug}@{version}#{installId}"` for marketplace-installed grants).

### Per-grant Revocation

Per-grant revocation lets a consumer turn off one permission inside a role without rebuilding the role. The grant's `GrantKey` addresses it: a SHA-256 of a versioned, length-prefixed encoding of the grant's permission pattern and scope, so two grants share a key exactly when their pattern and scope are equal. A role cannot hold two such grants: `RoleBuilder.build` and `InMemoryRoleStore.Add` throw, and a custom role store should call `Role.validate` on the roles it loads. So a key names one grant in its role. A key is an identifier, not a secret: anyone who knows the grant can compute it.

```fsharp
let key = GrantKey.forGrant grant
do! grantStore.RevokeGrantAsync(role.Id, key, PrincipalId "user:alice", DateTimeOffset.UtcNow, CancellationToken.None)
// Later:
do! grantStore.ReinstateGrantAsync(role.Id, key, CancellationToken.None)
```

With the in-memory role store, `AuthorizationHost` does the same without a grant store, recording the engine's current time as `RevokedAt`:

```fsharp
host.RevokeGrant(role.Id, key, PrincipalId "user:alice")
host.ReinstateGrant(role.Id, key)
```

`RevokeGrant` and `ReinstateGrant` throw `InvalidOperationException` when the host uses a custom `IRoleStore`.

`InMemoryGrantStore` wraps an `InMemoryRoleStore`: `RevokeGrantAsync` and `ReinstateGrantAsync` replace the role in that store with a copy whose matching grant has `RevokedAt` and `RevokedBy` set or cleared, under the store's write lock, so they are safe to call while requests are evaluated. Revoking a grant that is already revoked keeps the first `RevokedAt` and `RevokedBy`, and an unknown role or key changes nothing. The engine reads revocation only from the grants its `IRoleStore` returns, so a custom `IGrantStore` must write the metadata into the role definitions your `IRoleStore` reads.

### Write-Time Policy

`IGrantPolicy` is a hook consumers register to filter or gate grant writes. The library never calls it - it sits in the consumer's grant-write path:

```fsharp
[<RequireQualifiedAccess>]
type GrantPolicyDecision =
    | Allow
    | Reject of Reason: string * Code: string
    | RequireConsent of Reason: string * Tier: string

type IGrantPolicy =
    abstract EvaluateAsync: context: GrantPolicyContext * cancellationToken: CancellationToken -> Task<GrantPolicyDecision>
```

A policy that asks for consent before any wildcard grant:

```fsharp
type NoWildcardPolicy() =
    interface IGrantPolicy with
        member _.EvaluateAsync(context, cancellationToken) =
            Task.FromResult(
                if PermissionPattern.isWildcard context.Grant.Permission then
                    GrantPolicyDecision.RequireConsent(Reason = "Wildcard grant", Tier = "elevated")
                else
                    GrantPolicyDecision.Allow)

services.AddGrantPolicy<NoWildcardPolicy>() |> ignore
```

Register policies with `services.AddGrantPolicy<MyPolicy>()` (each as a singleton). `AddAuthzn` registers `IGrantPolicyChain`, which calls the policies in registration order and returns the first decision that is not `GrantPolicyDecision.Allow`, or `Allow` when every policy allows or none is registered. The `Tier` label on `RequireConsent` is consumer-defined - e.g. an app marketplace returns `"elevated"` for permissions outside its sandbox and drives a per-grant consent prompt off that label. A caller with no consent step should treat `RequireConsent` as `Reject`.

The context carries the principal performing the write, the target role, the proposed grant, and a free-form `Properties: Map<string,string>` for caller-defined values (app installation id, tenant slug, calling endpoint, etc.). Policies may inspect `Properties` to scope their rules.

The grant-write path runs the chain and enforces its decision:

```fsharp
// policyChain: the IGrantPolicyChain from the container; proposedGrant: the PermissionGrant to add
let context: GrantPolicyContext =
    { Principal = PrincipalId "user:alice"
      Role = RoleId "role:auditor"
      Grant = proposedGrant
      Properties = Map.ofList [ "tenant", "acme" ] }

let! decision = policyChain.EvaluateAsync(context, cancellationToken)

match decision with
| GrantPolicyDecision.Allow -> () // write the grant
| GrantPolicyDecision.Reject(reason, code) -> () // refuse the write
| GrantPolicyDecision.RequireConsent(reason, tier) -> () // ask for consent, or refuse when there is no consent step
```

## Dependency Injection

### Registration

```fsharp
open RealTree.Authzn
open Microsoft.Extensions.DependencyInjection

services.AddAuthzn(fun config ->
    config
    |> AuthorizationConfig.addRole (
        RoleBuilder.create "role:admin" "Admin"
        |> RoleBuilder.grantEverywhere "system:*"
        |> RoleBuilder.build)
    |> AuthorizationConfig.addRole (
        RoleBuilder.create "role:reader" "Reader"
        |> RoleBuilder.grantEverywhere "system:read"
        |> RoleBuilder.build)
    |> AuthorizationConfig.assign "user:1" "role:admin") |> ignore
```

`AddAuthzn` runs `configure` immediately, builds an `AuthorizationHost` over in-memory stores, and registers the host, its `AuthorizationEngine` and `IGrantPolicyChain` as singletons.

### Usage in Services

```fsharp
type InvoiceService(engine: AuthorizationEngine) =

    member _.GetInvoiceAsync(principalId: string, invoiceId: string, cancellationToken: CancellationToken) =
        task {
            let! decision =
                AuthorizationRequest.create
                    (PrincipalId principalId)
                    (PermissionId.parse "invoice:read")
                |> AuthorizationRequest.withScope
                    (Map.ofList [ "tenant", getTenantForInvoice invoiceId ])
                |> Engine.evaluateAsync engine cancellationToken

            match decision with
            | Allowed _ -> return! loadInvoiceAsync invoiceId cancellationToken
            | Denied reason -> return failwith $"Access denied: {reason}"
        }
```

## Custom Persistence

The library provides `IRoleStore` and `IAssignmentStore` interfaces for custom persistence implementations, `IGrantStore` for revoking single grants in your role store, and `IScopeValueResolver` (with the optional `IScopeValueEnumerator` for `visibleScopeAsync`) for dynamic scope resolution.

The engine calls the stores from every request it evaluates, which may run on several threads at once, so an implementation must be safe for concurrent calls. `GetAssignmentsForPrincipalAsync` may return inactive assignments, which the engine filters out; their order decides which role an `Allowed` decision names when several allow. A role store should call `Role.validate` on each role it loads: it throws `ArgumentException` when two grants share a permission pattern and scope, and so a `GrantKey`. Each store and resolver method receives the `CancellationToken` the caller passed to the `Engine` function; pass it on to database and HTTP calls.

### Interface Definitions

```fsharp
type IRoleStore =
    abstract GetRoleAsync: id: RoleId * cancellationToken: CancellationToken -> Task<Role option>

type IAssignmentStore =
    abstract GetAssignmentsForPrincipalAsync:
        principal: PrincipalId * cancellationToken: CancellationToken -> Task<Assignment list>

type IGrantStore =
    abstract RevokeGrantAsync:
        roleId: RoleId * grantKey: GrantKey * revokedBy: PrincipalId * at: DateTimeOffset * cancellationToken: CancellationToken
            -> Task
    abstract ReinstateGrantAsync: roleId: RoleId * grantKey: GrantKey * cancellationToken: CancellationToken -> Task

type IScopeValueResolver =
    abstract AdmitsAsync:
        principal: PrincipalId * scopeKey: string * marker: MarkerName * requestValue: string * cancellationToken: CancellationToken
            -> ValueTask<bool>
    // true  = the marker, resolved for the principal, admits the requested value
    // false = it does not, or this resolver does not recognise the marker

type IScopeValueEnumerator =
    abstract EnumerateScopeAsync:
        principal: PrincipalId * scopeKey: string * marker: MarkerName * cancellationToken: CancellationToken
            -> ValueTask<ScopeValueSet option>
    // None = this resolver cannot list the values; visibleScopeAsync then throws NotSupportedException
```

### Custom Store Example

```fsharp
open Microsoft.EntityFrameworkCore

type DbRoleStore(contextFactory: IDbContextFactory<AuthorizationDbContext>) =

    interface IRoleStore with
        member _.GetRoleAsync(id, cancellationToken) =
            task {
                // The engine calls the store from concurrent requests, and a DbContext is not
                // thread-safe, so each call uses its own context.
                use context = contextFactory.CreateDbContext()

                let! entity =
                    context.Roles
                        .Include(fun r -> r.Grants)
                        .FirstOrDefaultAsync((fun r -> r.Id = RoleId.value id), cancellationToken)

                match entity with
                | null -> return None
                | entity ->
                    let grants =
                        entity.Grants
                        |> Seq.map (fun g ->
                            // Patterns and scope values have text forms that read back exactly.
                            { Permission = PermissionPattern.parse g.Permission
                              Scope = deserializeScope g.ScopeJson |> ScopeValue.parseScope
                              Condition = None
                              Metadata = GrantMetadata.empty })
                        |> Seq.toList

                    let role = { Id = RoleId entity.Id; Name = entity.Name; Grants = grants }
                    // Throws ArgumentException when two grants share a permission pattern and scope.
                    Role.validate role
                    return Some role
            }
```

### Registration with Custom Stores

```fsharp
// contextFactory: an IDbContextFactory<AuthorizationDbContext>, such as
// PooledDbContextFactory<AuthorizationDbContext>(options)
let roleStore = DbRoleStore(contextFactory) :> IRoleStore
let assignmentStore = DbAssignmentStore(contextFactory) :> IAssignmentStore

services.AddAuthzn(roleStore, assignmentStore) |> ignore

// With a scope resolver:
services.AddAuthzn(roleStore, assignmentStore, myScopeResolver) |> ignore
```

Without dependency injection, pass the stores to the configuration; its roles and assignments are then ignored:

```fsharp
let host =
    AuthorizationConfig.defaultConfig
    |> AuthorizationConfig.useRoleStore roleStore
    |> AuthorizationConfig.useAssignmentStore assignmentStore
    |> AuthorizationHost.build
```

The stores overload of `AddAuthzn` takes no clock. To set a `TimeProvider` with custom stores, call `AddAuthzn(fun config -> ...)` and pipe `config` through `useRoleStore`, `useAssignmentStore` and `useTimeProvider`.

To use the `Engine` functions without a host, build the engine itself:

```fsharp
let engine =
    AuthorizationEngine.create roleStore assignmentStore
    |> AuthorizationEngine.withScopeResolver myScopeResolver
    |> AuthorizationEngine.withTimeProvider TimeProvider.System
```

## Runtime Management

The `AuthorizationHost` provides convenience methods for in-memory store manipulation:

```fsharp
let host = AuthorizationConfig.defaultConfig |> AuthorizationHost.build

// Add role at runtime
let newRole =
    RoleBuilder.create "role:analyst" "Data Analyst"
    |> RoleBuilder.grantEverywhere "report:read"
    |> RoleBuilder.grantEverywhere "report:export"
    |> RoleBuilder.build

host.AddRole(newRole)

// Add assignment at runtime
host.AddAssignment(Assignment.create (PrincipalId "user:new") (RoleId "role:analyst"))

// Revoke assignment at runtime
host.Revoke(PrincipalId "user:old", RoleId "role:analyst")
```

`AddRole` replaces any role with the same id and throws `ArgumentException` for a role with two grants of the same permission pattern and scope; `AddAssignment` appends after the principal's existing assignments; `Revoke` marks every assignment of the role to the principal revoked. `AddRole` works only with `InMemoryRoleStore`, and `AddAssignment` and `Revoke` only with `InMemoryAssignmentStore`; they throw `InvalidOperationException` when custom stores are used.

The in-memory stores are safe for concurrent use: these methods can run while other threads evaluate requests. Each store replaces an immutable snapshot under a lock, and each read sees one snapshot.

## Architecture

### Evaluation Flow

1. Retrieve all assignments for the principal; if there are none, deny with `NoAssignments`
2. Filter assignments to only those active at the current UTC time, read once from the engine's `TimeProvider`; if none is active, deny with `AssignmentNotActive`
3. For each active assignment, in the order the assignment store returns them (the order they were configured, for the in-memory store):
   - Retrieve the role definition, skipping an assignment whose role is not found
   - Check each permission grant in the role, in order:
     - Match permission (exact or wildcard)
     - Match scope (resolve markers via `IScopeValueResolver` if configured, then check granted scope is subset of requested scope)
     - Check that the grant's metadata is active (not revoked or expired)
     - Evaluate the ABAC condition if present; a condition that throws counts as false
   - The first grant that passes every check allows the request, and the decision names it and its role. A grant that fails a check withholds only itself; the search continues with the next grant.
4. If no grant allows, return the first deny reason that applies (see [Deny Reasons](#deny-reasons))

### Permission Matching

Permissions are matched by comparing resource and action components separately, as `PermissionPattern.covers` does:

```fsharp
let covered = PermissionPattern.covers (PermissionId.parse "invoice:read") (PermissionPattern.parse "invoice:*") // true
```

Exact match:
```
Granted: "invoice:read"
Requested: "invoice:read"
Result: Match (resource="invoice" matches, action="read" matches)
```

Wildcard action:
```
Granted: "invoice:*"
Requested: "invoice:read"
Result: Match (resource="invoice" matches, action="*" matches anything)
```

Wildcard resource and action:
```
Granted: "*" (equivalent to "*:*")
Requested: "invoice:read"
Result: Match (both wildcards match anything)
```

Hierarchical resource match:
```
Granted: "project:task:*"
Requested: "project:task:delete"
Result: Match (resource="project:task" matches, action="*" matches "delete")
```

A wildcard is a whole segment, not a prefix:
```
Granted: "project:*"
Requested: "project:task:delete"
Result: No match (resource="project" does not match "project:task")
```

No match - different resources:
```
Granted: "invoice:*"
Requested: "project:read"
Result: No match (resource "invoice" != "project")
```

No match - different actions:
```
Granted: "invoice:read"
Requested: "invoice:delete"
Result: No match (action "read" != "delete")
```

### Scope Matching

All keys in the granted scope must exist in the requested scope with matching values. Additional keys in the requested scope are permitted. A literal matches only the same text, compared case-sensitively.

```
Granted: { "tenant": "acme" }
Requested: { "tenant": "acme"; "project": "alpha" }
Result: Match
```

```
Granted: { "tenant": "acme"; "project": "alpha" }
Requested: { "tenant": "acme" }
Result: No match (missing required key "project")
```

### Scope Marker Resolution

When a scope value in a grant is a marker, the scope resolver decides whether it admits the requested value. It is never compared as text.

```
Resolver configured: Yes
Granted: { "tenant": ScopeValue.principal }
Requested: { "tenant": "acme" }
Resolution: resolver.AdmitsAsync(principal, "tenant", MarkerName "principal", "acme", cancellationToken) -> true
Result: Match (resolver determined the principal's tenant is "acme")
```

```
Resolver configured: Yes
Granted: { "org": ScopeValue.hierarchy }
Requested: { "org": "sales-west" }
Resolution: resolver.AdmitsAsync(principal, "org", MarkerName "hierarchy", "sales-west", cancellationToken) -> true
Result: Match (resolver determined "sales-west" is in the principal's org hierarchy)
```

```
Resolver configured: No (or the resolver does not recognise the marker)
Granted: { "tenant": ScopeValue.principal }
Requested: { "tenant": "@principal" }
Result: No match (a marker is never compared as text, not even with its own name)
```

### ABAC Evaluation

Conditions are evaluated after permission, metadata and scope matching. A condition that returns false or throws withholds only its own grant: another grant, in the same role or another, can still allow the request. When no grant allows and at least one grant failed only on its condition, the request is denied with `DenyReason.AttributeEvaluationFailed`.

## ISO 27001:2022 Alignment

Authzn provides technical controls that support compliance with several ISO 27001:2022 Annex A controls. The table below maps library features to the controls they help satisfy.

### A.5.15 -- Access Control

*Establish and implement rules for controlling logical access to information and associated assets.*

| Library Feature | How It Supports A.5.15 |
|---|---|
| RBAC (roles assigned to principals) | Implements role-based access policies as the primary control mechanism |
| ABAC (runtime conditions) | Supports context-aware, attribute-driven access rules beyond static role assignments |
| Scoped permissions | Enforces access policies scoped to organizational boundaries (tenant, project) |
| Purely additive model | Establishes a default-deny posture -- access is only granted when explicitly assigned |
| Wildcard permissions | Enables flexible yet structured permission grant patterns aligned with policy rules |

### A.5.16 -- Identity Management

*Manage the full lifecycle of identities, including registration and administration.*

| Library Feature | How It Supports A.5.16 |
|---|---|
| Principal-to-role assignments | Associates identities with their authorized roles |
| Scope markers (`@principal`, `@hierarchy`) | Supports dynamic identity-contextual resolution, tying access decisions to identity attributes |
| Time-bounded assignments (`NotBefore`/`NotAfter`) | Enforces lifecycle-aware identity-to-role bindings that activate and expire automatically |

### A.5.18 -- Access Rights

*Provision, review, modify, and revoke access rights in accordance with the access control policy.*

| Library Feature | How It Supports A.5.18 |
|---|---|
| Role assignments | Implements the provisioning of access rights |
| Revocation | Supports prompt removal of access rights: a revoked assignment, or a grant revoked through `IGrantStore`, stops allowing requests from the next evaluation |
| Time-bounded assignments | Supports automatic expiry of access rights, reducing the risk of stale permissions |
| Pluggable persistence (store interfaces) | Enables integration with existing access right review and audit processes |
| Scoped permissions | Ensures access rights are granted at the appropriate organizational scope |

### A.5.3 -- Segregation of Duties

*Separate conflicting duties and areas of responsibility to reduce opportunities for unauthorized modification or misuse.*

| Library Feature | How It Supports A.5.3 |
|---|---|
| RBAC with distinct roles | Enables defining separate roles with non-overlapping permissions to enforce duty segregation |
| Scoped permissions | Restricts what a given role can do within a specific scope, preventing cross-boundary privilege |
| Purely additive model | Makes it straightforward to audit exactly what permissions each role grants -- no hidden deny overrides that obscure the effective access picture |

### A.8.2 -- Privileged Access Rights

*Restrict and manage the allocation and use of privileged access rights.*

| Library Feature | How It Supports A.8.2 |
|---|---|
| Granular role definitions | Supports defining privileged roles separately from standard roles, enforcing least privilege |
| Time-bounded assignments | Enables just-in-time (JIT) privileged access that automatically expires |
| Revocation | Supports prompt removal of privileged access when no longer needed |
| Scoped permissions | Constrains privileged access to specific tenants or projects rather than granting system-wide privilege |

### A.8.3 -- Information Access Restriction

*Restrict access to information and associated assets using technical enforcement mechanisms aligned with the access control policy.*

This is the technical enforcement counterpart to A.5.15. Where A.5.15 is the organizational rule book, A.8.3 is the technical enforcement engine -- which is exactly what this library is.

| Library Feature | How It Supports A.8.3 |
|---|---|
| Runtime permission checks | The library is the enforcement mechanism -- it evaluates whether a principal has a specific permission |
| ABAC conditions | Implements dynamic access management that adjusts based on runtime context |
| Scoped permissions | Enforces granular, topic-specific access restrictions at the data/resource level |
| Deny reasons | Provides structured feedback on why access was denied, supporting diagnostics and audit |
| Scope markers with dynamic resolution | Supports context-sensitive restriction (e.g., "only your own resources" via `@principal`) |

### A.8.15 -- Logging

*Produce, store, protect, and analyze logs recording activities, exceptions, and security-relevant events.*

The library does not perform logging itself, but its outputs are designed to feed directly into security logging infrastructure.

| Library Feature | How It Supports A.8.15 |
|---|---|
| Structured deny reasons | Machine-readable denial categories (`NoAssignments`, `NoMatchingPermission`, `ScopeMismatch`, `AssignmentNotActive`, `GrantNotActive`, `AttributeEvaluationFailed`) feed directly into security logs |
| Deterministic decisions | Every permission check produces a structured `AuthorizationDecision` that can be logged |
| Matched role and grant | Allowed decisions name the role and the permission pattern of the first grant that allowed (which may be a wildcard such as `*`); `grantsAmongAsync` lists every grant that allows, providing audit trail detail |

### Controls Summary

| Control | Name | Relevance |
|---|---|---|
| A.5.3 | Segregation of Duties | Direct -- RBAC with scoped permissions enables duty segregation |
| A.5.15 | Access Control | Direct -- the library implements access control policy rules |
| A.5.16 | Identity Management | Direct -- manages identity-to-role bindings with lifecycle support |
| A.5.18 | Access Rights | Direct -- provisioning, time-bounding, and revocation of access rights |
| A.8.2 | Privileged Access Rights | Direct -- time-bounded, scoped, revocable privileged access management |
| A.8.3 | Information Access Restriction | Direct -- the library is the technical enforcement mechanism |
| A.8.15 | Logging | Supporting -- structured decision outputs designed for security logging |

## Design Constraints

- No deny rules or negative permissions
- No direct permissions on principals (all permissions flow through roles)
- ABAC conditions cannot be persisted (they are code-based functions)
- No built-in audit logging
- No permission inheritance or role hierarchies
- No query language or DSL for permission expressions

## Performance

The in-memory stores are designed for low-latency evaluation. Authorization checks complete in sub-microsecond time for typical configurations.

### Evaluation Benchmarks

Measured with BenchmarkDotNet 0.14.0 on .NET 10.0.12, Ubuntu 24.04.5 LTS, on a cloud VM with an Intel Xeon processor at 2.10 GHz (4 cores).

| Scenario | Mean | Allocated |
|---|---:|---:|
| Allow - simple (1 role, 1 grant) | 301 ns | 528 B |
| Deny - no matching permission | 283 ns | 496 B |
| Allow - scoped (2 scope keys) | 406 ns | 704 B |
| Deny - scope mismatch | 358 ns | 648 B |
| Allow - ABAC condition | 302 ns | 528 B |
| Allow - 50 roles (worst-case traversal) | 10,025 ns | 8,792 B |

### Assignment Store Scaling

The `InMemoryAssignmentStore` keeps an immutable map keyed by principal, so a lookup takes time logarithmic in the number of principals and grows only slowly with the total number of assignments in the system.

| Total Assignments | Mean | Allocated |
|---|---:|---:|
| 100 | 391 ns | 528 B |
| 1,000 | 436 ns | 528 B |
| 10,000 | 447 ns | 528 B |

### Running Benchmarks

```bash
dotnet run --project benchmarks/Authzn.Benchmarks/Authzn.Benchmarks.fsproj -c Release -- --filter '*Benchmarks*'
```

### Guidance for Custom Stores

- Each authorization check loads all of the principal's assignments, then looks up the role of each active assignment, in order, until a grant allows; a denied request looks up all of them
- Consider caching role definitions in custom store implementations
- The evaluation cost scales linearly with the number of roles assigned to a principal, not with total roles or assignments in the system

## Development

Build and test with `dotnet build Authzn.slnx` and `dotnet test Authzn.slnx` (.NET 10 SDK). The public API of each package is frozen in `api/RealTree.Authzn.txt` and `api/RealTree.Authzn.CSharp.txt`: a change to the public surface fails `PublicApiTests`, which writes the new surface to `api/<assembly>.received.txt`. If the change is intended, replace the listing with that file and commit it with the change, so the API diff shows in review.

## License

MIT
