module Authzn.Tests.Helpers

open System
open System.Threading.Tasks
open Authzn

let testPrincipal = PrincipalId "user-1"
let otherPrincipal = PrincipalId "user-2"

let readerRole =
    { Id = RoleId "reader"
      Name = "Reader"
      Grants =
        [ { Permission = PermissionPattern.parse "documents:read"
            Scope = Map.empty
            Condition = None
            Metadata = GrantMetadata.empty } ] }

let writerRole =
    { Id = RoleId "writer"
      Name = "Writer"
      Grants =
        [ { Permission = PermissionPattern.parse "documents:read"
            Scope = Map.empty
            Condition = None
            Metadata = GrantMetadata.empty }
          { Permission = PermissionPattern.parse "documents:write"
            Scope = Map.empty
            Condition = None
            Metadata = GrantMetadata.empty } ] }

let adminRole =
    { Id = RoleId "admin"
      Name = "Administrator"
      Grants =
        [ { Permission = PermissionPattern.parse "*"
            Scope = Map.empty
            Condition = None
            Metadata = GrantMetadata.empty } ] }

let buildEngine (roles: Role list) (assignments: Assignment list) : AuthorizationEngine =
    let roleStore = InMemoryRoleStore()

    for r in roles do
        roleStore.Add(r)

    let assignmentStore = InMemoryAssignmentStore()

    for a in assignments do
        assignmentStore.Add(a)

    AuthorizationEngine.create roleStore assignmentStore

let buildEngineWithResolver (roles: Role list) (assignments: Assignment list) (resolver: IScopeValueResolver) =
    buildEngine roles assignments |> AuthorizationEngine.withScopeResolver resolver

/// A resolver whose AdmitsAsync returns <c>admits</c>'s answer as a completed ValueTask.
let syncResolver (admits: PrincipalId -> string -> MarkerName -> string -> bool) : IScopeValueResolver =
    { new IScopeValueResolver with
        member _.AdmitsAsync(principal, key, marker, requestValue, _cancellationToken) =
            ValueTask<bool>(admits principal key marker requestValue) }

/// A clock that always reads <c>now</c>.
type FixedTimeProvider(now: DateTimeOffset) =
    inherit TimeProvider()
    override _.GetUtcNow() = now
