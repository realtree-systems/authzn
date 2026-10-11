module RealTree.Authzn.Tests.BuilderTests

open System.Threading
open Xunit
open RealTree.Authzn

[<Fact>]
let ``RoleBuilder creates role with grants`` () =
    let role =
        RoleBuilder.create "editor" "Editor"
        |> RoleBuilder.grantEverywhere "documents:read"
        |> RoleBuilder.grantEverywhere "documents:write"
        |> RoleBuilder.build

    Assert.Equal(RoleId "editor", role.Id)
    Assert.Equal("Editor", role.Name)
    Assert.Equal(2, role.Grants.Length)
    Assert.Equal(PermissionPattern.parse "documents:read", role.Grants[0].Permission)
    Assert.Equal(PermissionPattern.parse "documents:write", role.Grants[1].Permission)

[<Fact>]
let ``RoleBuilder grants with scope`` () =
    let scope = Map.ofList [ "tenant", ScopeValue.Literal "acme" ]

    let role =
        RoleBuilder.create "scoped" "Scoped"
        |> RoleBuilder.grant "documents:read" (Some scope) None
        |> RoleBuilder.build

    Assert.Equal(1, role.Grants.Length)
    Assert.Equal<GrantScope>(Map.ofList [ "tenant", ScopeValue.Literal "acme" ], role.Grants[0].Scope)

[<Fact>]
let ``grant fails closed when unconfined - use grantEverywhere instead`` () =
    let state = RoleBuilder.create "r" "R"

    // A grant with no scope and no condition would apply to every resource in every tenant, so
    // RoleBuilder.grant throws ArgumentException for a None scope and for an empty one.
    Assert.Throws<System.ArgumentException>(fun () -> RoleBuilder.grant "docs:read" None None state |> ignore)
    |> ignore
    Assert.Throws<System.ArgumentException>(fun () -> RoleBuilder.grant "docs:read" (Some Map.empty) None state |> ignore)
    |> ignore

    // These do not throw: grantEverywhere, a non-empty scope, and a condition with no scope.
    RoleBuilder.grantEverywhere "docs:read" state |> ignore
    RoleBuilder.grant "docs:read" (Some(Map.ofList [ "tenant", ScopeValue.Literal "acme" ])) None state |> ignore
    RoleBuilder.grant "docs:read" None (Some(fun _ -> true)) state |> ignore

[<Fact>]
let ``grant rejects an empty scope even with a condition`` () =
    let state = RoleBuilder.create "r" "R"
    let condition = Some(fun (_: AttributeBag) -> true)

    Assert.Throws<System.ArgumentException>(fun () -> RoleBuilder.grant "docs:read" (Some Map.empty) condition state |> ignore)
    |> ignore

    Assert.Throws<System.ArgumentException>(fun () ->
        RoleBuilder.grantWith "docs:read" (Some Map.empty) condition GrantMetadata.empty state |> ignore)
    |> ignore

[<Fact>]
let ``build rejects two grants with the same pattern and scope`` () =
    let tenant = Some(Map.ofList [ "tenant", ScopeValue.Literal "acme" ])

    let state =
        RoleBuilder.create "r" "R"
        |> RoleBuilder.grant "invoices:approve" tenant (Some(fun _ -> true))
        |> RoleBuilder.grant "invoices:approve" tenant (Some(fun _ -> false))

    Assert.Throws<System.ArgumentException>(fun () -> RoleBuilder.build state |> ignore) |> ignore

[<Fact>]
let ``build accepts grants of one pattern with different scopes`` () =
    let role =
        RoleBuilder.create "r" "R"
        |> RoleBuilder.grant "invoices:approve" (Some(Map.ofList [ "tenant", ScopeValue.Literal "acme" ])) None
        |> RoleBuilder.grant "invoices:approve" (Some(Map.ofList [ "tenant", ScopeValue.Literal "globex" ])) None
        |> RoleBuilder.build

    Assert.Equal(2, role.Grants.Length)

[<Fact>]
let ``InMemoryRoleStore.Add rejects a role with two grants of the same pattern and scope`` () =
    let grant condition =
        { Permission = PermissionPattern.parse "invoices:approve"
          Scope = Map.empty
          Condition = condition
          Metadata = GrantMetadata.empty }

    let role = { Id = RoleId "r"; Name = "R"; Grants = [ grant None; grant (Some(fun _ -> true)) ] }

    Assert.Throws<System.ArgumentException>(fun () -> InMemoryRoleStore().Add role) |> ignore

[<Fact>]
let ``AuthorizationConfig pipeline builds working engine`` () =
    task {
        let role =
            RoleBuilder.create "reader" "Reader"
            |> RoleBuilder.grantEverywhere "documents:read"
            |> RoleBuilder.build

        let host =
            AuthorizationConfig.defaultConfig
            |> AuthorizationConfig.addRole role
            |> AuthorizationConfig.assign "user-1" "reader"
            |> AuthorizationHost.build

        let request =
            AuthorizationRequest.create (PrincipalId "user-1") (PermissionId.create "documents" "read")

        let! decision = Engine.evaluateAsync host.Engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``AuthorizationConfig revoke works`` () =
    task {
        let role =
            RoleBuilder.create "reader" "Reader"
            |> RoleBuilder.grantEverywhere "documents:read"
            |> RoleBuilder.build

        let host =
            AuthorizationConfig.defaultConfig
            |> AuthorizationConfig.addRole role
            |> AuthorizationConfig.assign "user-1" "reader"
            |> AuthorizationConfig.revoke "user-1" "reader"
            |> AuthorizationHost.build

        let request =
            AuthorizationRequest.create (PrincipalId "user-1") (PermissionId.create "documents" "read")

        let! decision = Engine.evaluateAsync host.Engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.AssignmentNotActive, decision)
    }

[<Fact>]
let ``AuthorizationConfig revoke leaves assignments added after it active`` () =
    task {
        let role =
            RoleBuilder.create "reader" "Reader"
            |> RoleBuilder.grantEverywhere "documents:read"
            |> RoleBuilder.build

        let host =
            AuthorizationConfig.defaultConfig
            |> AuthorizationConfig.addRole role
            |> AuthorizationConfig.revoke "user-1" "reader"
            |> AuthorizationConfig.assign "user-1" "reader"
            |> AuthorizationHost.build

        let request =
            AuthorizationRequest.create (PrincipalId "user-1") (PermissionId.create "documents" "read")

        let! decision = Engine.evaluateAsync host.Engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``AuthorizationConfig rejects a second role with the same id`` () =
    let role name =
        RoleBuilder.create "editor" name
        |> RoleBuilder.grantEverywhere "documents:read"
        |> RoleBuilder.build

    let config = AuthorizationConfig.defaultConfig |> AuthorizationConfig.addRole (role "Editor v1")

    Assert.Throws<System.ArgumentException>(fun () -> AuthorizationConfig.addRole (role "Editor v2") config |> ignore)
    |> ignore

[<Fact>]
let ``AuthorizationHost checks assignments in configuration order`` () =
    task {
        let role id =
            RoleBuilder.create id id
            |> RoleBuilder.grantEverywhere "documents:read"
            |> RoleBuilder.build

        let host =
            AuthorizationConfig.defaultConfig
            |> AuthorizationConfig.addRole (role "editor")
            |> AuthorizationConfig.addRole (role "reader")
            |> AuthorizationConfig.assign "user-1" "editor"
            |> AuthorizationConfig.assign "user-1" "reader"
            |> AuthorizationHost.build

        let request =
            AuthorizationRequest.create (PrincipalId "user-1") (PermissionId.create "documents" "read")

        let! decision = Engine.evaluateAsync host.Engine CancellationToken.None request
        Assert.Equal(Allowed(RoleId "editor", PermissionPattern.parse "documents:read"), decision)
    }

[<Fact>]
let ``AuthorizationHost runtime AddRole works`` () =
    task {
        let host =
            AuthorizationConfig.defaultConfig
            |> AuthorizationConfig.assign "user-1" "late-role"
            |> AuthorizationHost.build

        let role =
            RoleBuilder.create "late-role" "Late"
            |> RoleBuilder.grantEverywhere "docs:read"
            |> RoleBuilder.build

        host.AddRole(role)

        let request =
            AuthorizationRequest.create (PrincipalId "user-1") (PermissionId.create "docs" "read")

        let! decision = Engine.evaluateAsync host.Engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``AuthorizationHost runtime AddAssignment works`` () =
    task {
        let role =
            RoleBuilder.create "reader" "Reader"
            |> RoleBuilder.grantEverywhere "docs:read"
            |> RoleBuilder.build

        let host =
            AuthorizationConfig.defaultConfig
            |> AuthorizationConfig.addRole role
            |> AuthorizationHost.build

        host.AddAssignment(Assignment.create (PrincipalId "user-1") (RoleId "reader"))

        let request =
            AuthorizationRequest.create (PrincipalId "user-1") (PermissionId.create "docs" "read")

        let! decision = Engine.evaluateAsync host.Engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``AuthorizationHost runtime Revoke works`` () =
    task {
        let role =
            RoleBuilder.create "reader" "Reader"
            |> RoleBuilder.grantEverywhere "docs:read"
            |> RoleBuilder.build

        let host =
            AuthorizationConfig.defaultConfig
            |> AuthorizationConfig.addRole role
            |> AuthorizationConfig.assign "user-1" "reader"
            |> AuthorizationHost.build

        host.Revoke(PrincipalId "user-1", RoleId "reader")

        let request =
            AuthorizationRequest.create (PrincipalId "user-1") (PermissionId.create "docs" "read")

        let! decision = Engine.evaluateAsync host.Engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
    }

[<Fact>]
let ``AuthorizationHost with custom stores`` () =
    task {
        let roleStore = InMemoryRoleStore()

        let role =
            RoleBuilder.create "r" "R"
            |> RoleBuilder.grantEverywhere "a:b"
            |> RoleBuilder.build

        roleStore.Add(role)

        let assignmentStore = InMemoryAssignmentStore()
        assignmentStore.Add(Assignment.create (PrincipalId "u") (RoleId "r"))

        let host =
            AuthorizationConfig.defaultConfig
            |> AuthorizationConfig.useRoleStore roleStore
            |> AuthorizationConfig.useAssignmentStore assignmentStore
            |> AuthorizationHost.build

        let request =
            AuthorizationRequest.create (PrincipalId "u") (PermissionId.create "a" "b")

        let! decision = Engine.evaluateAsync host.Engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }
