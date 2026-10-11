module Authzn.Tests.EdgeCaseTests

open System
open System.Threading
open Xunit
open Authzn
open Authzn.Tests.Helpers

[<Fact>]
let ``denies when assignment references a role not in the store`` () =
    task {
        let engine =
            buildEngine [] [ Assignment.create testPrincipal (RoleId "ghost-role") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "docs" "read")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.NoMatchingPermission, decision)
    }

[<Fact>]
let ``denies when role has no grants`` () =
    task {
        let emptyRole =
            { Id = RoleId "empty"
              Name = "Empty"
              Grants = [] }

        let engine =
            buildEngine [ emptyRole ] [ Assignment.create testPrincipal (RoleId "empty") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "docs" "read")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.NoMatchingPermission, decision)
    }

[<Fact>]
let ``allows when at least one assignment is active with matching permission`` () =
    task {
        let expired =
            { Assignment.create testPrincipal (RoleId "reader") with
                NotAfter = Some(DateTimeOffset.UtcNow.AddHours(-1.0)) }

        let active = Assignment.create testPrincipal (RoleId "reader")

        let engine = buildEngine [ readerRole ] [ expired; active ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``denies with AssignmentNotActive when all assignments are inactive`` () =
    task {
        let expired =
            { Assignment.create testPrincipal (RoleId "reader") with
                NotAfter = Some(DateTimeOffset.UtcNow.AddHours(-1.0)) }

        let revoked =
            Assignment.create testPrincipal (RoleId "writer") |> Assignment.revoke

        let engine = buildEngine [ readerRole; writerRole ] [ expired; revoked ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.AssignmentNotActive, decision)
    }

[<Fact>]
let ``principal cannot use another principal's assignments`` () =
    task {
        let engine =
            buildEngine
                [ writerRole ]
                [ Assignment.create otherPrincipal (RoleId "writer") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "write")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.NoAssignments, decision)
    }

[<Fact>]
let ``hierarchical resource permission only matches exact resource`` () =
    task {
        let role =
            { Id = RoleId "task-reader"
              Name = "Task Reader"
              Grants =
                [ { Permission = PermissionPattern.parse "project:task:read"
                    Scope = Map.empty
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        let engine =
            buildEngine [ role ] [ Assignment.create testPrincipal (RoleId "task-reader") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "project:task" "read")

        let! allowed = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(allowed.IsAllowed)

        let request2 =
            AuthorizationRequest.create testPrincipal (PermissionId.create "project" "read")

        let! denied = Engine.evaluateAsync engine CancellationToken.None request2
        Assert.False(denied.IsAllowed)
        Assert.Equal(Denied DenyReason.NoMatchingPermission, denied)
    }

[<Fact>]
let ``wildcard resource still requires action match`` () =
    task {
        let role =
            { Id = RoleId "all-read"
              Name = "All Read"
              Grants =
                [ { Permission = PermissionPattern.parse "*:read"
                    Scope = Map.empty
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        let engine =
            buildEngine [ role ] [ Assignment.create testPrincipal (RoleId "all-read") ]

        let readRequest =
            AuthorizationRequest.create testPrincipal (PermissionId.create "anything" "read")

        let! allowed = Engine.evaluateAsync engine CancellationToken.None readRequest
        Assert.True(allowed.IsAllowed)

        let writeRequest =
            AuthorizationRequest.create testPrincipal (PermissionId.create "anything" "write")

        let! denied = Engine.evaluateAsync engine CancellationToken.None writeRequest
        Assert.False(denied.IsAllowed)
        Assert.Equal(Denied DenyReason.NoMatchingPermission, denied)
    }

[<Fact>]
let ``scope and ABAC condition must both pass`` () =
    task {
        let role =
            { Id = RoleId "conditional-scoped"
              Name = "Conditional Scoped"
              Grants =
                [ { Permission = PermissionPattern.parse "orders:approve"
                    Scope = Map.ofList [ "region", ScopeValue.Literal "eu" ]
                    Condition = Some(fun attrs ->
                        match Map.tryFind "amount" attrs with
                        | Some v -> (v :?> int) < 10000
                        | None -> false)
                    Metadata = GrantMetadata.empty } ] }

        let engine =
            buildEngine [ role ] [ Assignment.create testPrincipal (RoleId "conditional-scoped") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "orders" "approve")
            |> AuthorizationRequest.withScope (Map.ofList [ "region", "eu" ])
            |> AuthorizationRequest.withAttributes (Map.ofList [ "amount", box 5000 ])

        let! allowed = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(allowed.IsAllowed)

        let request2 =
            AuthorizationRequest.create testPrincipal (PermissionId.create "orders" "approve")
            |> AuthorizationRequest.withScope (Map.ofList [ "region", "eu" ])
            |> AuthorizationRequest.withAttributes (Map.ofList [ "amount", box 50000 ])

        let! condDenied = Engine.evaluateAsync engine CancellationToken.None request2
        Assert.False(condDenied.IsAllowed)
        Assert.Equal(Denied DenyReason.AttributeEvaluationFailed, condDenied)

        let request3 =
            AuthorizationRequest.create testPrincipal (PermissionId.create "orders" "approve")
            |> AuthorizationRequest.withScope (Map.ofList [ "region", "us" ])
            |> AuthorizationRequest.withAttributes (Map.ofList [ "amount", box 5000 ])

        let! scopeDenied = Engine.evaluateAsync engine CancellationToken.None request3
        Assert.False(scopeDenied.IsAllowed)
        Assert.Equal(Denied DenyReason.ScopeMismatch, scopeDenied)
    }

[<Fact>]
let ``revoking one role does not affect other roles for same principal`` () =
    task {
        let host =
            AuthorizationConfig.defaultConfig
            |> AuthorizationConfig.addRole readerRole
            |> AuthorizationConfig.addRole writerRole
            |> AuthorizationConfig.assign "user-1" "reader"
            |> AuthorizationConfig.assign "user-1" "writer"
            |> AuthorizationHost.build

        let engine = host.Engine

        // Both roles grant documents:read, so the role a read is credited to shows whether the
        // reader assignment is active.
        let readRequest =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")

        let! readBefore = Engine.evaluateAsync engine CancellationToken.None readRequest
        Assert.Equal(Allowed(RoleId "reader", PermissionPattern.parse "documents:read"), readBefore)

        host.Revoke(testPrincipal, RoleId "reader")

        let! readAfter = Engine.evaluateAsync engine CancellationToken.None readRequest
        Assert.Equal(Allowed(RoleId "writer", PermissionPattern.parse "documents:read"), readAfter)

        let writeRequest =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "write")

        let! writeDecision = Engine.evaluateAsync engine CancellationToken.None writeRequest
        Assert.Equal(Allowed(RoleId "writer", PermissionPattern.parse "documents:write"), writeDecision)
    }

[<Fact>]
let ``AuthorizationHost.AddRole throws with custom role store`` () =
    let customRoleStore =
        { new IRoleStore with
            member _.GetRoleAsync(_, _) = System.Threading.Tasks.Task.FromResult(None) }

    let host =
        AuthorizationConfig.defaultConfig
        |> AuthorizationConfig.useRoleStore customRoleStore
        |> AuthorizationHost.build

    let role =
        RoleBuilder.create "r" "R"
        |> RoleBuilder.grantEverywhere "a:b"
        |> RoleBuilder.build

    Assert.Throws<InvalidOperationException>(fun () -> host.AddRole(role))

[<Fact>]
let ``AuthorizationHost.AddAssignment throws with custom assignment store`` () =
    let customAssignmentStore =
        { new IAssignmentStore with
            member _.GetAssignmentsForPrincipalAsync(_, _) =
                System.Threading.Tasks.Task.FromResult([]) }

    let host =
        AuthorizationConfig.defaultConfig
        |> AuthorizationConfig.useAssignmentStore customAssignmentStore
        |> AuthorizationHost.build

    Assert.Throws<InvalidOperationException>(fun () ->
        host.AddAssignment(Assignment.create (PrincipalId "u") (RoleId "r")))

[<Fact>]
let ``AuthorizationHost.Revoke throws with custom assignment store`` () =
    let customAssignmentStore =
        { new IAssignmentStore with
            member _.GetAssignmentsForPrincipalAsync(_, _) =
                System.Threading.Tasks.Task.FromResult([]) }

    let host =
        AuthorizationConfig.defaultConfig
        |> AuthorizationConfig.useAssignmentStore customAssignmentStore
        |> AuthorizationHost.build

    Assert.Throws<InvalidOperationException>(fun () ->
        host.Revoke(PrincipalId "u", RoleId "r"))

[<Fact>]
let ``extra scope keys in request do not prevent match`` () =
    task {
        let role =
            { Id = RoleId "tenant-scoped"
              Name = "Tenant Scoped"
              Grants =
                [ { Permission = PermissionPattern.parse "docs:read"
                    Scope = Map.ofList [ "tenant", ScopeValue.Literal "acme" ]
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        let engine =
            buildEngine [ role ] [ Assignment.create testPrincipal (RoleId "tenant-scoped") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "docs" "read")
            |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "acme"; "project", "beta" ])

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``assignForWindow creates time-bounded assignment`` () =
    task {
        let role =
            RoleBuilder.create "temp" "Temporary"
            |> RoleBuilder.grantEverywhere "docs:read"
            |> RoleBuilder.build

        let host =
            AuthorizationConfig.defaultConfig
            |> AuthorizationConfig.addRole role
            |> AuthorizationConfig.assignForWindow
                "user-1"
                "temp"
                (Some(DateTimeOffset.UtcNow.AddHours(-1.0)))
                (Some(DateTimeOffset.UtcNow.AddHours(1.0)))
            |> AuthorizationHost.build

        let request =
            AuthorizationRequest.create (PrincipalId "user-1") (PermissionId.create "docs" "read")

        let! decision = Engine.evaluateAsync host.Engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``assignForWindow denies when outside window`` () =
    task {
        let role =
            RoleBuilder.create "temp" "Temporary"
            |> RoleBuilder.grantEverywhere "docs:read"
            |> RoleBuilder.build

        let host =
            AuthorizationConfig.defaultConfig
            |> AuthorizationConfig.addRole role
            |> AuthorizationConfig.assignForWindow
                "user-1"
                "temp"
                (Some(DateTimeOffset.UtcNow.AddHours(-2.0)))
                (Some(DateTimeOffset.UtcNow.AddHours(-1.0)))
            |> AuthorizationHost.build

        let request =
            AuthorizationRequest.create (PrincipalId "user-1") (PermissionId.create "docs" "read")

        let! decision = Engine.evaluateAsync host.Engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.AssignmentNotActive, decision)
    }
