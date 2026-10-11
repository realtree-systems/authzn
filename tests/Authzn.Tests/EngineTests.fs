module Authzn.Tests.EngineTests

open System
open System.Threading
open Xunit
open Authzn
open Authzn.Tests.Helpers

[<Fact>]
let ``allows when principal has matching permission`` () =
    task {
        let engine =
            buildEngine [ readerRole ] [ Assignment.create testPrincipal (RoleId "reader") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
        Assert.Equal(Allowed(RoleId "reader", PermissionPattern.parse "documents:read"), decision)
    }

[<Fact>]
let ``denies with NoAssignments when principal has no assignments`` () =
    task {
        let engine = buildEngine [ readerRole ] []

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.NoAssignments, decision)
    }

[<Fact>]
let ``denies with NoMatchingPermission when role lacks permission`` () =
    task {
        let engine =
            buildEngine [ readerRole ] [ Assignment.create testPrincipal (RoleId "reader") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "write")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.NoMatchingPermission, decision)
    }

[<Fact>]
let ``admin wildcard grants any permission`` () =
    task {
        let engine =
            buildEngine [ adminRole ] [ Assignment.create testPrincipal (RoleId "admin") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "anything" "delete")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``resource wildcard grants all actions on resource`` () =
    task {
        let role =
            { Id = RoleId "docs-all"
              Name = "Docs All"
              Grants =
                [ { Permission = PermissionPattern.parse "documents:*"
                    Scope = Map.empty
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        let engine =
            buildEngine [ role ] [ Assignment.create testPrincipal (RoleId "docs-all") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "delete")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``denies with AssignmentNotActive when assignment is expired`` () =
    task {
        let expired =
            { Assignment.create testPrincipal (RoleId "reader") with
                NotAfter = Some(DateTimeOffset.UtcNow.AddHours(-1.0)) }

        let engine = buildEngine [ readerRole ] [ expired ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.AssignmentNotActive, decision)
    }

[<Fact>]
let ``denies with AssignmentNotActive when assignment not yet valid`` () =
    task {
        let future =
            { Assignment.create testPrincipal (RoleId "reader") with
                NotBefore = Some(DateTimeOffset.UtcNow.AddHours(1.0)) }

        let engine = buildEngine [ readerRole ] [ future ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.AssignmentNotActive, decision)
    }

[<Fact>]
let ``denies with AssignmentNotActive when assignment is revoked`` () =
    task {
        let revoked =
            Assignment.create testPrincipal (RoleId "reader") |> Assignment.revoke

        let engine = buildEngine [ readerRole ] [ revoked ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.AssignmentNotActive, decision)
    }

[<Fact>]
let ``allows when scope matches exactly`` () =
    task {
        let scopedRole =
            { Id = RoleId "scoped"
              Name = "Scoped"
              Grants =
                [ { Permission = PermissionPattern.parse "documents:read"
                    Scope = Map.ofList [ "tenant", ScopeValue.Literal "acme" ]
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        let engine =
            buildEngine [ scopedRole ] [ Assignment.create testPrincipal (RoleId "scoped") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")
            |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "acme" ])

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``denies with ScopeMismatch when scope does not match`` () =
    task {
        let scopedRole =
            { Id = RoleId "scoped"
              Name = "Scoped"
              Grants =
                [ { Permission = PermissionPattern.parse "documents:read"
                    Scope = Map.ofList [ "tenant", ScopeValue.Literal "acme" ]
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        let engine =
            buildEngine [ scopedRole ] [ Assignment.create testPrincipal (RoleId "scoped") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")
            |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "other" ])

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.ScopeMismatch, decision)
    }

[<Fact>]
let ``scope marker resolved via IScopeValueResolver`` () =
    task {
        let scopedRole =
            { Id = RoleId "scoped"
              Name = "Scoped"
              Grants =
                [ { Permission = PermissionPattern.parse "documents:read"
                    Scope = Map.ofList [ "tenant", ScopeValue.principal ]
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        let resolver =
            syncResolver (fun principal _key grantValue requestValue ->
                if grantValue.Value = ScopeMarkers.Principal then
                    PrincipalId.value principal = requestValue
                else
                    false)

        let engine =
            buildEngineWithResolver
                [ scopedRole ]
                [ Assignment.create testPrincipal (RoleId "scoped") ]
                resolver

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")
            |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "user-1" ])

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``allows when ABAC condition passes`` () =
    task {
        let condRole =
            { Id = RoleId "cond"
              Name = "Conditional"
              Grants =
                [ { Permission = PermissionPattern.parse "documents:read"
                    Scope = Map.empty
                    Condition = Some(fun attrs -> attrs |> Map.containsKey "approved")
                    Metadata = GrantMetadata.empty } ] }

        let engine =
            buildEngine [ condRole ] [ Assignment.create testPrincipal (RoleId "cond") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")
            |> AuthorizationRequest.withAttributes (Map.ofList [ "approved", box true ])

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``denies with AttributeEvaluationFailed when condition returns false`` () =
    task {
        let condRole =
            { Id = RoleId "cond"
              Name = "Conditional"
              Grants =
                [ { Permission = PermissionPattern.parse "documents:read"
                    Scope = Map.empty
                    Condition = Some(fun _ -> false)
                    Metadata = GrantMetadata.empty } ] }

        let engine =
            buildEngine [ condRole ] [ Assignment.create testPrincipal (RoleId "cond") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.AttributeEvaluationFailed, decision)
    }

[<Fact>]
let ``denies with AttributeEvaluationFailed when condition throws`` () =
    task {
        let condRole =
            { Id = RoleId "cond"
              Name = "Conditional"
              Grants =
                [ { Permission = PermissionPattern.parse "documents:read"
                    Scope = Map.empty
                    Condition = Some(fun _ -> failwith "boom")
                    Metadata = GrantMetadata.empty } ] }

        let engine =
            buildEngine [ condRole ] [ Assignment.create testPrincipal (RoleId "cond") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.AttributeEvaluationFailed, decision)
    }

[<Fact>]
let ``checks multiple roles and grants first match`` () =
    task {
        let engine =
            buildEngine
                [ readerRole; writerRole ]
                [ Assignment.create testPrincipal (RoleId "reader")
                  Assignment.create testPrincipal (RoleId "writer") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "write")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
        Assert.Equal(Allowed(RoleId "writer", PermissionPattern.parse "documents:write"), decision)
    }

[<Fact>]
let ``a grant whose condition fails does not deny a request another grant allows`` () =
    task {
        let grant condition =
            { Permission = PermissionPattern.parse "orders:approve"
              Scope = Map.empty
              Condition = condition
              Metadata = GrantMetadata.empty }

        let engine =
            buildEngine
                [ { Id = RoleId "conditional"; Name = "Conditional"; Grants = [ grant (Some(fun _ -> false)) ] }
                  { Id = RoleId "open"; Name = "Open"; Grants = [ grant None ] } ]
                [ Assignment.create testPrincipal (RoleId "conditional")
                  Assignment.create testPrincipal (RoleId "open") ]

        let request = AuthorizationRequest.create testPrincipal (PermissionId.parse "orders:approve")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.Equal(Allowed(RoleId "open", PermissionPattern.parse "orders:approve"), decision)
    }

[<Fact>]
let ``a failed condition takes precedence over a revoked grant as the deny reason`` () =
    task {
        let grant condition metadata =
            { Permission = PermissionPattern.parse "orders:approve"
              Scope = Map.empty
              Condition = condition
              Metadata = metadata }

        let revoked = { GrantMetadata.empty with RevokedAt = Some DateTimeOffset.UtcNow }

        let engine =
            buildEngine
                [ { Id = RoleId "revoked"; Name = "Revoked"; Grants = [ grant None revoked ] }
                  { Id = RoleId "conditional"; Name = "Conditional"; Grants = [ grant (Some(fun _ -> false)) GrantMetadata.empty ] } ]
                [ Assignment.create testPrincipal (RoleId "revoked")
                  Assignment.create testPrincipal (RoleId "conditional") ]

        let request = AuthorizationRequest.create testPrincipal (PermissionId.parse "orders:approve")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.Equal(Denied DenyReason.AttributeEvaluationFailed, decision)
    }
