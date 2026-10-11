module RealTree.Authzn.Tests.ScopeResolutionTests

open System.Threading
open Xunit
open RealTree.Authzn
open RealTree.Authzn.Tests.Helpers

[<Fact>]
let ``hierarchy marker allows when resolver confirms membership`` () =
    task {
        let role =
            { Id = RoleId "org-reader"
              Name = "Org Reader"
              Grants =
                [ { Permission = PermissionPattern.parse "reports:read"
                    Scope = Map.ofList [ "org", ScopeValue.hierarchy ]
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        let resolver =
            syncResolver (fun _principal _key grantValue requestValue ->
                if grantValue.Value = ScopeMarkers.Hierarchy then
                    // The hierarchy is org "acme" and its child "acme/engineering".
                    requestValue = "acme" || requestValue = "acme/engineering"
                else
                    false)

        let engine =
            buildEngineWithResolver
                [ role ]
                [ Assignment.create testPrincipal (RoleId "org-reader") ]
                resolver

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "reports" "read")
            |> AuthorizationRequest.withScope (Map.ofList [ "org", "acme/engineering" ])

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``hierarchy marker denies when resolver rejects membership`` () =
    task {
        let role =
            { Id = RoleId "org-reader"
              Name = "Org Reader"
              Grants =
                [ { Permission = PermissionPattern.parse "reports:read"
                    Scope = Map.ofList [ "org", ScopeValue.hierarchy ]
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        let resolver =
            syncResolver (fun _principal _key grantValue _requestValue ->
                if grantValue.Value = ScopeMarkers.Hierarchy then
                    false
                else
                    false)

        let engine =
            buildEngineWithResolver
                [ role ]
                [ Assignment.create testPrincipal (RoleId "org-reader") ]
                resolver

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "reports" "read")
            |> AuthorizationRequest.withScope (Map.ofList [ "org", "other-corp" ])

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.ScopeMismatch, decision)
    }

// A request scope value equal to a marker's text form ("@custom", "@principal") does not satisfy a
// grant scoped to that marker. Otherwise a resource whose stored scope value is that text would
// match the grant without the resolver admitting it.
[<Fact>]
let ``a marker the resolver does not admit does not match its own text`` () =
    task {
        let role =
            { Id = RoleId "scoped"
              Name = "Scoped"
              Grants =
                [ { Permission = PermissionPattern.parse "docs:read"
                    Scope = Map.ofList [ "tenant", ScopeValue.marker "custom" ]
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        let resolver =
            syncResolver (fun _principal _key _marker _requestValue -> false)

        let engine =
            buildEngineWithResolver
                [ role ]
                [ Assignment.create testPrincipal (RoleId "scoped") ]
                resolver

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "docs" "read")
            |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "@custom" ])

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.Equal(Denied DenyReason.ScopeMismatch, decision)
    }

[<Fact>]
let ``without a resolver a marker matches nothing, not even its own text`` () =
    task {
        let role =
            { Id = RoleId "scoped"
              Name = "Scoped"
              Grants =
                [ { Permission = PermissionPattern.parse "docs:read"
                    Scope = Map.ofList [ "tenant", ScopeValue.principal ]
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        let engine =
            buildEngine
                [ role ]
                [ Assignment.create testPrincipal (RoleId "scoped") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "docs" "read")
            |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "@principal" ])

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.Equal(Denied DenyReason.ScopeMismatch, decision)
    }

[<Fact>]
let ``all scope keys must match for grant to apply`` () =
    task {
        let role =
            { Id = RoleId "multi-scoped"
              Name = "Multi Scoped"
              Grants =
                [ { Permission = PermissionPattern.parse "docs:write"
                    Scope = Map.ofList [ "tenant", ScopeValue.Literal "acme"; "project", ScopeValue.Literal "alpha" ]
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        let engine =
            buildEngine [ role ] [ Assignment.create testPrincipal (RoleId "multi-scoped") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "docs" "write")
            |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "acme"; "project", "alpha" ])

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``scope mismatch when one of multiple keys does not match`` () =
    task {
        let role =
            { Id = RoleId "multi-scoped"
              Name = "Multi Scoped"
              Grants =
                [ { Permission = PermissionPattern.parse "docs:write"
                    Scope = Map.ofList [ "tenant", ScopeValue.Literal "acme"; "project", ScopeValue.Literal "alpha" ]
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        let engine =
            buildEngine [ role ] [ Assignment.create testPrincipal (RoleId "multi-scoped") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "docs" "write")
            |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "acme"; "project", "beta" ])

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.ScopeMismatch, decision)
    }

[<Fact>]
let ``scope mismatch when request is missing a required scope key`` () =
    task {
        let role =
            { Id = RoleId "multi-scoped"
              Name = "Multi Scoped"
              Grants =
                [ { Permission = PermissionPattern.parse "docs:write"
                    Scope = Map.ofList [ "tenant", ScopeValue.Literal "acme"; "project", ScopeValue.Literal "alpha" ]
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        let engine =
            buildEngine [ role ] [ Assignment.create testPrincipal (RoleId "multi-scoped") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "docs" "write")
            |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "acme" ])

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.ScopeMismatch, decision)
    }

[<Fact>]
let ``unscoped grant allows any request scope`` () =
    task {
        let engine =
            buildEngine [ readerRole ] [ Assignment.create testPrincipal (RoleId "reader") ]

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")
            |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "acme" ])

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``principal marker denies when request value does not match principal id`` () =
    task {
        let role =
            { Id = RoleId "self-service"
              Name = "Self Service"
              Grants =
                [ { Permission = PermissionPattern.parse "profile:edit"
                    Scope = Map.ofList [ "owner", ScopeValue.principal ]
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
                [ role ]
                [ Assignment.create testPrincipal (RoleId "self-service") ]
                resolver

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "profile" "edit")
            |> AuthorizationRequest.withScope (Map.ofList [ "owner", "user-999" ])

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.False(decision.IsAllowed)
        Assert.Equal(Denied DenyReason.ScopeMismatch, decision)
    }

[<Fact>]
let ``mixed scope with marker and literal both must match`` () =
    task {
        let role =
            { Id = RoleId "team-editor"
              Name = "Team Editor"
              Grants =
                [ { Permission = PermissionPattern.parse "tasks:edit"
                    Scope = Map.ofList [ "owner", ScopeValue.principal; "project", ScopeValue.Literal "alpha" ]
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
                [ role ]
                [ Assignment.create testPrincipal (RoleId "team-editor") ]
                resolver

        let request =
            AuthorizationRequest.create testPrincipal (PermissionId.create "tasks" "edit")
            |> AuthorizationRequest.withScope (Map.ofList [ "owner", "user-1"; "project", "alpha" ])

        let! allowed = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(allowed.IsAllowed)

        let request2 =
            AuthorizationRequest.create testPrincipal (PermissionId.create "tasks" "edit")
            |> AuthorizationRequest.withScope (Map.ofList [ "owner", "user-1"; "project", "beta" ])

        let! denied = Engine.evaluateAsync engine CancellationToken.None request2
        Assert.False(denied.IsAllowed)
        Assert.Equal(Denied DenyReason.ScopeMismatch, denied)
    }
