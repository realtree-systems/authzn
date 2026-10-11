module RealTree.Authzn.Tests.QueryTests

open System
open System.Threading
open System.Threading.Tasks
open Xunit
open RealTree.Authzn
open RealTree.Authzn.Tests.Helpers

// Both resolvers below admit "t1" for the principal marker on key "tenant", and the orgs in this
// set for the hierarchy marker.
let private subtree = Set.ofList [ "o1"; "o2" ]

// Implements IScopeValueEnumerator as well as IScopeValueResolver, so visibleScopeAsync can
// enumerate its markers.
let private admits (key: string) (marker: MarkerName) (requestValue: string) =
    match marker.Value with
    | ScopeMarkers.Principal when key = "tenant" -> requestValue = "t1"
    | ScopeMarkers.Hierarchy -> Set.contains requestValue subtree
    | _ -> false

let private dualResolver =
    { new IScopeValueResolver with
        member _.AdmitsAsync(_principal, key, marker, requestValue, _cancellationToken) =
            ValueTask<bool>(admits key marker requestValue)
      interface IScopeValueEnumerator with
          member _.EnumerateScopeAsync(_principal, key, marker, _cancellationToken) =
              ValueTask<ScopeValueSet option>(
                  match marker.Value with
                  | ScopeMarkers.Principal when key = "tenant" -> Some(Values(Set.singleton "t1"))
                  | ScopeMarkers.Hierarchy -> Some(Values subtree)
                  | _ -> None
              ) }

// Admits the same values as dualResolver but does not implement IScopeValueEnumerator.
let private matchOnlyResolver = syncResolver (fun _principal key marker requestValue -> admits key marker requestValue)

// Grants reports:read confined by the principal marker on "tenant" and the hierarchy marker on
// "org"; with dualResolver the grant admits tenant "t1" and orgs "o1" and "o2".
let private orgReaderRole =
    { Id = RoleId "org-reader"
      Name = "Org Reader"
      Grants =
        [ { Permission = PermissionPattern.parse "reports:read"
            Scope = Map.ofList [ "tenant", ScopeValue.principal; "org", ScopeValue.hierarchy ]
            Condition = None
            Metadata = GrantMetadata.empty } ] }

let private orgReaderAssignment = Assignment.create testPrincipal (RoleId "org-reader")

let private scopeOf (org: string) = Map.ofList [ "tenant", "t1"; "org", org ]
let private noAttrs (_: 'T) : AttributeBag = Map.empty

[<Fact>]
let ``filterAsync keeps only the candidates the grant admits`` () =
    task {
        let engine = buildEngineWithResolver [ orgReaderRole ] [ orgReaderAssignment ] dualResolver

        let! visible =
            Engine.filterAsync engine CancellationToken.None testPrincipal (PermissionId.create "reports" "read") [ "o1"; "o2"; "o3" ] scopeOf noAttrs

        Assert.Equal<string list>([ "o1"; "o2" ], visible)
    }

[<Fact>]
let ``filterAsync returns every candidate for an unconstrained grant`` () =
    task {
        let engine = buildEngineWithResolver [ adminRole ] [ Assignment.create testPrincipal (RoleId "admin") ] dualResolver

        let! visible =
            Engine.filterAsync engine CancellationToken.None testPrincipal (PermissionId.create "reports" "read") [ "o1"; "o2"; "o3" ] scopeOf noAttrs

        Assert.Equal<string list>([ "o1"; "o2"; "o3" ], visible)
    }

[<Fact>]
let ``filterAsync returns nothing when no grant matches the permission`` () =
    task {
        let engine = buildEngineWithResolver [ orgReaderRole ] [ orgReaderAssignment ] dualResolver

        let! visible =
            Engine.filterAsync engine CancellationToken.None testPrincipal (PermissionId.create "reports" "write") [ "o1"; "o2" ] scopeOf noAttrs

        Assert.Empty visible
    }

[<Fact>]
let ``filterAsync applies the grant's ABAC condition per candidate`` () =
    task {
        let role =
            { Id = RoleId "low-only"
              Name = "Low Only"
              Grants =
                [ { Permission = PermissionPattern.parse "reports:read"
                    Scope = Map.empty
                    Condition = Some(fun attrs -> attrs |> Map.tryFind "level" = Some(box "low"))
                    Metadata = GrantMetadata.empty } ] }

        let engine = buildEngine [ role ] [ Assignment.create testPrincipal (RoleId "low-only") ]
        let attrsOf (org: string) : AttributeBag = Map.ofList [ "level", box (if org = "o1" then "low" else "high") ]

        let! visible =
            Engine.filterAsync engine CancellationToken.None testPrincipal (PermissionId.create "reports" "read") [ "o1"; "o2" ] scopeOf attrsOf

        Assert.Equal<string list>([ "o1" ], visible)
    }

[<Fact>]
let ``filterAsync excludes a candidate whose ABAC condition throws`` () =
    task {
        // filterAsync, like evaluateAsync, treats a condition that throws as false and drops the
        // candidate.
        let role =
            { Id = RoleId "approver"
              Name = "Approver"
              Grants =
                [ { Permission = PermissionPattern.parse "reports:read"
                    Scope = Map.empty
                    Condition = Some(fun attrs -> unbox<int> (Map.find "amount" attrs) < 10)
                    Metadata = GrantMetadata.empty } ] }

        let engine = buildEngine [ role ] [ Assignment.create testPrincipal (RoleId "approver") ]
        // o1 carries "amount"; o2 omits it, so the condition throws on the missing key.
        let attrsOf (org: string) : AttributeBag =
            if org = "o1" then Map.ofList [ "amount", box 5 ] else Map.empty

        let! visible =
            Engine.filterAsync engine CancellationToken.None testPrincipal (PermissionId.create "reports" "read") [ "o1"; "o2" ] scopeOf attrsOf

        Assert.Equal<string list>([ "o1" ], visible)
    }

[<Fact>]
let ``filterAsync keeps a candidate exactly when evaluateAsync allows it`` () =
    task {
        // In "t1" the "strict" grant's condition fails but the "open" grant allows. In "t3" only the
        // failing "strict" grant matches, and in "t2" no grant matches.
        let grant tenant condition =
            { Permission = PermissionPattern.parse "reports:read"
              Scope = Map.ofList [ "tenant", ScopeValue.Literal tenant ]
              Condition = condition
              Metadata = GrantMetadata.empty }

        let strict =
            { Id = RoleId "strict"
              Name = "Strict"
              Grants = [ grant "t1" (Some(fun _ -> false)); grant "t3" (Some(fun _ -> false)) ] }

        let openRole = { Id = RoleId "open"; Name = "Open"; Grants = [ grant "t1" None ] }

        let engine =
            buildEngine
                [ strict; openRole ]
                [ Assignment.create testPrincipal (RoleId "strict")
                  Assignment.create testPrincipal (RoleId "open") ]

        let permission = PermissionId.create "reports" "read"
        let tenantOf (tenant: string) : ScopeBag = Map.ofList [ "tenant", tenant ]
        let tenants = [ "t1"; "t2"; "t3" ]

        let! visible = Engine.filterAsync engine CancellationToken.None testPrincipal permission tenants tenantOf noAttrs

        let! decisions =
            tenants
            |> List.map (fun tenant ->
                AuthorizationRequest.create testPrincipal permission
                |> AuthorizationRequest.withScope (tenantOf tenant)
                |> Engine.evaluateAsync engine CancellationToken.None)
            |> Task.WhenAll

        Assert.Equal<string list>([ "t1" ], visible)
        Assert.Equal(Allowed(RoleId "open", PermissionPattern.parse "reports:read"), decisions[0])
        Assert.Equal(Denied DenyReason.ScopeMismatch, decisions[1])
        Assert.Equal(Denied DenyReason.AttributeEvaluationFailed, decisions[2])
    }

[<Fact>]
let ``mayAnyAsync is true within the tenant, false in another tenant or for another permission`` () =
    task {
        let engine = buildEngineWithResolver [ orgReaderRole ] [ orgReaderAssignment ] dualResolver
        let read = PermissionId.create "reports" "read"

        let! inTenant = Engine.mayAnyAsync engine CancellationToken.None testPrincipal read (Map.ofList [ "tenant", "t1" ])
        let! otherTenant = Engine.mayAnyAsync engine CancellationToken.None testPrincipal read (Map.ofList [ "tenant", "t2" ])
        let! otherPermission = Engine.mayAnyAsync engine CancellationToken.None testPrincipal (PermissionId.create "reports" "write") (Map.ofList [ "tenant", "t1" ])

        Assert.True inTenant // mayAnyAsync treats the omitted "org" key as satisfiable
        Assert.False otherTenant
        Assert.False otherPermission
    }

[<Fact>]
let ``visibleScopeAsync materialises the grant's markers into a clause`` () =
    task {
        let engine = buildEngineWithResolver [ orgReaderRole ] [ orgReaderAssignment ] dualResolver

        let! constr = Engine.visibleScopeAsync engine CancellationToken.None testPrincipal (PermissionId.create "reports" "read") (Map.ofList [ "tenant", "t1" ])

        match constr with
        | Restricted [ clause ] ->
            Assert.Equal(Values(Set.ofList [ "t1" ]), clause.["tenant"])
            Assert.Equal(Values(Set.ofList [ "o1"; "o2" ]), clause.["org"])
        | other -> failwith $"expected a single Restricted clause, got {other}"
    }

[<Fact>]
let ``visibleScopeAsync returns Everything for an unconstrained grant`` () =
    task {
        let engine = buildEngineWithResolver [ adminRole ] [ Assignment.create testPrincipal (RoleId "admin") ] dualResolver

        let! constr = Engine.visibleScopeAsync engine CancellationToken.None testPrincipal (PermissionId.create "reports" "read") Map.empty

        Assert.Equal(Everything, constr)
    }

[<Fact>]
let ``visibleScopeAsync returns Nothing when no grant admits the partial scope`` () =
    task {
        let engine = buildEngineWithResolver [ orgReaderRole ] [ orgReaderAssignment ] dualResolver

        let! constr = Engine.visibleScopeAsync engine CancellationToken.None testPrincipal (PermissionId.create "reports" "read") (Map.ofList [ "tenant", "t2" ])

        Assert.Equal(Nothing, constr)
    }

[<Fact>]
let ``visibleScopeAsync raises when a relevant marker cannot be enumerated`` () =
    task {
        // matchOnlyResolver admits "t1" for the principal marker, so the grant is relevant to the
        // partial scope, but it does not implement IScopeValueEnumerator.
        let engine = buildEngineWithResolver [ orgReaderRole ] [ orgReaderAssignment ] matchOnlyResolver

        let! ex =
            Assert.ThrowsAsync<NotSupportedException>(fun () ->
                Engine.visibleScopeAsync engine CancellationToken.None testPrincipal (PermissionId.create "reports" "read") (Map.ofList [ "tenant", "t1" ])
                :> Task)

        Assert.NotNull ex
    }

[<Fact>]
let ``every query refuses a marker the resolver does not recognise, even against its own text`` () =
    task {
        // The grant scopes "tenant" to the marker "acme", whose text form is "@acme". dualResolver
        // neither admits nor enumerates that marker, and a marker is never compared as text.
        let role =
            { Id = RoleId "acme-reader"
              Name = "Acme Reader"
              Grants =
                [ { Permission = PermissionPattern.parse "reports:read"
                    Scope = Map.ofList [ "tenant", ScopeValue.marker "acme" ]
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        let engine =
            buildEngineWithResolver [ role ] [ Assignment.create testPrincipal (RoleId "acme-reader") ] dualResolver

        let read = PermissionId.create "reports" "read"
        let acme = Map.ofList [ "tenant", "@acme" ]

        let! decision =
            AuthorizationRequest.create testPrincipal read
            |> AuthorizationRequest.withScope acme
            |> Engine.evaluateAsync engine CancellationToken.None

        Assert.Equal(Denied DenyReason.ScopeMismatch, decision)

        let! visible = Engine.filterAsync engine CancellationToken.None testPrincipal read [ acme ] id noAttrs
        Assert.Empty(visible)

        let! reachable = Engine.mayAnyAsync engine CancellationToken.None testPrincipal read acme
        Assert.False(reachable)

        let! constr = Engine.visibleScopeAsync engine CancellationToken.None testPrincipal read acme
        Assert.Equal(Nothing, constr)
    }
