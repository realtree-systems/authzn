module RealTree.Authzn.Tests.AllowedAmongTests

open System.Collections.Generic
open System.Threading
open Xunit
open RealTree.Authzn
open RealTree.Authzn.Tests.Helpers

let private grant permission scope condition =
    { Permission = PermissionPattern.parse permission
      Scope = scope
      Condition = condition
      Metadata = GrantMetadata.empty }

let private role id grants = { Id = RoleId id; Name = id; Grants = grants }

let private permissions (names: string list) = names |> List.map PermissionId.parse

let private billing = Map.ofList [ "database", "billing" ]
let private billingGrant = Map.ofList [ "database", ScopeValue.Literal "billing" ]

/// The candidates evaluateAsync allows one by one; allowedAmongAsync must return the same set.
let private oneAtATime engine principal candidates scope =
    task {
        let held = HashSet<PermissionId>()

        for candidate in candidates do
            let request =
                AuthorizationRequest.create principal candidate
                |> AuthorizationRequest.withScope scope

            let! decision = Engine.evaluateAsync engine CancellationToken.None request

            if decision.IsAllowed then
                held.Add candidate |> ignore

        return Set.ofSeq held
    }

[<Fact>]
let ``the batch answer equals each candidate evaluated alone`` () =
    task {
        let engine =
            buildEngine
                [ role "invoicer" [ grant "invoices:*" Map.empty None ]
                  role "approver" [ grant "*:approve" billingGrant None ]
                  role "reporter" [ grant "reports:read" (Map.ofList [ "database", ScopeValue.Literal "other" ]) None ] ]
                [ Assignment.create testPrincipal (RoleId "invoicer")
                  Assignment.create testPrincipal (RoleId "approver")
                  Assignment.create testPrincipal (RoleId "reporter") ]

        let candidates =
            permissions [ "invoices:approve"; "invoices:read"; "orders:approve"; "orders:read"; "reports:read" ]

        let! batch = Engine.allowedAmongAsync engine CancellationToken.None testPrincipal candidates billing Map.empty
        let! alone = oneAtATime engine testPrincipal candidates billing

        Assert.Equal<Set<PermissionId>>(alone, batch)

        Assert.Equal<Set<PermissionId>>(
            Set.ofList (permissions [ "invoices:approve"; "invoices:read"; "orders:approve" ]),
            batch
        )
    }

[<Fact>]
let ``the admin wildcard holds every candidate`` () =
    task {
        let engine =
            buildEngine [ adminRole ] [ Assignment.create testPrincipal (RoleId "admin") ]

        let candidates = permissions [ "invoices:approve"; "documents:read" ]

        let! batch = Engine.allowedAmongAsync engine CancellationToken.None testPrincipal candidates billing Map.empty

        Assert.Equal<Set<PermissionId>>(Set.ofList candidates, batch)
    }

[<Fact>]
let ``a principal with no assignment holds nothing`` () =
    task {
        let engine = buildEngine [ adminRole ] []

        let! batch =
            Engine.allowedAmongAsync engine CancellationToken.None testPrincipal (permissions [ "documents:read" ]) Map.empty Map.empty

        Assert.Empty batch
    }

/// The "conditional" role's grant fails its condition, but the "open" role's grant allows, so the
/// candidate is held, as evaluateAsync allows it.
[<Fact>]
let ``a grant whose condition fails does not hide another grant that allows`` () =
    task {
        let engine =
            buildEngine
                [ role "conditional" [ grant "orders:approve" Map.empty (Some(fun _ -> false)) ]
                  role "open" [ grant "orders:approve" Map.empty None ] ]
                [ Assignment.create testPrincipal (RoleId "conditional")
                  Assignment.create testPrincipal (RoleId "open") ]

        let candidates = permissions [ "orders:approve" ]

        let! batch = Engine.allowedAmongAsync engine CancellationToken.None testPrincipal candidates Map.empty Map.empty
        let! alone = oneAtATime engine testPrincipal candidates Map.empty

        Assert.Equal<Set<PermissionId>>(Set.ofList candidates, batch)
        Assert.Equal<Set<PermissionId>>(alone, batch)
    }

[<Fact>]
let ``a candidate asked for twice is answered once`` () =
    task {
        let engine =
            buildEngine [ readerRole ] [ Assignment.create testPrincipal (RoleId "reader") ]

        let candidates = permissions [ "documents:read"; "documents:read" ]

        let! batch = Engine.allowedAmongAsync engine CancellationToken.None testPrincipal candidates Map.empty Map.empty

        Assert.Equal<Set<PermissionId>>(Set.ofList (permissions [ "documents:read" ]), batch)
    }
