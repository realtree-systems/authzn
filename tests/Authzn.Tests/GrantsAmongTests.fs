module Authzn.Tests.GrantsAmongTests

open System.Threading
open Xunit
open Authzn
open Authzn.Tests.Helpers

let private grant permission scope condition =
    { Permission = PermissionPattern.parse permission
      Scope = scope
      Condition = condition
      Metadata = GrantMetadata.empty }

let private role id grants = { Id = RoleId id; Name = id; Grants = grants }

let private permissions (names: string list) = names |> List.map PermissionId.parse

let private billing = Map.ofList [ "database", "billing" ]
let private billingGrant = Map.ofList [ "database", ScopeValue.Literal "billing" ]

/// Formats each source as "role pattern", such as "admin *", keeping grantsAmongAsync's order.
let private described (sources: GrantSource list) =
    sources
    |> List.map (fun source -> $"{RoleId.value source.Role} {PermissionPattern.format source.Grant.Permission}")

[<Fact>]
let ``every grant that admits a candidate is a source, not only the first`` () =
    task {
        let engine =
            buildEngine
                [ role "admin" [ grant "*:*" Map.empty None ]
                  role "approver" [ grant "invoices:approve" Map.empty None ] ]
                [ Assignment.create testPrincipal (RoleId "admin")
                  Assignment.create testPrincipal (RoleId "approver") ]

        let! sources =
            Engine.grantsAmongAsync engine CancellationToken.None testPrincipal (permissions [ "invoices:approve"; "invoices:read" ]) billing Map.empty

        Assert.Equal<string list>(
            [ "admin *"; "approver invoices:approve" ],
            described sources[PermissionId.parse "invoices:approve"]
        )

        Assert.Equal<string list>([ "admin *" ], described sources[PermissionId.parse "invoices:read"])
    }

[<Fact>]
let ``the keys equal allowedAmongAsync's answer`` () =
    task {
        let engine =
            buildEngine
                [ role "invoicer" [ grant "invoices:*" Map.empty None ]
                  role "approver" [ grant "*:approve" billingGrant None ]
                  role "reporter" [ grant "reports:read" (Map.ofList [ "database", ScopeValue.Literal "other" ]) None ]
                  role "conditional" [ grant "orders:read" Map.empty (Some(fun _ -> false)) ]
                  role "open" [ grant "orders:read" Map.empty None ] ]
                [ Assignment.create testPrincipal (RoleId "invoicer")
                  Assignment.create testPrincipal (RoleId "approver")
                  Assignment.create testPrincipal (RoleId "reporter")
                  Assignment.create testPrincipal (RoleId "conditional")
                  Assignment.create testPrincipal (RoleId "open") ]

        let candidates =
            permissions [ "invoices:approve"; "invoices:read"; "orders:approve"; "orders:read"; "reports:read" ]

        let! allowed = Engine.allowedAmongAsync engine CancellationToken.None testPrincipal candidates billing Map.empty
        let! sources = Engine.grantsAmongAsync engine CancellationToken.None testPrincipal candidates billing Map.empty

        Assert.Equal<Set<PermissionId>>(allowed, sources |> Map.keys |> Set.ofSeq)
    }

[<Fact>]
let ``a grant scoped elsewhere is not a source`` () =
    task {
        let engine =
            buildEngine
                [ role "global" [ grant "invoices:approve" Map.empty None ]
                  role "other" [ grant "invoices:approve" (Map.ofList [ "database", ScopeValue.Literal "other" ]) None ] ]
                [ Assignment.create testPrincipal (RoleId "global")
                  Assignment.create testPrincipal (RoleId "other") ]

        let! sources =
            Engine.grantsAmongAsync engine CancellationToken.None testPrincipal (permissions [ "invoices:approve" ]) billing Map.empty

        Assert.Equal<string list>(
            [ "global invoices:approve" ],
            described sources[PermissionId.parse "invoices:approve"]
        )
    }

/// "denied-first" and "denied-later" fail their conditions, so neither is a source, and neither
/// stops "open" from admitting both candidates.
[<Fact>]
let ``a grant whose condition fails is not a source and hides no other grant`` () =
    task {
        let engine =
            buildEngine
                [ role "denied-first" [ grant "orders:approve" Map.empty (Some(fun _ -> false)) ]
                  role "open" [ grant "orders:approve" Map.empty None; grant "orders:read" Map.empty None ]
                  role "denied-later" [ grant "orders:read" Map.empty (Some(fun _ -> false)) ] ]
                [ Assignment.create testPrincipal (RoleId "denied-first")
                  Assignment.create testPrincipal (RoleId "open")
                  Assignment.create testPrincipal (RoleId "denied-later") ]

        let! sources =
            Engine.grantsAmongAsync engine CancellationToken.None testPrincipal (permissions [ "orders:approve"; "orders:read" ]) Map.empty Map.empty

        Assert.Equal<string list>([ "open orders:approve" ], described sources[PermissionId.parse "orders:approve"])
        Assert.Equal<string list>([ "open orders:read" ], described sources[PermissionId.parse "orders:read"])
    }

[<Fact>]
let ``a revoked grant is not a source`` () =
    task {
        let revoked =
            { grant "invoices:approve" Map.empty None with
                Metadata =
                    { GrantMetadata.empty with
                        RevokedAt = Some System.DateTimeOffset.UtcNow } }

        let engine =
            buildEngine
                [ role "approver" [ revoked ]; role "admin" [ grant "*:*" Map.empty None ] ]
                [ Assignment.create testPrincipal (RoleId "approver")
                  Assignment.create testPrincipal (RoleId "admin") ]

        let! sources =
            Engine.grantsAmongAsync engine CancellationToken.None testPrincipal (permissions [ "invoices:approve" ]) Map.empty Map.empty

        Assert.Equal<string list>([ "admin *" ], described sources[PermissionId.parse "invoices:approve"])
    }

[<Fact>]
let ``a principal with no assignment has no sources`` () =
    task {
        let engine = buildEngine [ adminRole ] []

        let! sources =
            Engine.grantsAmongAsync engine CancellationToken.None testPrincipal (permissions [ "documents:read" ]) Map.empty Map.empty

        Assert.Empty sources
    }
