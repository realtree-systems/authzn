module Authzn.Tests.EngineOptionsTests

open System
open System.Collections.Concurrent
open System.Threading
open System.Threading.Tasks
open Xunit
open Authzn
open Authzn.Tests.Helpers

// Grants reports:read for the tenant the principal marker admits.
let private tenantReader =
    { Id = RoleId "tenant-reader"
      Name = "Tenant Reader"
      Grants =
        [ { Permission = PermissionPattern.parse "reports:read"
            Scope = Map.ofList [ "tenant", ScopeValue.principal ]
            Condition = None
            Metadata = GrantMetadata.empty } ] }

let private read = PermissionId.parse "reports:read"
let private inTenant tenant : ScopeBag = Map.ofList [ "tenant", tenant ]

// Admits and enumerates tenant "t1" for the principal marker, completing each answer only after
// yielding, so the engine sees a ValueTask that has not completed.
let private yieldingResolver =
    { new IScopeValueResolver with
        member _.AdmitsAsync(_principal, _key, _marker, requestValue, _cancellationToken) =
            ValueTask<bool>(
                task {
                    do! Task.Yield()
                    return requestValue = "t1"
                }
            )
      interface IScopeValueEnumerator with
          member _.EnumerateScopeAsync(_principal, _key, _marker, _cancellationToken) =
              ValueTask<ScopeValueSet option>(
                  task {
                      do! Task.Yield()
                      return Some(Values(Set.singleton "t1"))
                  }
              ) }

[<Fact>]
let ``every Engine function passes its cancellation token to the stores and the resolver`` () =
    task {
        let seen = ConcurrentBag<CancellationToken>()

        let roleStore =
            { new IRoleStore with
                member _.GetRoleAsync(_, cancellationToken) =
                    seen.Add cancellationToken
                    Task.FromResult(Some tenantReader) }

        let assignmentStore =
            { new IAssignmentStore with
                member _.GetAssignmentsForPrincipalAsync(principal, cancellationToken) =
                    seen.Add cancellationToken
                    Task.FromResult([ Assignment.create principal (RoleId "tenant-reader") ]) }

        let resolver =
            { new IScopeValueResolver with
                member _.AdmitsAsync(_, _, _, requestValue, cancellationToken) =
                    seen.Add cancellationToken
                    ValueTask<bool>((requestValue = "t1"))
              interface IScopeValueEnumerator with
                  member _.EnumerateScopeAsync(_, _, _, cancellationToken) =
                      seen.Add cancellationToken
                      ValueTask<ScopeValueSet option>(Some(Values(Set.singleton "t1"))) }

        let engine =
            AuthorizationEngine.create roleStore assignmentStore
            |> AuthorizationEngine.withScopeResolver resolver

        use source = new CancellationTokenSource()
        let token = source.Token

        let! _ =
            AuthorizationRequest.create testPrincipal read
            |> AuthorizationRequest.withScope (inTenant "t1")
            |> Engine.evaluateAsync engine token

        let! _ = Engine.allowedAmongAsync engine token testPrincipal [ read ] (inTenant "t1") Map.empty
        let! _ = Engine.grantsAmongAsync engine token testPrincipal [ read ] (inTenant "t1") Map.empty
        let! _ = Engine.filterAsync engine token testPrincipal read [ "t1" ] inTenant (fun _ -> Map.empty)
        let! _ = Engine.mayAnyAsync engine token testPrincipal read (inTenant "t1")
        let! _ = Engine.visibleScopeAsync engine token testPrincipal read Map.empty

        Assert.NotEmpty(seen)
        Assert.All(seen, fun received -> Assert.Equal(token, received))
    }

[<Fact>]
let ``filterAsync stops with OperationCanceledException once the token is cancelled`` () =
    task {
        let engine = buildEngine [ adminRole ] [ Assignment.create testPrincipal (RoleId "admin") ]
        use source = new CancellationTokenSource()
        source.Cancel()

        let! _ =
            Assert.ThrowsAnyAsync<OperationCanceledException>(fun () ->
                Engine.filterAsync engine source.Token testPrincipal read [ "t1"; "t2" ] inTenant (fun _ -> Map.empty)
                :> Task)

        ()
    }

[<Fact>]
let ``a resolver that completes asynchronously gives the same answers as one that does not`` () =
    task {
        let engine =
            buildEngineWithResolver
                [ tenantReader ]
                [ Assignment.create testPrincipal (RoleId "tenant-reader") ]
                yieldingResolver

        let decide tenant =
            AuthorizationRequest.create testPrincipal read
            |> AuthorizationRequest.withScope (inTenant tenant)
            |> Engine.evaluateAsync engine CancellationToken.None

        let! inT1 = decide "t1"
        let! inT2 = decide "t2"
        Assert.Equal(Allowed(RoleId "tenant-reader", PermissionPattern.parse "reports:read"), inT1)
        Assert.Equal(Denied DenyReason.ScopeMismatch, inT2)

        let! held = Engine.allowedAmongAsync engine CancellationToken.None testPrincipal [ read ] (inTenant "t1") Map.empty
        Assert.Equal<Set<PermissionId>>(Set.singleton read, held)

        let! visible =
            Engine.filterAsync engine CancellationToken.None testPrincipal read [ "t1"; "t2"; "t3" ] inTenant (fun _ -> Map.empty)

        Assert.Equal<string list>([ "t1" ], visible)

        let! reachable = Engine.mayAnyAsync engine CancellationToken.None testPrincipal read (inTenant "t2")
        Assert.False(reachable)

        let! constr = Engine.visibleScopeAsync engine CancellationToken.None testPrincipal read Map.empty
        Assert.Equal(Restricted [ Map.ofList [ "tenant", Values(Set.singleton "t1") ] ], constr)
    }

[<Fact>]
let ``the engine decides grant expiry by its TimeProvider`` () =
    task {
        let expiresAt = DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero)

        let role =
            RoleBuilder.create "temp" "Temporary"
            |> RoleBuilder.grantEverywhereWith "reports:read" { GrantMetadata.empty with ExpiresAt = Some expiresAt }
            |> RoleBuilder.build

        let decideAt (now: DateTimeOffset) =
            let engine =
                buildEngine [ role ] [ Assignment.create testPrincipal (RoleId "temp") ]
                |> AuthorizationEngine.withTimeProvider (FixedTimeProvider now)

            AuthorizationRequest.create testPrincipal read
            |> Engine.evaluateAsync engine CancellationToken.None

        let! before = decideAt (expiresAt.AddSeconds -1.0)
        let! at = decideAt expiresAt

        Assert.True(before.IsAllowed)
        Assert.Equal(Denied DenyReason.GrantNotActive, at)
    }

[<Fact>]
let ``AuthorizationConfig.useTimeProvider sets the clock for assignment windows`` () =
    task {
        let notBefore = DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero)

        let decideAt (now: DateTimeOffset) =
            let host =
                AuthorizationConfig.defaultConfig
                |> AuthorizationConfig.addRole adminRole
                |> AuthorizationConfig.assignForWindow "user-1" "admin" (Some notBefore) None
                |> AuthorizationConfig.useTimeProvider (FixedTimeProvider now)
                |> AuthorizationHost.build

            AuthorizationRequest.create testPrincipal read
            |> Engine.evaluateAsync host.Engine CancellationToken.None

        let! before = decideAt (notBefore.AddSeconds -1.0)
        let! from = decideAt notBefore

        Assert.Equal(Denied DenyReason.AssignmentNotActive, before)
        Assert.True(from.IsAllowed)
    }

[<Fact>]
let ``AuthorizationEngine functions reject null arguments`` () =
    let roleStore = InMemoryRoleStore()
    let assignmentStore = InMemoryAssignmentStore()
    let engine = AuthorizationEngine.create roleStore assignmentStore

    Assert.Throws<ArgumentNullException>(fun () -> AuthorizationEngine.create (Unchecked.defaultof<_>) assignmentStore |> ignore)
    |> ignore

    Assert.Throws<ArgumentNullException>(fun () -> AuthorizationEngine.create roleStore (Unchecked.defaultof<_>) |> ignore)
    |> ignore

    Assert.Throws<ArgumentNullException>(fun () -> AuthorizationEngine.withScopeResolver (Unchecked.defaultof<_>) engine |> ignore)
    |> ignore

    Assert.Throws<ArgumentNullException>(fun () -> AuthorizationEngine.withTimeProvider null engine |> ignore)
    |> ignore
