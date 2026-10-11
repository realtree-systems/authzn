module Authzn.Benchmarks.EngineBenchmarks

open System
open System.Threading
open BenchmarkDotNet.Attributes
open Authzn

let private buildEngine (roles: Role list) (assignments: Assignment list) resolver =
    let roleStore = InMemoryRoleStore()
    for r in roles do roleStore.Add(r)

    let assignmentStore = InMemoryAssignmentStore()
    for a in assignments do assignmentStore.Add(a)

    let engine = AuthorizationEngine.create roleStore assignmentStore

    match resolver with
    | Some r -> engine |> AuthorizationEngine.withScopeResolver r
    | None -> engine

[<MemoryDiagnoser>]
[<SimpleJob(warmupCount = 5, iterationCount = 20)>]
type EvaluationBenchmarks() =

    let mutable simpleEngine = Unchecked.defaultof<AuthorizationEngine>
    let mutable scopedEngine = Unchecked.defaultof<AuthorizationEngine>
    let mutable abacEngine = Unchecked.defaultof<AuthorizationEngine>
    let mutable manyRolesEngine = Unchecked.defaultof<AuthorizationEngine>

    let principal = PrincipalId "user-1"

    let mutable allowRequest = Unchecked.defaultof<AuthorizationRequest>
    let mutable denyNoPermRequest = Unchecked.defaultof<AuthorizationRequest>
    let mutable scopedAllowRequest = Unchecked.defaultof<AuthorizationRequest>
    let mutable scopedDenyRequest = Unchecked.defaultof<AuthorizationRequest>
    let mutable abacRequest = Unchecked.defaultof<AuthorizationRequest>
    let mutable manyRolesRequest = Unchecked.defaultof<AuthorizationRequest>

    [<GlobalSetup>]
    member _.Setup() =
        let readerRole =
            { Id = RoleId "reader"
              Name = "Reader"
              Grants =
                [ { Permission = PermissionPattern.parse "documents:read"
                    Scope = Map.empty
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        simpleEngine <-
            buildEngine
                [ readerRole ]
                [ Assignment.create principal (RoleId "reader") ]
                None

        allowRequest <-
            AuthorizationRequest.create principal (PermissionId.create "documents" "read")

        denyNoPermRequest <-
            AuthorizationRequest.create principal (PermissionId.create "documents" "delete")

        let scopedRole =
            { Id = RoleId "scoped"
              Name = "Scoped"
              Grants =
                [ { Permission = PermissionPattern.parse "documents:read"
                    Scope = Map.ofList [ "tenant", ScopeValue.Literal "acme"; "project", ScopeValue.Literal "alpha" ]
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        scopedEngine <-
            buildEngine
                [ scopedRole ]
                [ Assignment.create principal (RoleId "scoped") ]
                None

        scopedAllowRequest <-
            AuthorizationRequest.create principal (PermissionId.create "documents" "read")
            |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "acme"; "project", "alpha" ])

        scopedDenyRequest <-
            AuthorizationRequest.create principal (PermissionId.create "documents" "read")
            |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "acme"; "project", "beta" ])

        let abacRole =
            { Id = RoleId "abac"
              Name = "ABAC"
              Grants =
                [ { Permission = PermissionPattern.parse "orders:approve"
                    Scope = Map.empty
                    Condition = Some(fun attrs ->
                        match Map.tryFind "amount" attrs with
                        | Some v -> (v :?> int) < 10000
                        | None -> false)
                    Metadata = GrantMetadata.empty } ] }

        abacEngine <-
            buildEngine
                [ abacRole ]
                [ Assignment.create principal (RoleId "abac") ]
                None

        abacRequest <-
            AuthorizationRequest.create principal (PermissionId.create "orders" "approve")
            |> AuthorizationRequest.withAttributes (Map.ofList [ "amount", box 5000 ])

        let roles =
            [ for i in 1..50 ->
                { Id = RoleId $"role-{i}"
                  Name = $"Role {i}"
                  Grants =
                    [ { Permission = PermissionPattern.parse $"resource-{i}:read"
                        Scope = Map.empty
                        Condition = None
                        Metadata = GrantMetadata.empty } ] } ]

        let assignments =
            [ for i in 1..50 ->
                Assignment.create principal (RoleId $"role-{i}") ]

        manyRolesEngine <- buildEngine roles assignments None

        // Only role-50, the last assignment the store returns, grants resource-50:read, so
        // evaluateAsync reads all 50 roles before it allows.
        manyRolesRequest <-
            AuthorizationRequest.create principal (PermissionId.create "resource-50" "read")

    [<Benchmark(Description = "Allow - simple (1 role, 1 grant)", Baseline = true)>]
    member _.SimpleAllow() =
        Engine.evaluateAsync simpleEngine CancellationToken.None allowRequest

    [<Benchmark(Description = "Deny - no matching permission")>]
    member _.DenyNoPermission() =
        Engine.evaluateAsync simpleEngine CancellationToken.None denyNoPermRequest

    [<Benchmark(Description = "Allow - scoped (2 scope keys)")>]
    member _.ScopedAllow() =
        Engine.evaluateAsync scopedEngine CancellationToken.None scopedAllowRequest

    [<Benchmark(Description = "Deny - scope mismatch")>]
    member _.ScopedDeny() =
        Engine.evaluateAsync scopedEngine CancellationToken.None scopedDenyRequest

    [<Benchmark(Description = "Allow - ABAC condition")>]
    member _.AbacAllow() =
        Engine.evaluateAsync abacEngine CancellationToken.None abacRequest

    [<Benchmark(Description = "Allow - 50 roles (worst-case traversal)")>]
    member _.ManyRolesWorstCase() =
        Engine.evaluateAsync manyRolesEngine CancellationToken.None manyRolesRequest

[<MemoryDiagnoser>]
[<SimpleJob(warmupCount = 5, iterationCount = 20)>]
type AssignmentScaleBenchmarks() =

    let mutable engine100 = Unchecked.defaultof<AuthorizationEngine>
    let mutable engine1000 = Unchecked.defaultof<AuthorizationEngine>
    let mutable engine10000 = Unchecked.defaultof<AuthorizationEngine>

    let targetPrincipal = PrincipalId "target"
    let mutable request = Unchecked.defaultof<AuthorizationRequest>

    let buildWithNPrincipals n =
        let role =
            { Id = RoleId "reader"
              Name = "Reader"
              Grants =
                [ { Permission = PermissionPattern.parse "docs:read"
                    Scope = Map.empty
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        let assignments =
            [ for i in 1..n -> Assignment.create (PrincipalId $"user-{i}") (RoleId "reader") ]
            @ [ Assignment.create targetPrincipal (RoleId "reader") ]

        buildEngine [ role ] assignments None

    [<GlobalSetup>]
    member _.Setup() =
        engine100 <- buildWithNPrincipals 100
        engine1000 <- buildWithNPrincipals 1_000
        engine10000 <- buildWithNPrincipals 10_000

        request <-
            AuthorizationRequest.create targetPrincipal (PermissionId.create "docs" "read")

    [<Benchmark(Description = "100 total assignments", Baseline = true)>]
    member _.Scale100() =
        Engine.evaluateAsync engine100 CancellationToken.None request

    [<Benchmark(Description = "1,000 total assignments")>]
    member _.Scale1000() =
        Engine.evaluateAsync engine1000 CancellationToken.None request

    [<Benchmark(Description = "10,000 total assignments")>]
    member _.Scale10000() =
        Engine.evaluateAsync engine10000 CancellationToken.None request
