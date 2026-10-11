module RealTree.Authzn.Tests.ServiceCollectionTests

open System.Threading
open Xunit
open Microsoft.Extensions.DependencyInjection
open RealTree.Authzn
open RealTree.Authzn.Tests.Helpers

[<Fact>]
let ``AddAuthzn registers AuthorizationHost as singleton`` () =
    let services = ServiceCollection() :> IServiceCollection

    services.AddAuthzn(fun config ->
        let role =
            RoleBuilder.create "reader" "Reader"
            |> RoleBuilder.grantEverywhere "docs:read"
            |> RoleBuilder.build

        config
        |> AuthorizationConfig.addRole role
        |> AuthorizationConfig.assign "user-1" "reader")
    |> ignore

    let provider = services.BuildServiceProvider()
    let host = provider.GetService<AuthorizationHost>()
    Assert.NotNull(host)

[<Fact>]
let ``AddAuthzn registers AuthorizationEngine as singleton`` () =
    let services = ServiceCollection() :> IServiceCollection

    services.AddAuthzn(fun config ->
        config
        |> AuthorizationConfig.addRole
            (RoleBuilder.create "r" "R"
             |> RoleBuilder.grantEverywhere "a:b"
             |> RoleBuilder.build))
    |> ignore

    let provider = services.BuildServiceProvider()
    let engine = provider.GetService<AuthorizationEngine>()
    Assert.NotNull(engine)

[<Fact>]
let ``AddAuthzn resolves working engine`` () =
    task {
        let services = ServiceCollection() :> IServiceCollection

        services.AddAuthzn(fun config ->
            let role =
                RoleBuilder.create "editor" "Editor"
                |> RoleBuilder.grantEverywhere "docs:read"
                |> RoleBuilder.grantEverywhere "docs:write"
                |> RoleBuilder.build

            config
            |> AuthorizationConfig.addRole role
            |> AuthorizationConfig.assign "alice" "editor")
        |> ignore

        let provider = services.BuildServiceProvider()
        let engine = provider.GetRequiredService<AuthorizationEngine>()

        let request =
            AuthorizationRequest.create (PrincipalId "alice") (PermissionId.create "docs" "write")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``AddAuthzn host and engine are same instance`` () =
    let services = ServiceCollection() :> IServiceCollection

    services.AddAuthzn(fun config ->
        config
        |> AuthorizationConfig.addRole
            (RoleBuilder.create "r" "R"
             |> RoleBuilder.grantEverywhere "a:b"
             |> RoleBuilder.build))
    |> ignore

    let provider = services.BuildServiceProvider()
    let host = provider.GetRequiredService<AuthorizationHost>()
    let engine = provider.GetRequiredService<AuthorizationEngine>()
    Assert.Same(host.Engine, engine)

[<Fact>]
let ``AddAuthzn with custom stores resolves working engine`` () =
    task {
        let roleStore = InMemoryRoleStore()

        let role =
            RoleBuilder.create "viewer" "Viewer"
            |> RoleBuilder.grantEverywhere "pages:view"
            |> RoleBuilder.build

        roleStore.Add(role)

        let assignmentStore = InMemoryAssignmentStore()
        assignmentStore.Add(Assignment.create (PrincipalId "bob") (RoleId "viewer"))

        let services = ServiceCollection() :> IServiceCollection
        services.AddAuthzn(roleStore, assignmentStore) |> ignore

        let provider = services.BuildServiceProvider()
        let engine = provider.GetRequiredService<AuthorizationEngine>()

        let request =
            AuthorizationRequest.create (PrincipalId "bob") (PermissionId.create "pages" "view")

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``AddAuthzn with custom stores and scope resolver`` () =
    task {
        let roleStore = InMemoryRoleStore()

        let role =
            { Id = RoleId "scoped"
              Name = "Scoped"
              Grants =
                [ { Permission = PermissionPattern.parse "data:read"
                    Scope = Map.ofList [ "owner", ScopeValue.principal ]
                    Condition = None
                    Metadata = GrantMetadata.empty } ] }

        roleStore.Add(role)

        let assignmentStore = InMemoryAssignmentStore()
        assignmentStore.Add(Assignment.create (PrincipalId "carol") (RoleId "scoped"))

        let resolver =
            syncResolver (fun principal _key grantValue requestValue ->
                if grantValue.Value = ScopeMarkers.Principal then
                    PrincipalId.value principal = requestValue
                else
                    false)

        let services = ServiceCollection() :> IServiceCollection
        services.AddAuthzn(roleStore, assignmentStore, resolver) |> ignore

        let provider = services.BuildServiceProvider()
        let engine = provider.GetRequiredService<AuthorizationEngine>()

        let request =
            AuthorizationRequest.create (PrincipalId "carol") (PermissionId.create "data" "read")
            |> AuthorizationRequest.withScope (Map.ofList [ "owner", "carol" ])

        let! decision = Engine.evaluateAsync engine CancellationToken.None request
        Assert.True(decision.IsAllowed)
    }

[<Fact>]
let ``AddAuthzn returns IServiceCollection for chaining`` () =
    let services = ServiceCollection() :> IServiceCollection

    let result =
        services.AddAuthzn(fun config -> config)

    Assert.Same(services, result)
