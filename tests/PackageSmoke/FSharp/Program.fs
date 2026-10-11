// Installs Authzn from the packed package and checks one allowed and one denied decision.
open System.Threading
open Authzn

[<EntryPoint>]
let main _ =
    let reader =
        RoleBuilder.create "reader" "Reader"
        |> RoleBuilder.grant "documents:read" (Some(Map.ofList [ "tenant", ScopeValue.Literal "acme" ])) None
        |> RoleBuilder.build

    let host =
        AuthorizationConfig.defaultConfig
        |> AuthorizationConfig.addRole reader
        |> AuthorizationConfig.assign "alice" "reader"
        |> AuthorizationHost.build

    let decide tenant =
        AuthorizationRequest.create (PrincipalId "alice") (PermissionId.parse "documents:read")
        |> AuthorizationRequest.withScope (Map.ofList [ "tenant", tenant ])
        |> Engine.evaluateAsync host.Engine CancellationToken.None
        |> fun task -> task.Result

    match decide "acme", decide "globex" with
    | Allowed _, Denied DenyReason.ScopeMismatch ->
        printfn "Authzn smoke test passed"
        0
    | inTenant, otherTenant ->
        eprintfn "Authzn smoke test failed: acme -> %A, globex -> %A" inTenant otherTenant
        1
