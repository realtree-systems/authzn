namespace RealTree.Authzn

open System.Collections.Generic
open System.Runtime.CompilerServices
open System.Threading.Tasks
open Microsoft.Extensions.DependencyInjection

/// The <see cref="IGrantPolicyChain"/> that AddAuthzn registers. It receives every
/// registered <see cref="IGrantPolicy"/> from the container in registration order, calls them one
/// at a time, and returns the first decision that is not Allow without calling the rest. With no
/// policies registered it returns Allow.
type GrantPolicyChain(policies: IEnumerable<IGrantPolicy>) =
    let policyList = policies |> Seq.toArray

    /// Only Allow lets the next policy run. The match names every GrantPolicyDecision case, so a
    /// new case fails the build with FS0025 here until it is given a branch.
    let continues decision =
        match decision with
        | GrantPolicyDecision.Allow -> true
        | GrantPolicyDecision.Reject _
        | GrantPolicyDecision.RequireConsent _ -> false

    interface IGrantPolicyChain with
        member _.EvaluateAsync(context, cancellationToken) =
            task {
                let mutable result = GrantPolicyDecision.Allow
                let mutable i = 0

                while i < policyList.Length && continues result do
                    let! decision = policyList[i].EvaluateAsync(context, cancellationToken)
                    result <- decision
                    i <- i + 1

                return result
            }

/// Extension methods for registering authorization services with the dependency injection container.
[<Extension; AbstractClass; Sealed>]
type ServiceCollectionExtensions =

    /// Builds an AuthorizationHost from <c>configure</c> applied to
    /// AuthorizationConfig.defaultConfig, and registers the host, its AuthorizationEngine, and
    /// GrantPolicyChain as the IGrantPolicyChain, all as singletons. <c>configure</c> runs during
    /// this call.
    [<Extension>]
    static member AddAuthzn
        (services: IServiceCollection, configure: AuthorizationConfig -> AuthorizationConfig)
        =
        let config = configure AuthorizationConfig.defaultConfig
        let host = AuthorizationHost.build config
        services.AddSingleton<AuthorizationHost>(host) |> ignore
        services.AddSingleton<AuthorizationEngine>(host.Engine) |> ignore
        services.AddSingleton<IGrantPolicyChain, GrantPolicyChain>() |> ignore
        services

    /// Builds an AuthorizationHost over the given stores and optional scope resolver, and registers
    /// the host, its AuthorizationEngine, and GrantPolicyChain as the IGrantPolicyChain, all as
    /// singletons.
    [<Extension>]
    static member AddAuthzn
        (
            services: IServiceCollection,
            roleStore: IRoleStore,
            assignmentStore: IAssignmentStore,
            ?scopeResolver: IScopeValueResolver
        ) =
        let config =
            AuthorizationConfig.defaultConfig
            |> AuthorizationConfig.useRoleStore roleStore
            |> AuthorizationConfig.useAssignmentStore assignmentStore

        let config =
            match scopeResolver with
            | Some r -> config |> AuthorizationConfig.useScopeResolver r
            | None -> config

        let host = AuthorizationHost.build config
        services.AddSingleton<AuthorizationHost>(host) |> ignore
        services.AddSingleton<AuthorizationEngine>(host.Engine) |> ignore
        services.AddSingleton<IGrantPolicyChain, GrantPolicyChain>() |> ignore
        services

    /// Registers <c>'T</c> as a singleton <see cref="IGrantPolicy"/>. Multiple policies may be
    /// registered; GrantPolicyChain calls them in registration order and returns the first decision
    /// that is not Allow.
    [<Extension>]
    static member AddGrantPolicy<'T when 'T :> IGrantPolicy and 'T : not struct>
        (services: IServiceCollection)
        =
        services.AddSingleton<IGrantPolicy, 'T>() |> ignore
        services
