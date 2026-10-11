module Authzn.Tests.GrantPolicyTests

open System.Collections.Generic
open System.Threading
open System.Threading.Tasks
open Authzn
open Authzn.Tests.Helpers
open Microsoft.Extensions.DependencyInjection
open Xunit

let private ctx () : GrantPolicyContext =
    { Principal = testPrincipal
      Role = RoleId "r"
      Grant =
        { Permission = PermissionPattern.parse "documents:read"
          Scope = Map.empty
          Condition = None
          Metadata = GrantMetadata.empty }
      Properties = Map.empty }

type private AllowPolicy() =
    interface IGrantPolicy with
        member _.EvaluateAsync(_ctx, _cancellationToken) = Task.FromResult GrantPolicyDecision.Allow

type private RejectPolicy(reason: string, code: string) =
    interface IGrantPolicy with
        member _.EvaluateAsync(_ctx, _cancellationToken) = Task.FromResult(GrantPolicyDecision.Reject(reason, code))

type private RequireConsentPolicy(reason: string, tier: string) =
    interface IGrantPolicy with
        member _.EvaluateAsync(_ctx, _cancellationToken) = Task.FromResult(GrantPolicyDecision.RequireConsent(reason, tier))

[<Fact>]
let ``empty chain returns Allow`` () =
    task {
        let chain = GrantPolicyChain(Seq.empty) :> IGrantPolicyChain
        let! d = chain.EvaluateAsync(ctx (), CancellationToken.None)
        Assert.Equal(GrantPolicyDecision.Allow, d)
    }

[<Fact>]
let ``all-allow chain returns Allow`` () =
    task {
        let policies: IGrantPolicy seq = seq { AllowPolicy(); AllowPolicy() }
        let chain = GrantPolicyChain(policies) :> IGrantPolicyChain
        let! d = chain.EvaluateAsync(ctx (), CancellationToken.None)
        Assert.Equal(GrantPolicyDecision.Allow, d)
    }

[<Fact>]
let ``first Reject in chain wins`` () =
    task {
        let policies: IGrantPolicy seq =
            seq { AllowPolicy(); RejectPolicy("no", "DENIED"); RejectPolicy("won't reach", "OTHER") }
        let chain = GrantPolicyChain(policies) :> IGrantPolicyChain
        let! d = chain.EvaluateAsync(ctx (), CancellationToken.None)
        Assert.Equal(GrantPolicyDecision.Reject("no", "DENIED"), d)
    }

[<Fact>]
let ``first RequireConsent in chain wins`` () =
    task {
        let policies: IGrantPolicy seq =
            seq { AllowPolicy(); RequireConsentPolicy("need ok", "elevated"); AllowPolicy() }
        let chain = GrantPolicyChain(policies) :> IGrantPolicyChain
        let! d = chain.EvaluateAsync(ctx (), CancellationToken.None)
        Assert.Equal(GrantPolicyDecision.RequireConsent("need ok", "elevated"), d)
    }

[<Fact>]
let ``AddGrantPolicy registers IGrantPolicy and the chain resolves it`` () =
    task {
        let services = ServiceCollection()
        services
            .AddAuthzn(fun cfg -> cfg)
            .AddGrantPolicy<RejectPolicy>() |> ignore
        // The container cannot supply RejectPolicy's reason and code constructor arguments, so the
        // type registration AddGrantPolicy added is replaced with an instance.
        let descriptors =
            services
            |> Seq.filter (fun d -> d.ServiceType = typeof<IGrantPolicy>)
            |> Seq.toList
        let registered = Assert.Single<ServiceDescriptor>(descriptors)
        Assert.Equal(typeof<RejectPolicy>, registered.ImplementationType)
        Assert.Equal(ServiceLifetime.Singleton, registered.Lifetime)
        for d in descriptors do services.Remove(d) |> ignore
        services.AddSingleton<IGrantPolicy>(RejectPolicy("blocked", "DENIED")) |> ignore
        let sp = services.BuildServiceProvider()
        let chain = sp.GetRequiredService<IGrantPolicyChain>()
        let! d = chain.EvaluateAsync(ctx (), CancellationToken.None)
        Assert.Equal(GrantPolicyDecision.Reject("blocked", "DENIED"), d)
    }

[<Fact>]
let ``AddAuthzn alone registers an empty chain that allows everything`` () =
    task {
        let services = ServiceCollection()
        services.AddAuthzn(fun cfg -> cfg) |> ignore
        let sp = services.BuildServiceProvider()
        let chain = sp.GetRequiredService<IGrantPolicyChain>()
        let! d = chain.EvaluateAsync(ctx (), CancellationToken.None)
        Assert.Equal(GrantPolicyDecision.Allow, d)
    }
