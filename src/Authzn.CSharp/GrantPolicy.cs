using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Fs = RealTree.Authzn;

namespace RealTree.Authzn.CSharp;

/// <summary>
/// The decision a write-time <see cref="GrantPolicy"/> returns: <see cref="Allow"/>,
/// <see cref="Reject"/> with a reason and code, or <see cref="RequireConsent"/> with a reason and
/// consent tier. These are its only cases, so a <c>switch</c> over them is complete.
/// </summary>
public abstract record GrantPolicyDecision
{
    private GrantPolicyDecision() { }

    /// <summary>The grant may be added.</summary>
    public sealed record Allow : GrantPolicyDecision;

    /// <summary>The grant must not be added.</summary>
    /// <param name="Reason">A human-readable reason, chosen by the policy.</param>
    /// <param name="Code">A machine-readable identifier, chosen by the policy.</param>
    public sealed record Reject(string Reason, string Code) : GrantPolicyDecision;

    /// <summary>
    /// The grant may be added only after explicit consent. A caller with no consent step should
    /// treat it as <see cref="Reject"/>.
    /// </summary>
    /// <param name="Reason">A human-readable reason, chosen by the policy.</param>
    /// <param name="Tier">A consumer-defined consent tier, such as <c>elevated</c>.</param>
    public sealed record RequireConsent(string Reason, string Tier) : GrantPolicyDecision;

    internal Fs.GrantPolicyDecision ToFs() => this switch
    {
        Allow => Fs.GrantPolicyDecision.Allow,
        Reject reject => Fs.GrantPolicyDecision.NewReject(reject.Reason, reject.Code),
        RequireConsent consent => Fs.GrantPolicyDecision.NewRequireConsent(consent.Reason, consent.Tier),
        _ => throw new InvalidOperationException($"Unknown GrantPolicyDecision '{this}'."),
    };

    internal static GrantPolicyDecision FromFs(Fs.GrantPolicyDecision decision) => decision switch
    {
        { IsAllow: true } => new Allow(),
        Fs.GrantPolicyDecision.Reject reject => new Reject(reject.Reason, reject.Code),
        Fs.GrantPolicyDecision.RequireConsent consent => new RequireConsent(consent.Reason, consent.Tier),
        _ => throw new InvalidOperationException($"Unmapped RealTree.Authzn.GrantPolicyDecision case '{decision}'."),
    };
}

/// <summary>
/// The proposed write that a <see cref="GrantPolicy"/> evaluates: the principal adding the grant,
/// the role, the grant, and caller-defined properties.
/// </summary>
public sealed class GrantPolicyContext
{
    private readonly Fs.GrantPolicyContext _fs;

    /// <summary>
    /// Creates the context for adding <paramref name="grant"/> to <paramref name="role"/> on
    /// behalf of <paramref name="principal"/>. Take <paramref name="grant"/> from
    /// <see cref="Role.Grants"/> of the role as it will be written, for example one built with
    /// <see cref="Role.Define"/>. <paramref name="properties"/> is empty when it is
    /// <see langword="null"/>.
    /// </summary>
    public GrantPolicyContext(
        PrincipalRef principal,
        RoleRef role,
        PermissionGrant grant,
        IReadOnlyDictionary<string, string>? properties = null)
    {
        ArgumentNullException.ThrowIfNull(grant);
        _fs = new Fs.GrantPolicyContext(principal.ToFs(), role.ToFs(), grant.ToFs(), Interop.ToStringMap(properties));
    }

    internal GrantPolicyContext(Fs.GrantPolicyContext fs) => _fs = fs;

    /// <summary>The principal attempting to add the grant.</summary>
    public PrincipalRef Principal => PrincipalRef.FromFs(_fs.Principal);

    /// <summary>The role the grant is being added to.</summary>
    public RoleRef Role => RoleRef.FromFs(_fs.Role);

    /// <summary>The proposed grant.</summary>
    public PermissionGrant Grant => new(_fs.Grant);

    /// <summary>
    /// Caller-defined values for policies to read, such as an installation id or a tenant. Authzn
    /// defines no keys and does not read them.
    /// </summary>
    public IReadOnlyDictionary<string, string> Properties => Interop.FromStringMap(_fs.Properties);

    internal Fs.GrantPolicyContext ToFs() => _fs;
}

/// <summary>
/// Base class for a write-time grant policy. Override <see cref="EvaluateAsync"/> to allow, reject,
/// or require consent for a proposed grant. Neither the engine nor <see cref="RoleBuilder"/> calls
/// a policy. Your grant-write code calls it directly, or registers policies with
/// <c>AddGrantPolicy&lt;T&gt;</c> and calls the <see cref="GrantPolicyChain"/> that
/// <c>AddAuthzn</c> registers.
/// </summary>
public abstract class GrantPolicy : Fs.IGrantPolicy
{
    /// <summary>
    /// Evaluates the proposed grant. Implementations should be fast and side-effect-free.
    /// <paramref name="cancellationToken"/> is the token passed to the policy chain.
    /// </summary>
    public abstract Task<GrantPolicyDecision> EvaluateAsync(
        GrantPolicyContext context,
        CancellationToken cancellationToken);

    async Task<Fs.GrantPolicyDecision> Fs.IGrantPolicy.EvaluateAsync(
        Fs.GrantPolicyContext context,
        CancellationToken cancellationToken)
    {
        var decision = await EvaluateAsync(new GrantPolicyContext(context), cancellationToken).ConfigureAwait(false);
        return decision.ToFs();
    }
}

/// <summary>
/// Runs write-time grant policies in order and returns the first decision that is not
/// <see cref="GrantPolicyDecision.Allow"/>, without calling the policies after it, or
/// <see cref="GrantPolicyDecision.Allow"/> when every policy allows or there is none.
/// <c>AddAuthzn</c> registers one as a singleton over the policies registered with
/// <c>AddGrantPolicy&lt;T&gt;</c>, in registration order. Nothing in Authzn calls it; your
/// grant-write code calls <see cref="EvaluateAsync"/> and enforces the decision. A caller with no
/// consent step should treat <see cref="GrantPolicyDecision.RequireConsent"/> as
/// <see cref="GrantPolicyDecision.Reject"/>.
/// </summary>
public sealed class GrantPolicyChain
{
    private readonly Fs.IGrantPolicyChain _fs;

    /// <summary>
    /// Creates a chain over <paramref name="policies"/>, which it runs in the order given. Throws
    /// <see cref="ArgumentException"/> when an element is <see langword="null"/>.
    /// </summary>
    public GrantPolicyChain(IEnumerable<GrantPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(policies);
        var list = policies.ToArray();

        if (list.Any(policy => policy is null))
        {
            throw new ArgumentException("The policies must not contain null.", nameof(policies));
        }

        _fs = new Fs.GrantPolicyChain(list);
    }

    internal GrantPolicyChain(Fs.IGrantPolicyChain fs) => _fs = fs;

    /// <summary>
    /// Evaluates <paramref name="context"/> with each policy in turn, passing
    /// <paramref name="cancellationToken"/> to each, and returns the first decision that is not
    /// <see cref="GrantPolicyDecision.Allow"/>, or <see cref="GrantPolicyDecision.Allow"/>.
    /// </summary>
    public async Task<GrantPolicyDecision> EvaluateAsync(
        GrantPolicyContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        var decision = await _fs.EvaluateAsync(context.ToFs(), cancellationToken).ConfigureAwait(false);
        return GrantPolicyDecision.FromFs(decision);
    }
}
