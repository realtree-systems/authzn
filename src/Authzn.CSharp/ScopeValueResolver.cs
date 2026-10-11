using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.FSharp.Core;
using Fs = RealTree.Authzn;

namespace RealTree.Authzn.CSharp;

/// <summary>
/// Resolves scope markers (<see cref="ScopeValue.Marker"/>) at evaluation time. Derive from this
/// class to implement dynamic scoping such as <see cref="ScopeValue.Principal"/> ("the user's own
/// value") or <see cref="ScopeValue.Hierarchy"/> ("within the user's org tree"). A marker is never
/// compared as text; it matches a requested value only when <see cref="AdmitsAsync"/> returns
/// true. The engine may call <see cref="AdmitsAsync"/> once per grant and candidate, so an override
/// that answers from memory should return a completed <see cref="ValueTask{TResult}"/>, such as
/// <c>ValueTask.FromResult(value)</c>, rather than an <see langword="async"/> method.
/// </summary>
public abstract class ScopeValueResolver : Fs.IScopeValueResolver, Fs.IScopeValueEnumerator
{
    /// <summary>
    /// Returns <see langword="true"/> when the marker named <paramref name="marker"/> (e.g.
    /// <see cref="ScopeMarkers.Principal"/>), resolved for <paramref name="principal"/> under
    /// <paramref name="scopeKey"/>, admits <paramref name="requestValue"/>. Return
    /// <see langword="false"/> for a marker this resolver does not recognise.
    /// <paramref name="cancellationToken"/> is the token the caller passed to the
    /// <see cref="Authorizer"/> method.
    /// </summary>
    public abstract ValueTask<bool> AdmitsAsync(
        PrincipalRef principal,
        string scopeKey,
        string marker,
        string requestValue,
        CancellationToken cancellationToken);

    /// <summary>
    /// Returns the values the marker named <paramref name="marker"/> admits for
    /// <paramref name="principal"/> under <paramref name="scopeKey"/> (for example, the principal's
    /// subtree ids for <c>@hierarchy</c>), or <see langword="null"/> when this resolver cannot
    /// enumerate that marker. <see cref="Authorizer.VisibleScopeAsync"/> calls it for each marker
    /// in the grants it turns into a <see cref="ScopeConstraint"/>, and throws
    /// <see cref="NotSupportedException"/> when it returns <see langword="null"/>. The default
    /// returns <see langword="null"/> for every marker. The other <see cref="Authorizer"/> methods
    /// use only <see cref="AdmitsAsync"/>. <paramref name="cancellationToken"/> is the token the
    /// caller passed to <see cref="Authorizer.VisibleScopeAsync"/>.
    /// </summary>
    public virtual ValueTask<ScopeValueSet?> EnumerateScopeAsync(
        PrincipalRef principal,
        string scopeKey,
        string marker,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult<ScopeValueSet?>(null);

    ValueTask<bool> Fs.IScopeValueResolver.AdmitsAsync(
        Fs.PrincipalId principal,
        string scopeKey,
        Fs.MarkerName marker,
        string requestValue,
        CancellationToken cancellationToken) =>
        AdmitsAsync(PrincipalRef.FromFs(principal), scopeKey, marker.Value, requestValue, cancellationToken);

    async ValueTask<FSharpOption<Fs.ScopeValueSet>> Fs.IScopeValueEnumerator.EnumerateScopeAsync(
        Fs.PrincipalId principal,
        string scopeKey,
        Fs.MarkerName marker,
        CancellationToken cancellationToken)
    {
        var resolved = await EnumerateScopeAsync(PrincipalRef.FromFs(principal), scopeKey, marker.Value, cancellationToken)
            .ConfigureAwait(false);
        return resolved is null
            ? FSharpOption<Fs.ScopeValueSet>.None
            : FSharpOption<Fs.ScopeValueSet>.Some(resolved.ToFs());
    }
}

/// <summary>
/// A <see cref="ScopeValueResolver"/> whose <see cref="AdmitsAsync"/> calls a synchronous
/// delegate, so no subclass is needed for a resolver that answers from memory. Derive from
/// <see cref="ScopeValueResolver"/> for one that needs I/O. It does not override
/// <see cref="ScopeValueResolver.EnumerateScopeAsync"/>, so
/// <see cref="Authorizer.VisibleScopeAsync"/> throws <see cref="NotSupportedException"/> when a
/// grant it uses has a marker in its scope.
/// </summary>
public sealed class DelegateScopeResolver : ScopeValueResolver
{
    private readonly Func<PrincipalRef, string, string, string, bool> _admits;

    /// <summary>
    /// Creates a resolver that delegates to <paramref name="admits"/>, called with the principal, the scope
    /// key, the marker's name and the requested value.
    /// </summary>
    public DelegateScopeResolver(Func<PrincipalRef, string, string, string, bool> admits) =>
        _admits = admits ?? throw new ArgumentNullException(nameof(admits));

    /// <inheritdoc />
    public override ValueTask<bool> AdmitsAsync(
        PrincipalRef principal,
        string scopeKey,
        string marker,
        string requestValue,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult(_admits(principal, scopeKey, marker, requestValue));
}

/// <summary>
/// The names of the well-known scope markers, as <see cref="ScopeValueResolver.AdmitsAsync"/> receives them. In a
/// grant, use <see cref="ScopeValue.Principal"/> and <see cref="ScopeValue.Hierarchy"/>.
/// </summary>
public static class ScopeMarkers
{
    /// <summary>The principal's own value for a scope key.</summary>
    public const string Principal = Fs.ScopeMarkers.Principal;

    /// <summary>Membership in the principal's organizational hierarchy.</summary>
    public const string Hierarchy = Fs.ScopeMarkers.Hierarchy;
}
