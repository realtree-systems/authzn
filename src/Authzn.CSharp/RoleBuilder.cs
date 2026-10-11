using System;
using System.Collections.Generic;
using Microsoft.FSharp.Collections;
using Fs = RealTree.Authzn;

namespace RealTree.Authzn.CSharp;

/// <summary>
/// A fluent builder for a <see cref="Role"/>. Add a confined grant (a scope, an ABAC condition, or
/// both) with <c>Grant</c> or <see cref="GrantIf"/>, or an unconfined grant with
/// <see cref="GrantEverywhere(string)"/>, then call <see cref="Build"/>. Use it directly to build
/// roles for a custom store, or through <c>AuthorizationBuilder.AddRole</c>. Each grant method
/// parses its permission argument with <see cref="PermissionPattern.Parse"/>, so it may hold a
/// wildcard, and throws <see cref="ArgumentException"/> when the text is not a pattern.
/// <para>
/// A grant with an empty grant scope and no condition applies to every resource in every tenant.
/// <c>Grant</c> and <see cref="GrantIf"/> throw <see cref="ArgumentException"/> when they receive an
/// empty scope, even with a condition, and when they receive neither a scope nor a condition, so a
/// forgotten or empty scope fails at the call. <see cref="GrantEverywhere(string)"/> is the only
/// way to add such a grant.
/// </para>
/// </summary>
public sealed class RoleBuilder
{
    private Fs.RoleBuilder.State _state;

    /// <summary>Starts building a role with the given id and human-readable name.</summary>
    public RoleBuilder(string id, string name) => _state = Fs.RoleBuilder.create(id, name);

    /// <summary>
    /// Adds an unconfined grant of <paramref name="permission"/>: an empty grant scope and no
    /// condition, so it applies to every resource in every tenant. Use it for a deliberate
    /// cross-cutting grant, such as a platform superuser; for a confined grant pass a scope to
    /// <c>Grant</c>.
    /// </summary>
    public RoleBuilder GrantEverywhere(string permission) => Add(permission, null, null, null, everywhere: true);

    /// <summary>
    /// Adds an unconfined grant, as <see cref="GrantEverywhere(string)"/> does, carrying
    /// <paramref name="metadata"/>.
    /// </summary>
    public RoleBuilder GrantEverywhere(string permission, GrantMetadata metadata) =>
        Add(permission, null, null, metadata, everywhere: true);

    /// <summary>
    /// Adds a grant confined to <paramref name="scope"/>, where each value is a
    /// <see cref="ScopeValue.Literal"/> or a <see cref="ScopeValue.Marker"/>. Throws
    /// <see cref="ArgumentException"/> when <paramref name="scope"/> is empty or a value is
    /// <see langword="null"/>; use <see cref="GrantEverywhere(string)"/> for an unconfined grant.
    /// </summary>
    public RoleBuilder Grant(string permission, params (string key, ScopeValue value)[] scope) =>
        Add(permission, Interop.ToGrantScope(scope), null, null, everywhere: false);

    /// <summary>
    /// Adds a grant confined to <paramref name="scope"/>. Throws <see cref="ArgumentException"/>
    /// when <paramref name="scope"/> is <see langword="null"/> or empty or holds a null value.
    /// </summary>
    public RoleBuilder Grant(string permission, IReadOnlyDictionary<string, ScopeValue> scope) =>
        Add(permission, Interop.ToGrantScope(scope), null, null, everywhere: false);

    /// <summary>
    /// Adds a grant that applies only when <paramref name="condition"/> returns true for the
    /// request's attributes, and optionally only within <paramref name="scope"/>. The condition
    /// confines the grant, so <paramref name="scope"/> may be <see langword="null"/>, but an empty
    /// <paramref name="scope"/> throws <see cref="ArgumentException"/>, because a scope that comes
    /// out empty has usually lost its keys. Use guarded lookups (<c>attrs.TryGetValue(...)</c>); a
    /// condition that throws counts as false. When the condition fails and no other grant allows
    /// the request,
    /// <see cref="Authorizer.AuthorizeAsync(AuthorizationRequest, System.Threading.CancellationToken)"/>
    /// returns <see cref="DenyReason.AttributeEvaluationFailed"/>.
    /// </summary>
    public RoleBuilder GrantIf(
        string permission,
        Func<IReadOnlyDictionary<string, object>, bool> condition,
        IReadOnlyDictionary<string, ScopeValue>? scope = null) =>
        Add(permission, scope is null ? null : Interop.ToGrantScope(scope), condition, null, everywhere: false);

    /// <summary>
    /// Adds a grant carrying <paramref name="metadata"/>, confined by <paramref name="scope"/>,
    /// <paramref name="condition"/>, or both. Throws <see cref="ArgumentException"/> when
    /// <paramref name="scope"/> is empty, or when <paramref name="scope"/> and
    /// <paramref name="condition"/> are both <see langword="null"/>; use
    /// <see cref="GrantEverywhere(string, GrantMetadata)"/> for an unconfined grant.
    /// </summary>
    public RoleBuilder Grant(
        string permission,
        GrantMetadata metadata,
        IReadOnlyDictionary<string, ScopeValue>? scope = null,
        Func<IReadOnlyDictionary<string, object>, bool>? condition = null) =>
        Add(permission, scope is null ? null : Interop.ToGrantScope(scope), condition, metadata, everywhere: false);

    /// <summary>
    /// Builds the configured <see cref="Role"/>. Throws <see cref="ArgumentException"/> when two
    /// grants have the same permission pattern and scope, because they would share a
    /// <see cref="GrantRef"/>; merge their conditions into one grant or move one to another role.
    /// </summary>
    public Role Build() => new(Fs.RoleBuilder.build(_state));

    private RoleBuilder Add(
        string permission,
        FSharpMap<string, Fs.ScopeValue>? scope,
        Func<IReadOnlyDictionary<string, object>, bool>? condition,
        GrantMetadata? metadata,
        bool everywhere)
    {
        // Confinement is checked only in the core, so this facade and the F# API reject the same
        // inputs. RoleBuilder.grant and grantWith throw ArgumentException for an empty scope, and
        // for an absent scope with no condition; grantEverywhere is the only core function that
        // adds an unconfined grant. A null scope here becomes None, any other scope Some.
        var scopeOption = Interop.ToScopeOption(scope);
        var conditionOption = Interop.ToConditionOption(condition);

        if (everywhere)
            _state = metadata is null
                ? Fs.RoleBuilder.grantEverywhere(permission, _state)
                : Fs.RoleBuilder.grantEverywhereWith(permission, metadata.ToFs(), _state);
        else
            _state = metadata is null
                ? Fs.RoleBuilder.grant(permission, scopeOption, conditionOption, _state)
                : Fs.RoleBuilder.grantWith(permission, scopeOption, conditionOption, metadata.ToFs(), _state);

        return this;
    }
}
