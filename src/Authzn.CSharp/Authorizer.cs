using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.FSharp.Collections;
using Microsoft.FSharp.Core;
using Fs = Authzn;

namespace Authzn.CSharp;

/// <summary>
/// Evaluates authorization requests, and finds which of several permissions a principal holds or
/// which resources it may act on. When built with the in-memory stores, it also adds roles and
/// assignments and revokes assignments at runtime. Create one with
/// <see cref="AuthorizationBuilder"/> or resolve it from DI after <c>AddAuthzn(...)</c>.
/// </summary>
/// <remarks>
/// Methods that take one permission string parse it with <see cref="Permission.Parse"/>, which
/// throws <see cref="ArgumentException"/> for text that is not <c>resource:action</c>, including
/// any wildcard. <see cref="AllowedAmongAsync"/> and <see cref="GrantsAmongAsync"/> leave such
/// strings out instead.
/// </remarks>
public sealed class Authorizer
{
    private readonly Fs.AuthorizationHost _host;

    internal Authorizer(Fs.AuthorizationHost host) => _host = host;

    /// <summary>
    /// Evaluates <paramref name="request"/>. Only active assignments count. The request is allowed
    /// when any grant in their roles covers the permission, is active, matches the scope, and has
    /// no condition or a condition that returns true; a condition that throws counts as false. The
    /// decision names the first such grant, in the order the assignment store returns the
    /// assignments and each role lists its grants. When no grant allows and one of them failed only
    /// on its condition, the result is <see cref="DenyReason.AttributeEvaluationFailed"/>.
    /// </summary>
    public async Task<AuthorizationDecision> AuthorizeAsync(
        AuthorizationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var decision = await Fs.Engine
            .evaluateAsync(_host.Engine, cancellationToken, request.ToFs())
            .ConfigureAwait(false);
        return AuthorizationDecision.FromFs(decision);
    }

    /// <summary>
    /// Evaluates whether a principal may perform a permission, optionally in a scope and with
    /// attributes, as <see cref="AuthorizeAsync(AuthorizationRequest, CancellationToken)"/> does.
    /// </summary>
    public Task<AuthorizationDecision> AuthorizeAsync(
        PrincipalRef principal,
        string permission,
        IReadOnlyDictionary<string, string>? scope = null,
        IReadOnlyDictionary<string, object>? attributes = null,
        CancellationToken cancellationToken = default) =>
        AuthorizeAsync(new AuthorizationRequest(principal, Permission.Parse(permission), scope, attributes), cancellationToken);

    /// <summary>
    /// Returns the members of <paramref name="permissions"/> the principal holds in <paramref name="scope"/>:
    /// the batch form of <see cref="AuthorizeAsync(PrincipalRef, string, IReadOnlyDictionary{string, string}?, IReadOnlyDictionary{string, object}?, CancellationToken)"/>.
    /// A permission is in the result exactly when authorizing it on its own would allow. The principal's
    /// assignments are read once, however many permissions are asked about.
    /// </summary>
    /// <remarks>
    /// A string that <see cref="Permission.TryParse"/> rejects, including <see langword="null"/>
    /// and any wildcard such as <c>documents:*</c>, is left out of the result without an exception,
    /// so one bad entry does not fail the rest. The result holds the strings as they were passed.
    /// </remarks>
    public async Task<IReadOnlySet<string>> AllowedAmongAsync(
        PrincipalRef principal,
        IEnumerable<string> permissions,
        IReadOnlyDictionary<string, string>? scope = null,
        IReadOnlyDictionary<string, object>? attributes = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(permissions);

        var inputs = InputsByPermission(permissions);

        var held = await Fs.Engine
            .allowedAmongAsync(
                _host.Engine,
                cancellationToken,
                principal.ToFs(),
                inputs.Keys,
                Interop.ToStringMap(scope),
                Interop.ToObjectMap(attributes))
            .ConfigureAwait(false);

        var result = new HashSet<string>(StringComparer.Ordinal);

        foreach (var permission in held)
        {
            foreach (var text in inputs[permission])
            {
                result.Add(text);
            }
        }

        return result;
    }

    /// <summary>
    /// Returns, for each member of <paramref name="permissions"/> the principal holds in
    /// <paramref name="scope"/>, every grant that admits it and the role that carries each one. The
    /// key set equals <see cref="AllowedAmongAsync"/>'s result for the same arguments.
    /// </summary>
    /// <remarks>
    /// <see cref="AuthorizeAsync(AuthorizationRequest, CancellationToken)"/> reports only the first allowing grant, so
    /// an account holding both <c>*:*</c> and <c>invoices:approve</c> is credited to whichever
    /// role's assignment the assignment store returns first. GrantsAmongAsync returns both, and
    /// <see cref="GrantSource.IsWildcard"/> distinguishes a permission a role names from one a
    /// wildcard covers. A grant whose condition returns false or throws is not a source. Strings
    /// that do not parse are left out, and the keys are the strings as they were passed.
    /// </remarks>
    public async Task<IReadOnlyDictionary<string, IReadOnlyList<GrantSource>>> GrantsAmongAsync(
        PrincipalRef principal,
        IEnumerable<string> permissions,
        IReadOnlyDictionary<string, string>? scope = null,
        IReadOnlyDictionary<string, object>? attributes = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(permissions);

        var inputs = InputsByPermission(permissions);

        var held = await Fs.Engine
            .grantsAmongAsync(
                _host.Engine,
                cancellationToken,
                principal.ToFs(),
                inputs.Keys,
                Interop.ToStringMap(scope),
                Interop.ToObjectMap(attributes))
            .ConfigureAwait(false);

        var result = new Dictionary<string, IReadOnlyList<GrantSource>>(StringComparer.Ordinal);

        foreach (var (permission, sources) in held)
        {
            IReadOnlyList<GrantSource> converted = sources.Select(GrantSource.FromFs).ToList();

            foreach (var text in inputs[permission])
            {
                result[text] = converted;
            }
        }

        return result;
    }

    /// <summary>
    /// Maps each parsed permission to the input strings that parsed to it, so the permissions the
    /// core returns can be reported as the caller's strings. A string that
    /// <see cref="Permission.TryParse"/> rejects is left out. TryParse accepts only the exact
    /// <c>resource:action</c> text that <see cref="Permission.ToString"/> produces, so a list holds
    /// more than one string only when the input repeats a string.
    /// </summary>
    private static Dictionary<Fs.PermissionId, List<string>> InputsByPermission(IEnumerable<string> permissions)
    {
        var inputs = new Dictionary<Fs.PermissionId, List<string>>();

        foreach (var text in permissions)
        {
            if (text is null || !Permission.TryParse(text, out var parsed))
            {
                continue;
            }

            var key = parsed.ToFs();

            if (!inputs.TryGetValue(key, out var named))
            {
                named = [];
                inputs[key] = named;
            }

            named.Add(text);
        }

        return inputs;
    }

    /// <summary>
    /// Returns the members of <paramref name="candidates"/> the principal may perform
    /// <paramref name="permission"/> on, in their original order: the collection dual of
    /// <see cref="AuthorizeAsync(PrincipalRef, string, IReadOnlyDictionary{string, string}?, IReadOnlyDictionary{string, object}?, CancellationToken)"/>.
    /// A candidate is kept exactly when authorizing it on its own, with the scope from
    /// <paramref name="scopeOf"/> and the attributes from <paramref name="attributesOf"/> (empty
    /// when it is <see langword="null"/>), would allow: when some active grant covers the
    /// permission, matches the candidate's scope, and has no condition or a condition that returns
    /// true. A condition that throws counts as false.
    /// </summary>
    public async Task<IReadOnlyList<T>> FilterAsync<T>(
        PrincipalRef principal,
        string permission,
        IEnumerable<T> candidates,
        Func<T, IReadOnlyDictionary<string, string>> scopeOf,
        Func<T, IReadOnlyDictionary<string, object>>? attributesOf = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidates);
        ArgumentNullException.ThrowIfNull(scopeOf);

        var scopeFn = FSharpFunc<T, FSharpMap<string, string>>.FromConverter(item => Interop.ToStringMap(scopeOf(item)));
        var attrsFn = FSharpFunc<T, FSharpMap<string, object>>.FromConverter(
            item => Interop.ToObjectMap(attributesOf is null ? null : attributesOf(item)));

        var result = await Fs.Engine
            .filterAsync(_host.Engine, cancellationToken, principal.ToFs(), Permission.Parse(permission).ToFs(), candidates, scopeFn, attrsFn)
            .ConfigureAwait(false);
        return result.ToList();
    }

    /// <summary>
    /// Returns whether the principal may perform <paramref name="permission"/> on at least one
    /// resource within <paramref name="partialScope"/>, for a check such as "may you list anything
    /// in this tenant?". It returns <see langword="true"/> when an active grant that covers the
    /// permission matches <paramref name="partialScope"/> on every key both name; grant scope keys
    /// absent from <paramref name="partialScope"/> count as satisfiable. It does not enumerate
    /// resources, so it can return <see langword="true"/> when <see cref="FilterAsync{T}"/> over
    /// the actual resources returns an empty list. ABAC conditions are not evaluated (the method
    /// takes no attributes), so a grant with a condition counts as if the condition passed.
    /// </summary>
    public Task<bool> MayAnyAsync(
        PrincipalRef principal,
        string permission,
        IReadOnlyDictionary<string, string>? partialScope = null,
        CancellationToken cancellationToken = default) =>
        Fs.Engine.mayAnyAsync(
            _host.Engine,
            cancellationToken,
            principal.ToFs(),
            Permission.Parse(permission).ToFs(),
            Interop.ToStringMap(partialScope));

    /// <summary>
    /// Materialises the set of resources the principal may perform <paramref name="permission"/> on
    /// within <paramref name="partialScope"/> as a <see cref="ScopeConstraint"/> to apply in a
    /// query (a SQL where clause or an id set) instead of filtering loaded results. It uses the
    /// active grants that cover the permission and that <see cref="MayAnyAsync"/> would accept for
    /// <paramref name="partialScope"/>. A literal in a grant scope contributes its value; for a
    /// marker it calls <see cref="ScopeValueResolver.EnumerateScopeAsync"/>, and throws
    /// <see cref="NotSupportedException"/> when that returns <see langword="null"/> or no scope
    /// resolver is configured (use <see cref="FilterAsync{T}"/> for scopes that are not
    /// enumerable). ABAC conditions are not evaluated, so a grant with a condition contributes as
    /// if the condition passed; the caller applies conditions separately.
    /// </summary>
    public async Task<ScopeConstraint> VisibleScopeAsync(
        PrincipalRef principal,
        string permission,
        IReadOnlyDictionary<string, string>? partialScope = null,
        CancellationToken cancellationToken = default)
    {
        var constraint = await Fs.Engine
            .visibleScopeAsync(_host.Engine, cancellationToken, principal.ToFs(), Permission.Parse(permission).ToFs(), Interop.ToStringMap(partialScope))
            .ConfigureAwait(false);
        return ScopeConstraint.FromFs(constraint);
    }

    /// <summary>
    /// Adds <paramref name="role"/> to the in-memory role store, replacing any role with the same
    /// id. Throws <see cref="InvalidOperationException"/> when a custom role store is in use.
    /// </summary>
    public void AddRole(Role role)
    {
        ArgumentNullException.ThrowIfNull(role);
        _host.AddRole(role.ToFs());
    }

    /// <summary>
    /// Defines a role with <see cref="Role.Define"/> and adds it to the in-memory role store as
    /// <see cref="AddRole(Role)"/> does.
    /// </summary>
    public void AddRole(string id, string name, Action<RoleBuilder> configure) =>
        AddRole(Role.Define(id, name, configure));

    /// <summary>
    /// Adds <paramref name="assignment"/> to the in-memory assignment store. Throws
    /// <see cref="InvalidOperationException"/> when the authorizer uses a custom assignment store.
    /// </summary>
    public void AddAssignment(Assignment assignment)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        _host.AddAssignment(assignment.ToFs());
    }

    /// <summary>
    /// Revokes every assignment of <paramref name="role"/> to <paramref name="principal"/> in the
    /// in-memory assignment store; an assignment added afterwards is not revoked. Throws
    /// <see cref="InvalidOperationException"/> when the authorizer uses a custom assignment store.
    /// </summary>
    public void Revoke(PrincipalRef principal, RoleRef role) => _host.Revoke(principal.ToFs(), role.ToFs());

    /// <summary>
    /// Revokes the grant of <paramref name="role"/> whose <see cref="PermissionGrant.Key"/> is
    /// <paramref name="grant"/> in the in-memory role store, without removing the role: its
    /// <see cref="GrantMetadata.RevokedBy"/> becomes <paramref name="revokedBy"/> and its
    /// <see cref="GrantMetadata.RevokedAt"/> the authorizer's current time. A grant that is already
    /// revoked keeps its first revocation, and an unknown role or key changes nothing. Throws
    /// <see cref="InvalidOperationException"/> when the authorizer uses a custom role store; such a
    /// store revokes a grant by returning it with <see cref="GrantMetadata.RevokedAt"/> set.
    /// </summary>
    public void RevokeGrant(RoleRef role, GrantRef grant, PrincipalRef revokedBy) =>
        _host.RevokeGrant(role.ToFs(), grant.ToFs(), revokedBy.ToFs());

    /// <summary>
    /// Clears <see cref="GrantMetadata.RevokedAt"/> and <see cref="GrantMetadata.RevokedBy"/> on the
    /// grant of <paramref name="role"/> whose key is <paramref name="grant"/> in the in-memory role
    /// store, so it is active again unless its <see cref="GrantMetadata.ExpiresAt"/> has passed. An
    /// unknown role or key changes nothing. Throws <see cref="InvalidOperationException"/> when the
    /// authorizer uses a custom role store.
    /// </summary>
    public void ReinstateGrant(RoleRef role, GrantRef grant) => _host.ReinstateGrant(role.ToFs(), grant.ToFs());
}
