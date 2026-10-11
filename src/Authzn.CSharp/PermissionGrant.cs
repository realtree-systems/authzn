using System.Collections.Generic;
using Microsoft.FSharp.Core;
using Microsoft.FSharp.Collections;
using Fs = RealTree.Authzn;

namespace RealTree.Authzn.CSharp;

/// <summary>
/// A read-only view of a single permission grant within a role: the pattern it covers, its grant
/// scope, whether it carries an ABAC condition, and its metadata. Returned by
/// <see cref="Role.Grants"/>, <see cref="GrantPolicyContext.Grant"/> and
/// <see cref="GrantSource.Grant"/>.
/// </summary>
public sealed class PermissionGrant
{
    private readonly Fs.PermissionGrant _fs;

    internal PermissionGrant(Fs.PermissionGrant fs) => _fs = fs;

    /// <summary>The pattern of permissions the grant covers.</summary>
    public PermissionPattern Permission => PermissionPattern.FromFs(_fs.Permission);

    /// <summary>
    /// The grant scope: each key must be present in the request's scope with a matching value. An
    /// empty grant scope places no scope restriction on the grant.
    /// </summary>
    public IReadOnlyDictionary<string, ScopeValue> Scope => Interop.FromGrantScope(_fs.Scope);

    /// <summary>Whether the grant carries an ABAC condition.</summary>
    public bool HasCondition =>
        FSharpOption<FSharpFunc<FSharpMap<string, object>, bool>>.get_IsSome(_fs.Condition);

    /// <summary>Audit and lifecycle metadata for the grant.</summary>
    public GrantMetadata Metadata => GrantMetadata.FromFs(_fs.Metadata);

    /// <summary>
    /// The key that identifies this grant for per-grant revocation, computed from its pattern and
    /// scope (see <see cref="GrantRef"/>).
    /// </summary>
    public GrantRef Key => GrantRef.FromFs(Fs.GrantKeyModule.forGrant(_fs));

    internal Fs.PermissionGrant ToFs() => _fs;
}
