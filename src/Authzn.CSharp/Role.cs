using System;
using System.Collections.Generic;
using System.Linq;
using Fs = Authzn;

namespace Authzn.CSharp;

/// <summary>
/// A reusable definition of authority: a named set of permission grants assigned to principals.
/// Build one with <see cref="Define"/> (or via <c>AuthorizationBuilder.AddRole</c>); a custom
/// <see cref="RoleStore"/> returns these from <see cref="RoleStore.GetRoleAsync"/>.
/// </summary>
public sealed class Role
{
    private readonly Fs.Role _fs;

    internal Role(Fs.Role fs) => _fs = fs;

    /// <summary>The unique identifier for this role.</summary>
    public RoleRef Id => RoleRef.FromFs(_fs.Id);

    /// <summary>The human-readable name of the role.</summary>
    public string Name => _fs.Name;

    /// <summary>
    /// The permission grants this role provides, in the order they were added.
    /// <see cref="Authorizer.AuthorizeAsync(AuthorizationRequest, System.Threading.CancellationToken)"/>
    /// allows a request when any of them allows it, and the order decides which grant an allowed
    /// decision names when more than one does.
    /// </summary>
    public IReadOnlyList<PermissionGrant> Grants =>
        _fs.Grants.Select(grant => new PermissionGrant(grant)).ToList();

    /// <summary>
    /// Defines a role by id and name, configuring its grants via the supplied builder action. Throws
    /// <see cref="ArgumentException"/> as <see cref="RoleBuilder.Build"/> does.
    /// </summary>
    public static Role Define(string id, string name, Action<RoleBuilder> configure)
    {
        var builder = new RoleBuilder(id, name);
        configure(builder);
        return builder.Build();
    }

    internal Fs.Role ToFs() => _fs;
}
