using Fs = Authzn;

namespace Authzn.CSharp;

/// <summary>
/// One grant that admits a permission, and the role that carries it. Returned by
/// <see cref="Authorizer.GrantsAmongAsync"/>.
/// </summary>
/// <param name="Role">The role whose grant admits the permission.</param>
/// <param name="Grant">
/// The grant as the role defines it, whose pattern can be wider than the permission asked about
/// (<see cref="PermissionPattern.Everything"/> for an administrator).
/// </param>
public sealed record GrantSource(RoleRef Role, PermissionGrant Grant)
{
    /// <summary>
    /// Whether the grant covers the permission through a <c>*</c> in its resource or its action.
    /// False means the grant names the permission exactly, because a pattern with no <c>*</c>
    /// covers only the one permission it names.
    /// </summary>
    public bool IsWildcard => Grant.Permission.IsWildcard;

    internal static GrantSource FromFs(Fs.GrantSource source) =>
        new(RoleRef.FromFs(source.Role), new PermissionGrant(source.Grant));
}
