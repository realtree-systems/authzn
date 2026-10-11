using System;
using Fs = Authzn;

namespace Authzn.CSharp;

/// <summary>
/// The link between a principal and a role, optionally bounded by a validity window and
/// revocable. Construct one with <see cref="Create"/> or <see cref="ForWindow"/>; a custom
/// <see cref="AssignmentStore"/> returns these from
/// <see cref="AssignmentStore.GetAssignmentsForPrincipalAsync"/>.
/// </summary>
public sealed class Assignment
{
    private readonly Fs.Assignment _fs;

    internal Assignment(Fs.Assignment fs) => _fs = fs;

    /// <summary>The principal to whom the role is assigned.</summary>
    public PrincipalRef Principal => PrincipalRef.FromFs(_fs.Principal);

    /// <summary>The role being assigned.</summary>
    public RoleRef Role => RoleRef.FromFs(_fs.Role);

    /// <summary>The earliest time the assignment is active, or <see langword="null"/> for immediately.</summary>
    public DateTimeOffset? NotBefore => Interop.FromOptionStruct(_fs.NotBefore);

    /// <summary>The time the assignment expires, or <see langword="null"/> for never.</summary>
    public DateTimeOffset? NotAfter => Interop.FromOptionStruct(_fs.NotAfter);

    /// <summary>Whether this assignment has been revoked.</summary>
    public bool Revoked => _fs.Revoked;

    /// <summary>Creates an assignment with no time constraints.</summary>
    public static Assignment Create(PrincipalRef principal, RoleRef role) =>
        new(Fs.AssignmentModule.create(principal.ToFs(), role.ToFs()));

    /// <summary>
    /// Creates an assignment active from <paramref name="notBefore"/> (inclusive) until
    /// <paramref name="notAfter"/> (exclusive). Either bound may be <see langword="null"/>, leaving
    /// that side open.
    /// </summary>
    public static Assignment ForWindow(
        PrincipalRef principal,
        RoleRef role,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null) =>
        new(new Fs.Assignment(
            principal.ToFs(),
            role.ToFs(),
            Interop.ToOptionStruct(notBefore),
            Interop.ToOptionStruct(notAfter),
            false));

    /// <summary>Returns a copy of this assignment marked revoked.</summary>
    public Assignment AsRevoked() => new(Fs.AssignmentModule.revoke(_fs));

    /// <summary>
    /// Returns whether the assignment is not revoked and <paramref name="at"/> is at or after
    /// <see cref="NotBefore"/> and before <see cref="NotAfter"/>, where each is set.
    /// </summary>
    public bool IsActiveAt(DateTimeOffset at) => Fs.AssignmentModule.isActiveAt(at, _fs);

    internal Fs.Assignment ToFs() => _fs;
}
