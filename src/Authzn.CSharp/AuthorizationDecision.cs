using System;
using Fs = Authzn;

namespace Authzn.CSharp;

/// <summary>
/// The reason an authorization request was denied, carried by <see cref="AuthorizationDecision.Denied"/>.
/// An allowed decision has no reason. No member is zero, so <c>default(DenyReason)</c> is not a reason.
/// </summary>
public enum DenyReason
{
    /// <summary>The principal has no role assignments.</summary>
    NoAssignments = 1,

    /// <summary>The principal has roles, but none grant the requested permission.</summary>
    NoMatchingPermission = 2,

    /// <summary>A grant covers the permission, but no grant that covers it matches the request's scope.</summary>
    ScopeMismatch = 3,

    /// <summary>The principal has assignments, but every one is expired, not yet valid, or revoked.</summary>
    AssignmentNotActive = 4,

    /// <summary>
    /// A grant covers the permission and matches the scope, but its <see cref="GrantMetadata"/>
    /// marks it revoked or expired.
    /// </summary>
    GrantNotActive = 5,

    /// <summary>
    /// No grant allows the request, and a grant that covers the permission, is active and matches
    /// the scope has an attribute-based (ABAC) condition that returned false or threw.
    /// </summary>
    AttributeEvaluationFailed = 6,
}

/// <summary>
/// The result of an authorization evaluation: <see cref="Allowed"/>, with the role and the pattern
/// of the first grant that allowed the request, or <see cref="Denied"/>, with the reason.
/// </summary>
public abstract record AuthorizationDecision
{
    private AuthorizationDecision() { }

    /// <summary>Access is allowed.</summary>
    /// <param name="Role">The role of the first grant that allowed the request.</param>
    /// <param name="Permission">
    /// The pattern of that grant, which can be wider than the requested permission
    /// (<see cref="PermissionPattern.Everything"/>, written <c>*</c>, for a grant of <c>*</c> or
    /// <c>*:*</c>).
    /// </param>
    public sealed record Allowed(RoleRef Role, PermissionPattern Permission) : AuthorizationDecision;

    /// <summary>Access is denied.</summary>
    /// <param name="Reason">The check that failed.</param>
    public sealed record Denied(DenyReason Reason) : AuthorizationDecision;

    /// <summary>Whether the decision is <see cref="Allowed"/>.</summary>
    public bool IsAllowed => this is Allowed;

    internal static AuthorizationDecision FromFs(Fs.AuthorizationDecision decision) => decision switch
    {
        Fs.AuthorizationDecision.Allowed allowed =>
            new Allowed(RoleRef.FromFs(allowed.Role), PermissionPattern.FromFs(allowed.Permission)),
        Fs.AuthorizationDecision.Denied denied => new Denied(Interop.FromDenyReason(denied.Reason)),
        _ => throw new InvalidOperationException($"Unmapped Authzn.AuthorizationDecision case '{decision}'."),
    };
}
