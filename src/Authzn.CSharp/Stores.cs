using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.FSharp.Collections;
using Microsoft.FSharp.Core;
using Fs = Authzn;

namespace Authzn.CSharp;

/// <summary>
/// Base class for a custom role store. Override <see cref="GetRoleAsync"/> to load roles from
/// your persistence. The engine calls it through the core's <c>Authzn.IRoleStore</c> interface for
/// the role of each active assignment it evaluates, and does not cache the result. Requests may be
/// evaluated on several threads at once, so the override must be safe for concurrent calls.
/// </summary>
public abstract class RoleStore : Fs.IRoleStore
{
    /// <summary>
    /// Returns the role with <paramref name="id"/>, or <see langword="null"/> if not found. The
    /// engine skips an assignment whose role is not found. <paramref name="cancellationToken"/> is
    /// the token the caller passed to the <see cref="Authorizer"/> method.
    /// </summary>
    public abstract Task<Role?> GetRoleAsync(RoleRef id, CancellationToken cancellationToken);

    async Task<FSharpOption<Fs.Role>> Fs.IRoleStore.GetRoleAsync(Fs.RoleId id, CancellationToken cancellationToken)
    {
        var role = await GetRoleAsync(RoleRef.FromFs(id), cancellationToken).ConfigureAwait(false);
        return role is null ? FSharpOption<Fs.Role>.None : FSharpOption<Fs.Role>.Some(role.ToFs());
    }
}

/// <summary>
/// Base class for a custom assignment store. Override <see cref="GetAssignmentsForPrincipalAsync"/>
/// to load assignments from your persistence. Requests may be evaluated on several threads at once,
/// so the override must be safe for concurrent calls.
/// </summary>
public abstract class AssignmentStore : Fs.IAssignmentStore
{
    /// <summary>
    /// Returns all role assignments for <paramref name="principal"/>. The list may include revoked
    /// or expired assignments, which the engine filters out with
    /// <see cref="Assignment.IsActiveAt"/>. The engine checks the active assignments in the order
    /// returned, so the order decides which role an allowed decision from
    /// <see cref="Authorizer.AuthorizeAsync(AuthorizationRequest, CancellationToken)"/> names when
    /// more than one role allows the request. <paramref name="cancellationToken"/> is the token the caller passed to
    /// the <see cref="Authorizer"/> method.
    /// </summary>
    public abstract Task<IReadOnlyList<Assignment>> GetAssignmentsForPrincipalAsync(
        PrincipalRef principal,
        CancellationToken cancellationToken);

    async Task<FSharpList<Fs.Assignment>> Fs.IAssignmentStore.GetAssignmentsForPrincipalAsync(
        Fs.PrincipalId principal,
        CancellationToken cancellationToken)
    {
        var assignments = await GetAssignmentsForPrincipalAsync(PrincipalRef.FromFs(principal), cancellationToken)
            .ConfigureAwait(false);
        return ListModule.OfSeq(assignments.Select(a => a.ToFs()));
    }
}
