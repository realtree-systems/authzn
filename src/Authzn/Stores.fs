namespace RealTree.Authzn

open System
open System.Threading.Tasks

/// IRoleStore over an immutable Map from RoleId to Role. Writers replace the map under a lock and
/// readers take the current map without locking, so Add can run while other threads call
/// GetRoleAsync.
type InMemoryRoleStore() =
    let sync = obj ()

    [<VolatileField>]
    let mutable roles: Map<RoleId, Role> = Map.empty

    /// Adds the role, replacing any role with the same Id. Throws ArgumentException when two of its
    /// grants have the same permission pattern and scope (see <see cref="Role.validate"/>).
    member _.Add(role: Role) =
        Role.validate role
        lock sync (fun () -> roles <- roles.Add(role.Id, role))

    /// Replaces the role with this id by <c>update role</c>, holding the write lock from the read to
    /// the write so a concurrent Add or Update cannot be lost. Does nothing when there is no such
    /// role.
    member internal _.Update(id: RoleId, update: Role -> Role) =
        lock sync (fun () ->
            match roles.TryFind id with
            | Some role -> roles <- roles.Add(id, update role)
            | None -> ())

    interface IRoleStore with
        member _.GetRoleAsync(id, _cancellationToken) = Task.FromResult(roles.TryFind id)

/// IAssignmentStore over an immutable Map from PrincipalId to that principal's assignments, which
/// GetAssignmentsForPrincipalAsync returns in the order they were added. Writers replace the map
/// under a lock and readers take the current map without locking, so Add and Revoke can run while
/// other threads call GetAssignmentsForPrincipalAsync.
type InMemoryAssignmentStore() =
    let sync = obj ()

    [<VolatileField>]
    let mutable assignments: Map<PrincipalId, Assignment list> = Map.empty

    let assignmentsOf (principal: PrincipalId) =
        assignments |> Map.tryFind principal |> Option.defaultValue []

    /// Appends the assignment after the principal's existing assignments. An existing assignment of
    /// the same role is kept.
    member _.Add(assignment: Assignment) =
        lock sync (fun () ->
            assignments <- assignments.Add(assignment.Principal, assignmentsOf assignment.Principal @ [ assignment ]))

    /// Sets Revoked on every assignment of the role to the principal. Does nothing when there is
    /// none.
    member _.Revoke(principal: PrincipalId, role: RoleId) =
        lock sync (fun () ->
            match assignments.TryFind principal with
            | Some existing ->
                let revoked =
                    existing
                    |> List.map (fun a -> if a.Role = role && not a.Revoked then Assignment.revoke a else a)

                assignments <- assignments.Add(principal, revoked)
            | None -> ())

    interface IAssignmentStore with
        member _.GetAssignmentsForPrincipalAsync(principal, _cancellationToken) =
            Task.FromResult(assignmentsOf principal)

/// IGrantStore over an InMemoryRoleStore. RevokeGrantAsync and ReinstateGrantAsync replace the role
/// in roleStore with a copy in which every grant whose GrantKey.forGrant equals the key has
/// RevokedAt and RevokedBy set or cleared, under the role store's write lock, so concurrent calls
/// on grants of one role do not lose each other's changes. An unknown role or key leaves the store
/// unchanged, and a grant that is already revoked keeps its RevokedAt and RevokedBy.
type InMemoryGrantStore(roleStore: InMemoryRoleStore) =
    let updateGrant (role: Role) (key: GrantKey) (transform: GrantMetadata -> GrantMetadata) =
        let newGrants =
            role.Grants
            |> List.map (fun g ->
                if GrantKey.forGrant g = key then
                    { g with Metadata = transform g.Metadata }
                else
                    g)

        { role with Grants = newGrants }

    member internal _.Revoke(roleId: RoleId, grantKey: GrantKey, revokedBy: PrincipalId, at: DateTimeOffset) =
        roleStore.Update(
            roleId,
            fun role ->
                updateGrant role grantKey (fun m ->
                    match m.RevokedAt with
                    | Some _ -> m
                    | None ->
                        { m with
                            RevokedAt = Some at
                            RevokedBy = Some revokedBy })
        )

    member internal _.Reinstate(roleId: RoleId, grantKey: GrantKey) =
        roleStore.Update(
            roleId,
            fun role ->
                updateGrant role grantKey (fun m ->
                    { m with
                        RevokedAt = None
                        RevokedBy = None })
        )

    interface IGrantStore with
        member store.RevokeGrantAsync(roleId, grantKey, revokedBy, at, _cancellationToken) =
            store.Revoke(roleId, grantKey, revokedBy, at)
            Task.CompletedTask

        member store.ReinstateGrantAsync(roleId, grantKey, _cancellationToken) =
            store.Reinstate(roleId, grantKey)
            Task.CompletedTask
