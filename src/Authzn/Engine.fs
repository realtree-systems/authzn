namespace RealTree.Authzn

open System
open System.Threading
open System.Threading.Tasks

/// An authorization request for <c>Engine.evaluateAsync</c>.
type AuthorizationRequest =
    { /// The principal requesting access.
      Principal: PrincipalId
      /// The permission being requested.
      Permission: PermissionId
      /// The scope bag of the resource being acted on. A grant matches only when every key of its
      /// scope is present here with a matching value, so an empty bag matches only grants whose
      /// scope is empty.
      Scope: ScopeBag
      /// The attributes passed to the condition of each grant that matches the request.
      Attributes: AttributeBag }

/// Functions for constructing authorization requests using a pipe-friendly API.
[<RequireQualifiedAccess>]
module AuthorizationRequest =

    /// Creates a new authorization request for the given principal and permission,
    /// with empty scope and attributes.
    let create principal permission =
        { Principal = principal
          Permission = permission
          Scope = Map.empty
          Attributes = Map.empty }

    /// Replaces the request's scope bag.
    let withScope (scope: ScopeBag) (request: AuthorizationRequest) = { request with Scope = scope }

    /// Replaces the request's attribute bag, which is passed to grant conditions.
    let withAttributes (attributes: AttributeBag) (request: AuthorizationRequest) =
        { request with Attributes = attributes }

/// The stores, scope resolver and clock that the Engine functions evaluate against. Create one
/// with AuthorizationEngine.create, or use AuthorizationHost.Engine. Its fields are not public, so
/// a setting can be added later as a new function without breaking callers.
[<NoEquality; NoComparison>]
type AuthorizationEngine =
    internal
        { RoleStore: IRoleStore
          AssignmentStore: IAssignmentStore
          ScopeResolver: IScopeValueResolver option
          TimeProvider: TimeProvider }

/// Functions for creating and configuring an AuthorizationEngine.
[<RequireQualifiedAccess>]
module AuthorizationEngine =

    /// An engine over the stores, with no scope resolver and the system clock. Without a resolver,
    /// a grant whose scope holds a marker matches no request. Throws ArgumentNullException when a
    /// store is null.
    let create (roleStore: IRoleStore) (assignmentStore: IAssignmentStore) : AuthorizationEngine =
        ArgumentNullException.ThrowIfNull(roleStore, nameof roleStore)
        ArgumentNullException.ThrowIfNull(assignmentStore, nameof assignmentStore)

        { RoleStore = roleStore
          AssignmentStore = assignmentStore
          ScopeResolver = None
          TimeProvider = TimeProvider.System }

    /// Returns the engine with <c>resolver</c> resolving scope markers such as "@principal" or
    /// "@hierarchy". visibleScopeAsync also needs the resolver to implement IScopeValueEnumerator.
    /// Throws ArgumentNullException when the resolver is null.
    let withScopeResolver (resolver: IScopeValueResolver) (engine: AuthorizationEngine) =
        ArgumentNullException.ThrowIfNull(resolver, nameof resolver)
        { engine with ScopeResolver = Some resolver }

    /// Returns the engine with <c>timeProvider</c> as its clock. The engine reads the current UTC
    /// time from it once per call, to decide which assignments and grants are active. Use it to
    /// test expiry without waiting. Throws ArgumentNullException when the provider is null.
    let withTimeProvider (timeProvider: TimeProvider) (engine: AuthorizationEngine) =
        ArgumentNullException.ThrowIfNull(timeProvider, nameof timeProvider)
        { engine with TimeProvider = timeProvider }

/// Authorization queries over an AuthorizationEngine: evaluateAsync for one request,
/// allowedAmongAsync and grantsAmongAsync for many permissions in one scope, and filterAsync,
/// mayAnyAsync and visibleScopeAsync for which resources a principal may act on. Each passes its
/// <c>cancellationToken</c> to every store and scope resolver call it makes.
[<RequireQualifiedAccess>]
module Engine =

    /// True when the grant has no condition or its condition returns true for the attributes. A
    /// condition that throws counts as false, so a faulty condition withholds its grant instead of
    /// failing the request.
    let private conditionPasses (condition: (AttributeBag -> bool) option) (attributes: AttributeBag) =
        match condition with
        | None -> true
        | Some condFn ->
            try
                condFn attributes
            with _ ->
                false

    /// Evaluates an authorization request against the configured stores. Returns Denied
    /// NoAssignments when the assignment store returns no assignments for the principal, and Denied
    /// AssignmentNotActive when none is active at the engine's current UTC time. Otherwise the
    /// request is allowed when any grant in the roles of the active assignments covers the
    /// permission, has active metadata, matches the request scope, and has no condition or a
    /// condition that returns true; a condition that throws counts as false. Roles that are not
    /// found are skipped. The decision names the first allowing grant and its role, in the order
    /// the assignment store returns the assignments and each role lists its grants. When no grant
    /// allows, the reason is the first of these that applies: AttributeEvaluationFailed (a grant
    /// matched on permission, metadata and scope, but its condition failed), GrantNotActive (a
    /// revoked or expired grant matches on permission and scope), ScopeMismatch (a grant covers the
    /// permission), and NoMatchingPermission.
    let evaluateAsync
        (engine: AuthorizationEngine)
        (cancellationToken: CancellationToken)
        (request: AuthorizationRequest)
        : Task<AuthorizationDecision> =
        task {
            let! assignments =
                engine.AssignmentStore.GetAssignmentsForPrincipalAsync(request.Principal, cancellationToken)

            if assignments.IsEmpty then
                return Denied DenyReason.NoAssignments
            else
                let now = engine.TimeProvider.GetUtcNow()
                let activeAssignments = assignments |> List.filter (Assignment.isActiveAt now)

                if activeAssignments.IsEmpty then
                    return Denied DenyReason.AssignmentNotActive
                else
                    let mutable allowed: AuthorizationDecision option = None
                    let mutable conditionFailed = false
                    let mutable inactiveScopeMatch = false
                    let mutable permissionMatch = false

                    for assignment in activeAssignments do
                        if allowed.IsNone then
                            let! roleOpt = engine.RoleStore.GetRoleAsync(assignment.Role, cancellationToken)

                            match roleOpt with
                            | None -> ()
                            | Some role ->
                                for grant in role.Grants do
                                    if allowed.IsNone && PermissionPattern.covers request.Permission grant.Permission then
                                        permissionMatch <- true

                                        let! scopeMatches =
                                            Permissions.scopeMatchesAsync
                                                request.Principal
                                                engine.ScopeResolver
                                                grant.Scope
                                                request.Scope
                                                cancellationToken

                                        if scopeMatches then
                                            if not (GrantMetadata.isActiveAt now grant.Metadata) then
                                                inactiveScopeMatch <- true
                                            elif conditionPasses grant.Condition request.Attributes then
                                                allowed <- Some(Allowed(assignment.Role, grant.Permission))
                                            else
                                                conditionFailed <- true

                    match allowed with
                    | Some decision -> return decision
                    | None when conditionFailed -> return Denied DenyReason.AttributeEvaluationFailed
                    | None when inactiveScopeMatch -> return Denied DenyReason.GrantNotActive
                    | None when permissionMatch -> return Denied DenyReason.ScopeMismatch
                    | None -> return Denied DenyReason.NoMatchingPermission
        }

    /// Returns the candidates the principal holds in the scope, passing <c>attributes</c> to grant
    /// conditions: the batch form of evaluateAsync for many permissions in one scope. A candidate
    /// is in the result exactly when evaluateAsync, given the same principal, scope and attributes,
    /// would return Allowed for it, that is when some active grant covers it, matches the scope and
    /// has no condition or a passing one. The assignment store is read once and the role store at
    /// most once per active assignment, however many candidates there are; the walk stops once
    /// every candidate is held.
    let allowedAmongAsync
        (engine: AuthorizationEngine)
        (cancellationToken: CancellationToken)
        (principal: PrincipalId)
        (candidates: PermissionId seq)
        (scope: ScopeBag)
        (attributes: AttributeBag)
        : Task<Set<PermissionId>> =
        task {
            let! assignments = engine.AssignmentStore.GetAssignmentsForPrincipalAsync(principal, cancellationToken)
            let now = engine.TimeProvider.GetUtcNow()
            let held = System.Collections.Generic.HashSet<PermissionId>()
            let pending = System.Collections.Generic.List<PermissionId>(Seq.distinct candidates)

            for assignment in assignments |> List.filter (Assignment.isActiveAt now) do
                if pending.Count > 0 then
                    let! roleOpt = engine.RoleStore.GetRoleAsync(assignment.Role, cancellationToken)

                    match roleOpt with
                    | None -> ()
                    | Some role ->
                        for grant in role.Grants do
                            // The scope is checked only for a grant that covers a pending candidate,
                            // so the resolver is not called for grants that cannot change the result.
                            if
                                pending.Count > 0
                                && GrantMetadata.isActiveAt now grant.Metadata
                                && pending.Exists(fun candidate -> PermissionPattern.covers candidate grant.Permission)
                            then
                                let! scopeMatches =
                                    Permissions.scopeMatchesAsync principal engine.ScopeResolver grant.Scope scope cancellationToken

                                if scopeMatches && conditionPasses grant.Condition attributes then
                                    for index in pending.Count - 1 .. -1 .. 0 do
                                        if PermissionPattern.covers pending[index] grant.Permission then
                                            held.Add pending[index] |> ignore
                                            pending.RemoveAt index

            return Set.ofSeq held
        }

    /// Returns, for each candidate the principal holds in the scope, every grant that admits it and
    /// the role that carries each one, in assignment and grant order. A grant admits a candidate
    /// when it is active, covers the candidate, matches the scope and has no condition or a passing
    /// one. The key set equals allowedAmongAsync's result for the same arguments.
    ///
    /// evaluateAsync names only the first allowing grant, so for a principal holding "*:*" through
    /// one role and "invoices:approve" through another, its Allowed decision names whichever role's
    /// assignment the assignment store returns first. This function returns both, so a caller can
    /// tell a permission a role names from one a wildcard covers.
    let grantsAmongAsync
        (engine: AuthorizationEngine)
        (cancellationToken: CancellationToken)
        (principal: PrincipalId)
        (candidates: PermissionId seq)
        (scope: ScopeBag)
        (attributes: AttributeBag)
        : Task<Map<PermissionId, GrantSource list>> =
        task {
            let! assignments = engine.AssignmentStore.GetAssignmentsForPrincipalAsync(principal, cancellationToken)
            let now = engine.TimeProvider.GetUtcNow()
            let wanted = Array.ofSeq (Seq.distinct candidates)
            let sources = System.Collections.Generic.Dictionary<PermissionId, ResizeArray<GrantSource>>()

            for assignment in assignments |> List.filter (Assignment.isActiveAt now) do
                let! roleOpt = engine.RoleStore.GetRoleAsync(assignment.Role, cancellationToken)

                match roleOpt with
                | None -> ()
                | Some role ->
                    for grant in role.Grants do
                        let covered =
                            wanted |> Array.filter (fun candidate -> PermissionPattern.covers candidate grant.Permission)

                        if covered.Length > 0 && GrantMetadata.isActiveAt now grant.Metadata then
                            let! scopeMatches =
                                Permissions.scopeMatchesAsync principal engine.ScopeResolver grant.Scope scope cancellationToken

                            if scopeMatches && conditionPasses grant.Condition attributes then
                                let source = { Role = assignment.Role; Grant = grant }

                                for candidate in covered do
                                    match sources.TryGetValue candidate with
                                    | true, found -> found.Add source
                                    | false, _ -> sources[candidate] <- ResizeArray [ source ]

            return
                sources
                |> Seq.map (fun pair -> pair.Key, List.ofSeq pair.Value)
                |> Map.ofSeq
        }

    /// The grants that cover the permission and whose metadata is active, from the roles of the
    /// principal's active assignments, in assignment and grant order. Shared by filterAsync,
    /// mayAnyAsync and visibleScopeAsync.
    let private activeGrantsForAsync
        (engine: AuthorizationEngine)
        (cancellationToken: CancellationToken)
        (principal: PrincipalId)
        (permission: PermissionId)
        : Task<PermissionGrant list> =
        task {
            let! assignments = engine.AssignmentStore.GetAssignmentsForPrincipalAsync(principal, cancellationToken)
            let now = engine.TimeProvider.GetUtcNow()
            let grants = ResizeArray<PermissionGrant>()

            for assignment in assignments |> List.filter (Assignment.isActiveAt now) do
                let! roleOpt = engine.RoleStore.GetRoleAsync(assignment.Role, cancellationToken)

                match roleOpt with
                | None -> ()
                | Some role ->
                    for grant in role.Grants do
                        if
                            PermissionPattern.covers permission grant.Permission
                            && GrantMetadata.isActiveAt now grant.Metadata
                        then
                            grants.Add grant

            return List.ofSeq grants
        }

    /// Returns the members of <c>candidates</c>, in input order, that the principal may act on for
    /// the permission: exactly those for which <see cref="evaluateAsync"/>, given
    /// <c>scopeOf candidate</c> and <c>attributesOf candidate</c>, would return Allowed. A candidate
    /// is kept when some active grant that covers the permission, from the principal's active
    /// assignments, matches <c>scopeOf candidate</c> and has no condition or a condition that
    /// returns true for <c>attributesOf candidate</c>; a condition that throws counts as false. The
    /// stores are read once per call, however many candidates there are. Throws
    /// OperationCanceledException between candidates once <c>cancellationToken</c> is cancelled.
    let filterAsync
        (engine: AuthorizationEngine)
        (cancellationToken: CancellationToken)
        (principal: PrincipalId)
        (permission: PermissionId)
        (candidates: 'T seq)
        (scopeOf: 'T -> ScopeBag)
        (attributesOf: 'T -> AttributeBag)
        : Task<'T list> =
        task {
            let! grants = activeGrantsForAsync engine cancellationToken principal permission
            let kept = ResizeArray<'T>()

            if not grants.IsEmpty then
                for item in candidates do
                    cancellationToken.ThrowIfCancellationRequested()
                    let scope = scopeOf item
                    let attributes = lazy (attributesOf item)
                    let mutable admitted = false
                    let mutable remaining = grants

                    while not admitted && not remaining.IsEmpty do
                        let grant = remaining.Head
                        remaining <- remaining.Tail

                        let! scopeMatches =
                            Permissions.scopeMatchesAsync principal engine.ScopeResolver grant.Scope scope cancellationToken

                        if scopeMatches && conditionPasses grant.Condition attributes.Value then
                            admitted <- true

                    if admitted then
                        kept.Add item

            return List.ofSeq kept
        }

    /// Returns true when some active grant that covers the permission, from the principal's active
    /// assignments, admits <c>partialScope</c>: every key of the grant's scope that partialScope
    /// also holds matches there. It checks whether the principal may act on any resource within the
    /// partial scope (e.g. "may the principal list anything in this tenant?"). Grant keys that
    /// partialScope lacks are not checked and no values are enumerated, so it can return true when
    /// no resource is admitted, for example when such a key holds a marker that admits no value;
    /// <see cref="filterAsync"/> over the resources then returns an empty list. ABAC conditions are
    /// not evaluated, because the call has no resource attributes to pass them, so it can also
    /// return true for a grant whose condition would fail.
    let mayAnyAsync
        (engine: AuthorizationEngine)
        (cancellationToken: CancellationToken)
        (principal: PrincipalId)
        (permission: PermissionId)
        (partialScope: ScopeBag)
        : Task<bool> =
        task {
            let! grants = activeGrantsForAsync engine cancellationToken principal permission
            let mutable found = false
            let mutable remaining = grants

            while not found && not remaining.IsEmpty do
                let grant = remaining.Head
                remaining <- remaining.Tail

                let! admits =
                    Permissions.scopeAdmitsAsync principal engine.ScopeResolver grant.Scope partialScope cancellationToken

                if admits then
                    found <- true

            return found
        }

    /// Returns the resources the principal may act on for the permission within <c>partialScope</c>
    /// as a <see cref="ScopeConstraint"/> a caller can translate into a query filter. The grants
    /// considered are the active grants that cover the permission, from the principal's active
    /// assignments, that admit partialScope as in <see cref="mayAnyAsync"/>; with none, the result
    /// is Nothing. Each becomes one clause, in which a literal becomes a one-element set and a
    /// marker becomes the set that the engine's resolver, as an <see cref="IScopeValueEnumerator"/>,
    /// returns for it; AnyValue keys are dropped, and an empty clause makes the result Everything.
    /// The clauses are not narrowed to partialScope's values, so the caller must also apply
    /// partialScope in the query.
    ///
    /// Throws <see cref="System.NotSupportedException"/> when a considered grant's scope holds a
    /// marker and the engine has no resolver, the resolver does not implement
    /// IScopeValueEnumerator, or it returns None for the marker, even if another grant would make
    /// the result Everything; use <see cref="filterAsync"/> for such collections. Conditions are
    /// ignored, so a grant with a condition contributes its clause as if the condition passed; the
    /// caller must apply any ABAC condition itself.
    let visibleScopeAsync
        (engine: AuthorizationEngine)
        (cancellationToken: CancellationToken)
        (principal: PrincipalId)
        (permission: PermissionId)
        (partialScope: ScopeBag)
        : Task<ScopeConstraint> =
        task {
            let! grants = activeGrantsForAsync engine cancellationToken principal permission
            let relevant = ResizeArray<PermissionGrant>()

            for grant in grants do
                let! admits =
                    Permissions.scopeAdmitsAsync principal engine.ScopeResolver grant.Scope partialScope cancellationToken

                if admits then
                    relevant.Add grant

            if relevant.Count = 0 then
                return Nothing
            else
                let enumerator =
                    match engine.ScopeResolver with
                    | Some resolver ->
                        match box resolver with
                        | :? IScopeValueEnumerator as e -> Some e
                        | _ -> None
                    | None -> None

                let clauses = ResizeArray<Map<string, ScopeValueSet>>()

                for grant in relevant do
                    // AnyValue keys are left out, so a clause left empty means its grant admits
                    // every resource and the result is Everything.
                    let mutable clause = Map.empty

                    for KeyValue(key, grantValue) in grant.Scope do
                        match grantValue with
                        | ScopeValue.Literal literal -> clause <- clause.Add(key, Values(Set.singleton literal))
                        | ScopeValue.Marker marker ->
                            let! valueSet =
                                match enumerator with
                                | Some e -> e.EnumerateScopeAsync(principal, key, marker, cancellationToken)
                                | None -> ValueTask<ScopeValueSet option>(None)

                            match valueSet with
                            | Some AnyValue -> ()
                            | Some(Values _ as values) -> clause <- clause.Add(key, values)
                            | None ->
                                raise (
                                    NotSupportedException(
                                        $"visibleScopeAsync cannot materialise the scope marker '{marker.Value}' for key '{key}': the resolver does not enumerate it (implement IScopeValueEnumerator). Use filterAsync instead."
                                    )
                                )

                    clauses.Add clause

                if clauses |> Seq.exists Map.isEmpty then
                    return Everything
                else
                    return Restricted(List.ofSeq clauses)
        }
