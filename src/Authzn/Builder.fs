namespace RealTree.Authzn

open System

/// Pipe-friendly functions for building role definitions with permission grants.
[<RequireQualifiedAccess>]
module RoleBuilder =

    /// A role under construction, passed from create through the grant functions to build. Its
    /// fields are not public. Grants holds the grants newest first; build reverses them.
    [<NoEquality; NoComparison>]
    type State =
        internal
            { Id: RoleId
              Name: string
              Grants: PermissionGrant list }

    /// Creates a new role builder state with the given id and name, and no grants.
    let create (id: string) (name: string) : State =
        { Id = RoleId id; Name = name; Grants = [] }

    /// Adds the grant at the head of state.Grants. build reverses the list, so the role keeps its
    /// grants in the order they were added.
    let private append (pg: PermissionGrant) (state: State) =
        { state with Grants = pg :: state.Grants }

    /// Throws ArgumentException when the scope is Some empty map, or when the scope and the
    /// condition are both None. A grant with neither matches every request scope, so grant and
    /// grantWith treat it as a forgotten scope; grantEverywhere is the way to add one deliberately.
    /// An empty map is rejected even with a condition, because a scope built at run time that comes
    /// out empty has usually lost its keys, and accepting it would apply the grant in every tenant.
    /// Pass None for a grant confined by its condition alone.
    let private ensureConfined (permission: string) (scope: GrantScope option) (condition: (AttributeBag -> bool) option) =
        match scope, condition with
        | Some s, _ when Map.isEmpty s ->
            invalidArg
                "scope"
                (sprintf
                    "Grant of '%s' has an empty scope, so it would apply to every resource in every tenant. Pass a non-empty scope, pass no scope (None, or null in the C# facade) for a grant confined by its condition alone, or use RoleBuilder.grantEverywhere (GrantEverywhere in the C# facade) for a deliberately unconfined grant."
                    permission)
        | None, None ->
            invalidArg
                "scope"
                (sprintf
                    "Grant of '%s' has no scope and no condition, so it would apply to every resource in every tenant. Pass a non-empty scope, add a condition, or use RoleBuilder.grantEverywhere (GrantEverywhere in the C# facade) for a deliberately unconfined grant."
                    permission)
        | _ -> ()

    /// Adds a confined grant with empty metadata. The permission is a pattern in "resource:action"
    /// format, with "*" for any resource or action (see PermissionPattern.parse, which throws
    /// ArgumentException for text that is not a pattern). Throws ArgumentException when the scope
    /// is an empty map, or when the scope and the condition are both None, because such a grant
    /// would match every request scope; use grantEverywhere to add one deliberately.
    let grant
        (permission: string)
        (scope: GrantScope option)
        (condition: (AttributeBag -> bool) option)
        (state: State)
        =
        ensureConfined permission scope condition
        let scopeMap = scope |> Option.defaultValue Map.empty

        append
            { Permission = PermissionPattern.parse permission
              Scope = scopeMap
              Condition = condition
              Metadata = GrantMetadata.empty }
            state

    /// Adds a confined grant with the given metadata, under the same rules and exceptions as grant.
    /// Use it to set GrantMetadata fields such as ExpiresAt, ConsentedBy or Source.
    let grantWith
        (permission: string)
        (scope: GrantScope option)
        (condition: (AttributeBag -> bool) option)
        (metadata: GrantMetadata)
        (state: State)
        =
        ensureConfined permission scope condition
        let scopeMap = scope |> Option.defaultValue Map.empty

        append
            { Permission = PermissionPattern.parse permission
              Scope = scopeMap
              Condition = condition
              Metadata = metadata }
            state

    /// Adds an unconfined grant, with no scope and no condition, which matches every request scope
    /// (e.g. for a platform superuser). grant and grantWith reject such a grant, so that it cannot
    /// be created by passing an empty scope by mistake; this function adds one deliberately. Throws
    /// ArgumentException when the permission is not a valid pattern.
    let grantEverywhere (permission: string) (state: State) =
        append
            { Permission = PermissionPattern.parse permission
              Scope = Map.empty
              Condition = None
              Metadata = GrantMetadata.empty }
            state

    /// Adds an unconfined grant with the given metadata (see grantEverywhere).
    let grantEverywhereWith (permission: string) (metadata: GrantMetadata) (state: State) =
        append
            { Permission = PermissionPattern.parse permission
              Scope = Map.empty
              Condition = None
              Metadata = metadata }
            state

    /// Builds a Role from the state, with its grants in the order they were added, which is the
    /// order Engine.evaluateAsync checks them. Throws ArgumentException when two grants have the
    /// same permission pattern and scope (see <see cref="Role.validate"/>).
    let build (state: State) : Role =
        let role: Role =
            { Id = state.Id
              Name = state.Name
              Grants = List.rev state.Grants }

        Role.validate role
        role

/// The input to AuthorizationHost.build. Start from AuthorizationConfig.defaultConfig and pipe it
/// through the AuthorizationConfig module functions. Its fields are not public, so a setting can be
/// added later as a new function without breaking callers.
[<NoEquality; NoComparison>]
type AuthorizationConfig =
    internal
        { /// Roles to register in the in-memory store, in the order they were added. Their ids must
          /// be distinct. Ignored if a custom RoleStore is provided.
          Roles: Role list
          /// Assignments to register in the in-memory store, in the order they were added, which is
          /// the order the store returns them and Engine.evaluateAsync checks their roles. Ignored
          /// if a custom AssignmentStore is provided.
          Assignments: Assignment list
          /// Optional custom role store. If None, an InMemoryRoleStore is created.
          RoleStore: IRoleStore option
          /// Optional custom assignment store. If None, an InMemoryAssignmentStore is created.
          AssignmentStore: IAssignmentStore option
          /// Optional resolver for scope markers. With None, a grant whose scope holds a marker
          /// matches no request.
          ScopeResolver: IScopeValueResolver option
          /// Optional clock for the engine. With None, the engine uses TimeProvider.System.
          TimeProvider: TimeProvider option }

/// Pipe-friendly functions for configuring an authorization system.
[<RequireQualifiedAccess>]
module AuthorizationConfig =

    /// An empty default configuration with no roles, assignments, or custom stores.
    let defaultConfig =
        { Roles = []
          Assignments = []
          RoleStore = None
          AssignmentStore = None
          ScopeResolver = None
          TimeProvider = None }

    let private duplicateRole (role: Role) =
        invalidArg
            "role"
            $"Role '{RoleId.value role.Id}' is configured more than once. Give each role a distinct id, or use AuthorizationHost.AddRole (Authorizer.AddRole in the C# facade) at runtime to replace a role."

    /// Adds a role definition after the roles already configured. Throws ArgumentException when a
    /// role with the same id is already configured.
    let addRole (role: Role) (config: AuthorizationConfig) =
        if config.Roles |> List.exists (fun r -> r.Id = role.Id) then
            duplicateRole role

        { config with Roles = config.Roles @ [ role ] }

    /// Assigns a role to a principal with no time constraints, after the assignments already
    /// configured.
    let assign (principal: string) (role: string) (config: AuthorizationConfig) =
        let a = Assignment.create (PrincipalId principal) (RoleId role)
        { config with Assignments = config.Assignments @ [ a ] }

    /// Assigns a role to a principal, active from notBefore (inclusive) until notAfter (exclusive),
    /// after the assignments already configured. None leaves that end of the window open.
    let assignForWindow
        (principal: string)
        (role: string)
        (notBefore: DateTimeOffset option)
        (notAfter: DateTimeOffset option)
        (config: AuthorizationConfig)
        =
        let a =
            { Principal = PrincipalId principal
              Role = RoleId role
              NotBefore = notBefore
              NotAfter = notAfter
              Revoked = false }

        { config with Assignments = config.Assignments @ [ a ] }

    /// Revokes the principal's assignments of the role configured so far. An assignment added later
    /// in the pipeline is not revoked. Ignored when a custom assignment store is configured, like
    /// every configured assignment.
    let revoke (principal: string) (role: string) (config: AuthorizationConfig) =
        let principal, role = PrincipalId principal, RoleId role

        { config with
            Assignments =
                config.Assignments
                |> List.map (fun a ->
                    if a.Principal = principal && a.Role = role then Assignment.revoke a else a) }

    /// Specifies a custom IRoleStore implementation instead of the default InMemoryRoleStore. The
    /// configured Roles are then ignored. Throws ArgumentNullException when the store is null.
    let useRoleStore (store: IRoleStore) (config: AuthorizationConfig) =
        ArgumentNullException.ThrowIfNull(store, nameof store)
        { config with RoleStore = Some store }

    /// Specifies a custom IAssignmentStore implementation instead of the default
    /// InMemoryAssignmentStore. The configured Assignments are then ignored. Throws
    /// ArgumentNullException when the store is null.
    let useAssignmentStore (store: IAssignmentStore) (config: AuthorizationConfig) =
        ArgumentNullException.ThrowIfNull(store, nameof store)
        { config with AssignmentStore = Some store }

    /// Specifies an IScopeValueResolver for resolving scope markers like "@principal" or
    /// "@hierarchy". Throws ArgumentNullException when the resolver is null.
    let useScopeResolver (resolver: IScopeValueResolver) (config: AuthorizationConfig) =
        ArgumentNullException.ThrowIfNull(resolver, nameof resolver)
        { config with ScopeResolver = Some resolver }

    /// Specifies the clock the engine reads the current UTC time from, instead of
    /// TimeProvider.System. Use it to test expiry and assignment windows without waiting. Throws
    /// ArgumentNullException when the provider is null.
    let useTimeProvider (timeProvider: TimeProvider) (config: AuthorizationConfig) =
        ArgumentNullException.ThrowIfNull(timeProvider, nameof timeProvider)
        { config with TimeProvider = Some timeProvider }

/// Holds an AuthorizationEngine built by AuthorizationHost.build. At runtime it adds roles when the
/// role store is an InMemoryRoleStore, and adds and revokes assignments when the assignment store is
/// an InMemoryAssignmentStore.
type AuthorizationHost internal (engine: AuthorizationEngine) =

    /// The AuthorizationEngine over this host's stores, scope resolver and clock, for the Engine
    /// functions.
    member _.Engine = engine

    /// Adds a role to the in-memory role store at runtime, replacing any role with the same Id.
    /// Throws InvalidOperationException if not using InMemoryRoleStore.
    member _.AddRole(role: Role) =
        match engine.RoleStore with
        | :? InMemoryRoleStore as store -> store.Add(role)
        | _ -> invalidOp "AddRole is only supported with InMemoryRoleStore"

    /// Adds an assignment to the in-memory assignment store at runtime.
    /// Throws InvalidOperationException if not using InMemoryAssignmentStore.
    member _.AddAssignment(assignment: Assignment) =
        match engine.AssignmentStore with
        | :? InMemoryAssignmentStore as store -> store.Add(assignment)
        | _ -> invalidOp "AddAssignment is only supported with InMemoryAssignmentStore"

    /// Revokes every assignment of the role to the principal in the in-memory assignment store.
    /// Throws InvalidOperationException if not using InMemoryAssignmentStore.
    member _.Revoke(principal: PrincipalId, role: RoleId) =
        match engine.AssignmentStore with
        | :? InMemoryAssignmentStore as store -> store.Revoke(principal, role)
        | _ -> invalidOp "Revoke is only supported with InMemoryAssignmentStore"

    /// Revokes the grant of the role whose <see cref="GrantKey.forGrant"/> is <c>grantKey</c> in
    /// the in-memory role store, setting RevokedBy to <c>revokedBy</c> and RevokedAt to the engine's
    /// current time, as InMemoryGrantStore.RevokeGrantAsync does: a grant that is already revoked
    /// keeps its first revocation, and an unknown role or key changes nothing. Throws
    /// InvalidOperationException if not using InMemoryRoleStore.
    member _.RevokeGrant(role: RoleId, grantKey: GrantKey, revokedBy: PrincipalId) =
        match engine.RoleStore with
        | :? InMemoryRoleStore as store ->
            InMemoryGrantStore(store).Revoke(role, grantKey, revokedBy, engine.TimeProvider.GetUtcNow())
        | _ -> invalidOp "RevokeGrant is only supported with InMemoryRoleStore"

    /// Clears RevokedAt and RevokedBy on the grant of the role whose key is <c>grantKey</c> in the
    /// in-memory role store, so it is active again unless its ExpiresAt has passed. An unknown role
    /// or key changes nothing. Throws InvalidOperationException if not using InMemoryRoleStore.
    member _.ReinstateGrant(role: RoleId, grantKey: GrantKey) =
        match engine.RoleStore with
        | :? InMemoryRoleStore as store -> InMemoryGrantStore(store).Reinstate(role, grantKey)
        | _ -> invalidOp "ReinstateGrant is only supported with InMemoryRoleStore"

/// Functions for building an AuthorizationHost from configuration.
[<RequireQualifiedAccess>]
module AuthorizationHost =

    /// Builds an AuthorizationHost from the given configuration. Unless useRoleStore set a role
    /// store, it creates an InMemoryRoleStore holding the added roles, and unless
    /// useAssignmentStore set an assignment store, an InMemoryAssignmentStore holding the
    /// assignments, both in configuration order. Throws ArgumentException when an added role fails
    /// <see cref="Role.validate"/>.
    let build (config: AuthorizationConfig) =
        let roleStore =
            match config.RoleStore with
            | Some s -> s
            | None ->
                let store = InMemoryRoleStore()

                for role in config.Roles do
                    store.Add(role)

                store :> IRoleStore

        let assignmentStore =
            match config.AssignmentStore with
            | Some s -> s
            | None ->
                let store = InMemoryAssignmentStore()

                for a in config.Assignments do
                    store.Add(a)

                store :> IAssignmentStore

        let engine = AuthorizationEngine.create roleStore assignmentStore

        let engine =
            match config.ScopeResolver with
            | Some resolver -> engine |> AuthorizationEngine.withScopeResolver resolver
            | None -> engine

        let engine =
            match config.TimeProvider with
            | Some timeProvider -> engine |> AuthorizationEngine.withTimeProvider timeProvider
            | None -> engine

        AuthorizationHost(engine)
