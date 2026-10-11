namespace Authzn

open System

/// Validation shared by ResourceName, ActionName and MarkerName.
module internal Names =

    /// True when part is non-empty and holds no whitespace and no '*'. '*' is reserved for the
    /// wildcard, which PermissionPattern.parse accepts only as a whole segment.
    let validPart (part: string) =
        not (String.IsNullOrEmpty part)
        && not (part |> Seq.exists (fun c -> Char.IsWhiteSpace c || c = '*'))

    /// The prefix of a marker in the text form of a scope value, as in "@principal".
    [<Literal>]
    let MarkerPrefix = "@"

    let check (kind: string) (valid: string -> bool) (value: string) =
        if isNull value || not (valid value) then
            invalidArg "value" $"Not a valid {kind}: '{value}'."

/// The resource of a permission: one or more ':'-separated parts, such as "documents" or
/// "project:task". Each part is non-empty and holds no whitespace and no '*'. Compared as exact,
/// case-sensitive text. Create with <see cref="ResourceName.create"/>.
type ResourceName =
    internal
    | ResourceName of string

    /// The name as text.
    member n.Value =
        let (ResourceName value) = n
        value

    override n.ToString() = n.Value

/// Functions for creating resource names.
[<RequireQualifiedAccess>]
module ResourceName =

    /// Validates text as a resource name. Throws ArgumentException when it is not one.
    let create (value: string) =
        Names.check "resource name" (fun v -> v.Split ':' |> Array.forall Names.validPart) value
        ResourceName value

    /// Returns the resource name, or None when the text is not a valid one.
    let tryCreate (value: string) =
        try
            Some(create value)
        with :? ArgumentException ->
            None

/// The action of a permission, such as "read": one part, non-empty, with no ':', no whitespace
/// and no '*'. Create with <see cref="ActionName.create"/>.
type ActionName =
    internal
    | ActionName of string

    /// The name as text.
    member n.Value =
        let (ActionName value) = n
        value

    override n.ToString() = n.Value

/// Functions for creating action names.
[<RequireQualifiedAccess>]
module ActionName =

    /// Validates text as an action name. Throws ArgumentException when it is not one.
    let create (value: string) =
        Names.check "action name" (fun v -> not (v.Contains ':') && Names.validPart v) value
        ActionName value

    /// Returns the action name, or None when the text is not a valid one.
    let tryCreate (value: string) =
        try
            Some(create value)
        with :? ArgumentException ->
            None

/// A permission a request asks for: a concrete resource and action, written "resource:action"
/// ("documents:read", "project:task:write"). It holds no wildcard, because ResourceName and
/// ActionName reject '*'. A grant covers a <see cref="PermissionPattern"/>, which may hold one.
type PermissionId =
    { /// The resource, e.g. "documents" or "project:task".
      Resource: ResourceName
      /// The action, e.g. "read".
      Action: ActionName }

    /// The "resource:action" text, which PermissionId.parse reads back to the same permission.
    override permission.ToString() =
        $"{permission.Resource.Value}:{permission.Action.Value}"

/// Functions for creating, parsing, and formatting permissions.
[<RequireQualifiedAccess>]
module PermissionId =

    /// Creates a permission from its resource and action. Throws ArgumentException when either is
    /// not a valid name.
    let create (resource: string) (action: string) =
        { Resource = ResourceName.create resource
          Action = ActionName.create action }

    /// Parses "resource:action": the last ':' separates the action from the resource. Throws
    /// ArgumentException for anything else, including a wildcard.
    let parse (text: string) =
        let idx = if isNull text then -1 else text.LastIndexOf ':'

        let parts =
            if idx <= 0 then
                None
            else
                Option.map2
                    (fun resource action -> { Resource = resource; Action = action })
                    (ResourceName.tryCreate (text.Substring(0, idx)))
                    (ActionName.tryCreate (text.Substring(idx + 1)))

        match parts with
        | Some permission -> permission
        | None -> invalidArg (nameof text) $"Not a permission (\"resource:action\", no wildcards): '{text}'."

    /// Parses "resource:action", or None.
    let tryParse (text: string) =
        try
            Some(parse text)
        with :? ArgumentException ->
            None

    /// The "resource:action" text, which parse reads back to the same permission.
    let format (permission: PermissionId) = permission.ToString()

/// One segment of a permission pattern: any resource (or action), or exactly one.
[<RequireQualifiedAccess>]
type Segment<'Name> =
    /// Any resource, or any action. Written "*".
    | Any
    /// This name only.
    | Exactly of 'Name

    /// "*" for any, otherwise the name's text.
    override segment.ToString() =
        match segment with
        | Segment.Any -> "*"
        | Segment.Exactly name -> name.ToString()

/// Functions over segments.
[<RequireQualifiedAccess>]
module Segment =

    /// True for <see cref="Segment.Any"/>.
    let isAny (segment: Segment<'Name>) =
        match segment with
        | Segment.Any -> true
        | Segment.Exactly _ -> false

/// The permissions a grant covers: a resource segment and an action segment, either of which may be
/// any. Written like a permission with "*" for any: "documents:read", "documents:*", "*:read", or
/// "*" for everything.
type PermissionPattern =
    { /// The resource the grant covers, or any.
      Resource: Segment<ResourceName>
      /// The action the grant covers, or any.
      Action: Segment<ActionName> }

    /// The text of the pattern, which PermissionPattern.parse reads back to the same pattern: "*"
    /// for everything, otherwise "resource:action" with "*" for any.
    override pattern.ToString() =
        match pattern.Resource, pattern.Action with
        | Segment.Any, Segment.Any -> "*"
        | resource, action -> $"{resource}:{action}"

/// Functions for creating, parsing, and formatting permission patterns.
[<RequireQualifiedAccess>]
module PermissionPattern =

    /// The text of a segment that stands for any resource or any action.
    [<Literal>]
    let Wildcard = "*"

    /// Every resource and every action: "*".
    let everything =
        { Resource = Segment.Any
          Action = Segment.Any }

    /// The pattern that covers exactly one permission.
    let exactly (permission: PermissionId) =
        { Resource = Segment.Exactly permission.Resource
          Action = Segment.Exactly permission.Action }

    /// True when the resource or the action is any, so the pattern covers more than one permission.
    let isWildcard (pattern: PermissionPattern) =
        Segment.isAny pattern.Resource || Segment.isAny pattern.Action

    /// True when <c>pattern</c> covers <c>permission</c>: each of its segments is any, or exactly
    /// the permission's resource or action. This is the rule every Engine function applies to a
    /// grant's pattern.
    let covers (permission: PermissionId) (pattern: PermissionPattern) =
        let segmentCovers (segment: Segment<'Name>) (name: 'Name) =
            match segment with
            | Segment.Any -> true
            | Segment.Exactly exact -> exact = name

        segmentCovers pattern.Resource permission.Resource
        && segmentCovers pattern.Action permission.Action

    let private segmentOf (create: string -> 'Name option) (text: string) =
        if text = Wildcard then Some Segment.Any else create text |> Option.map Segment.Exactly

    /// Parses "resource:action" with "*" for either segment, or "*" alone for everything. Throws
    /// ArgumentException for anything else.
    let parse (text: string) =
        if text = Wildcard then
            everything
        else
            let idx = if isNull text then -1 else text.LastIndexOf ':'

            let parts =
                if idx <= 0 then
                    None
                else
                    Option.map2
                        (fun resource action -> { Resource = resource; Action = action })
                        (segmentOf ResourceName.tryCreate (text.Substring(0, idx)))
                        (segmentOf ActionName.tryCreate (text.Substring(idx + 1)))

            match parts with
            | Some pattern -> pattern
            | None -> invalidArg (nameof text) $"Not a permission pattern (\"resource:action\", \"*\" for any): '{text}'."

    /// Parses a pattern, or None.
    let tryParse (text: string) =
        try
            Some(parse text)
        with :? ArgumentException ->
            None

    /// The text of the pattern, which parse reads back to the same pattern.
    let format (pattern: PermissionPattern) = pattern.ToString()

/// The identifier of a principal, such as a user, service or group. Authzn does not expand group
/// membership, so only the assignments made to this id apply to it.
type PrincipalId =
    | PrincipalId of string

    /// The id as text.
    member principal.Value =
        let (PrincipalId value) = principal
        value

    override principal.ToString() = principal.Value

/// Functions for creating and reading principal ids.
[<RequireQualifiedAccess>]
module PrincipalId =

    /// The id as text.
    let value (principal: PrincipalId) = principal.Value

    /// Creates a principal id from its text.
    let create (value: string) = PrincipalId value

/// The identifier of a role.
type RoleId =
    | RoleId of string

    /// The id as text.
    member role.Value =
        let (RoleId value) = role
        value

    override role.ToString() = role.Value

/// Functions for creating and reading role ids.
[<RequireQualifiedAccess>]
module RoleId =

    /// The id as text.
    let value (role: RoleId) = role.Value

    /// Creates a role id from its text.
    let create (value: string) = RoleId value

/// The reason Engine.evaluateAsync denied a request.
[<RequireQualifiedAccess>]
type DenyReason =
    /// The assignment store returned no assignments for the principal.
    | NoAssignments
    /// No grant in the roles of the principal's active assignments covers the permission.
    | NoMatchingPermission
    /// A grant covers the permission, but none of the grants that cover it matches the request
    /// scope.
    | ScopeMismatch
    /// The principal has assignments, but every one is revoked, expired or not yet valid.
    | AssignmentNotActive
    /// No active grant matches the request, and a grant that covers the permission and matches the
    /// request scope is revoked or expired by its GrantMetadata.
    | GrantNotActive
    /// No grant allows the request, and a grant that matches it on permission, metadata and scope
    /// has a condition that returned false or threw.
    | AttributeEvaluationFailed

/// The scope of a request: the concrete scope values of the resource being acted on (e.g. its
/// tenant and project).
type ScopeBag = Map<string, string>

/// The attributes of a request, by name, passed to a grant's ABAC condition.
type AttributeBag = Map<string, obj>

/// The name of a scope marker, such as "principal" or "hierarchy": non-empty, with no whitespace,
/// and not starting with "@" (the prefix of the text form). Create with <see cref="MarkerName.create"/>.
type MarkerName =
    internal
    | MarkerName of string

    /// The name as text.
    member n.Value =
        let (MarkerName value) = n
        value

    override n.ToString() = n.Value

/// Functions for creating marker names.
[<RequireQualifiedAccess>]
module MarkerName =

    /// Validates text as a marker name. Throws ArgumentException when it is not one.
    let create (value: string) =
        Names.check
            "marker name"
            (fun v ->
                v <> ""
                && not (v.StartsWith(Names.MarkerPrefix, StringComparison.Ordinal))
                && not (v |> Seq.exists Char.IsWhiteSpace))
            value

        MarkerName value

    /// Returns the marker name, or None when the text is not a valid one.
    let tryCreate (value: string) =
        try
            Some(create value)
        with :? ArgumentException ->
            None

/// One value in a grant's scope: a literal the requested value must equal exactly, or a marker the
/// scope resolver resolves for the principal at evaluation time. A marker is never compared as text.
[<RequireQualifiedAccess>]
type ScopeValue =
    /// The requested value must be exactly this text.
    | Literal of string
    /// IScopeValueResolver.AdmitsAsync determines which requested values this marker admits. With
    /// no resolver it admits none.
    | Marker of MarkerName

    /// The text form, which ScopeValue.parse reads back to the same value: "@name" for a marker,
    /// and a literal as itself, with a leading "@" doubled.
    override value.ToString() =
        match value with
        | ScopeValue.Marker name -> Names.MarkerPrefix + name.Value
        | ScopeValue.Literal text when text.StartsWith(Names.MarkerPrefix, StringComparison.Ordinal) ->
            Names.MarkerPrefix + text
        | ScopeValue.Literal text -> text

/// A grant's scope: the scope values a request must satisfy, by key. An empty map matches every
/// request scope.
type GrantScope = Map<string, ScopeValue>

/// The names of the predefined scope markers, as an <see cref="IScopeValueResolver"/> receives
/// them. Authzn defines only the names; a resolver gives them their meaning.
[<RequireQualifiedAccess>]
module ScopeMarkers =

    /// The principal's own value for the scope key.
    [<Literal>]
    let Principal = "principal"

    /// Membership in the principal's organizational hierarchy.
    [<Literal>]
    let Hierarchy = "hierarchy"

/// Functions for creating scope values and reading and writing their text form.
[<RequireQualifiedAccess>]
module ScopeValue =

    /// The prefix of a marker in the text form, "@".
    [<Literal>]
    let MarkerPrefix = Names.MarkerPrefix

    /// A marker by name. Throws ArgumentException when the name is not valid.
    let marker (name: string) = ScopeValue.Marker(MarkerName.create name)

    /// The <c>principal</c> marker: the principal's own value for the scope key.
    let principal = marker ScopeMarkers.Principal

    /// The <c>hierarchy</c> marker: membership in the principal's organizational hierarchy.
    let hierarchy = marker ScopeMarkers.Hierarchy

    /// Reads the text form, for configuration and storage: "@name" is the marker "name", "@@text" is
    /// the literal "@text", and anything else is a literal. Throws ArgumentException for "@" followed
    /// by an invalid marker name.
    let parse (text: string) =
        if isNull text then
            invalidArg (nameof text) "A scope value cannot be null."
        elif text.StartsWith(MarkerPrefix + MarkerPrefix, StringComparison.Ordinal) then
            ScopeValue.Literal(text.Substring MarkerPrefix.Length)
        elif text.StartsWith(MarkerPrefix, StringComparison.Ordinal) then
            marker (text.Substring MarkerPrefix.Length)
        else
            ScopeValue.Literal text

    /// Reads the text form (see <see cref="parse"/>), or None.
    let tryParse (text: string) =
        try
            Some(parse text)
        with :? ArgumentException ->
            None

    /// The text form, which parse reads back to the same value.
    let format (value: ScopeValue) = value.ToString()

    /// Reads a whole scope from its text form (see <see cref="parse"/>).
    let parseScope (scope: Map<string, string>) : GrantScope = scope |> Map.map (fun _ text -> parse text)

    /// Writes a whole scope in its text form (see <see cref="format"/>).
    let formatScope (scope: GrantScope) : Map<string, string> = scope |> Map.map (fun _ value -> format value)

/// Metadata on a permission grant, every field optional: who added it, why, who consented and
/// when, when it expires, and whether it is revoked. Authzn reads only ExpiresAt and RevokedAt (through
/// <see cref="GrantMetadata.isActiveAt"/>), and InMemoryGrantStore writes RevokedAt and RevokedBy;
/// the other fields are stored for the caller. Use <see cref="GrantMetadata.empty"/> when none is
/// needed.
type GrantMetadata =
    { /// Free-form text identifying what added the grant, such as
      /// "app:stellar/admin-tools@1.0.0#install-...", "user:alice@acme" or "bootstrap". For the
      /// caller's audit records and for IGrantPolicy implementations, which see it in
      /// GrantPolicyContext.Grant.
      Source: string option
      /// Human-readable justification for the grant, recorded when the grant is written.
      Reason: string option
      /// The principal who consented to the grant. May differ from <see cref="Source"/> when an
      /// installer acts on behalf of an admin.
      ConsentedBy: PrincipalId option
      /// When ConsentedBy consented.
      ConsentedAt: DateTimeOffset option
      /// When the grant expires. <see cref="GrantMetadata.isActiveAt"/> treats the grant as
      /// inactive once <c>now &gt;= ExpiresAt</c>. Assignment.NotAfter bounds a whole assignment;
      /// this bounds one grant.
      ExpiresAt: DateTimeOffset option
      /// When the grant was revoked. Some makes the grant inactive whatever the time;
      /// IGrantStore.ReinstateGrantAsync sets it back to None.
      RevokedAt: DateTimeOffset option
      /// The principal who revoked the grant.
      RevokedBy: PrincipalId option }

/// Functions for creating and inspecting grant metadata.
[<RequireQualifiedAccess>]
module GrantMetadata =

    /// Metadata with every field None, for a grant that never expires and is not revoked.
    let empty: GrantMetadata =
        { Source = Option.None
          Reason = Option.None
          ConsentedBy = Option.None
          ConsentedAt = Option.None
          ExpiresAt = Option.None
          RevokedAt = Option.None
          RevokedBy = Option.None }

    /// Returns true when RevokedAt is None and ExpiresAt is None or later than now. No Engine
    /// function allows a request through a grant for which this is false.
    let isActiveAt (now: DateTimeOffset) (metadata: GrantMetadata) =
        (match metadata.RevokedAt with
         | Some _ -> false
         | Option.None -> true)
        && (match metadata.ExpiresAt with
            | Some exp -> now < exp
            | Option.None -> true)

/// One grant in a role: the permissions it covers, the scope a request must match, an optional ABAC
/// condition, and its metadata.
type PermissionGrant =
    { /// The pattern of the permissions the grant covers.
      Permission: PermissionPattern
      /// The scope values a request's scope bag must match, by key. An empty map matches every
      /// request scope.
      Scope: GrantScope
      /// Optional ABAC condition on the request's attributes. The grant allows a request it
      /// matches on permission, metadata and scope only when the condition returns true; a
      /// condition that throws counts as false. A failing condition withholds only this grant, so
      /// another grant can still allow the request.
      Condition: (AttributeBag -> bool) option
      /// Audit and lifecycle metadata; its ExpiresAt and RevokedAt decide whether the grant is
      /// active. Use <see cref="GrantMetadata.empty"/> when none is needed.
      Metadata: GrantMetadata }

/// A named list of grants that assignments give to principals. A role has no time bounds or
/// revocation of its own; those are on Assignment and on each grant's GrantMetadata.
type Role =
    { /// The unique identifier for this role.
      Id: RoleId
      /// The human-readable name of the role.
      Name: string
      /// The role's grants. Engine.evaluateAsync allows a request when any of them allows it, and
      /// the order decides which grant an Allowed decision names when more than one does.
      Grants: PermissionGrant list }

/// The assignment of a role to a principal, with an optional validity window and a revoked flag.
/// Time bounds are set here (NotBefore, NotAfter) and on individual grants
/// (GrantMetadata.ExpiresAt); a role has none.
type Assignment =
    { /// The principal to whom the role is assigned.
      Principal: PrincipalId
      /// The role being assigned to the principal.
      Role: RoleId
      /// The assignment is inactive before this time. None means no lower bound.
      NotBefore: DateTimeOffset option
      /// The assignment is inactive from this time on. None means it does not expire.
      NotAfter: DateTimeOffset option
      /// Whether this assignment has been revoked. A revoked assignment is inactive whatever its
      /// window.
      Revoked: bool }

/// Functions for creating and managing assignments.
[<RequireQualifiedAccess>]
module Assignment =

    /// Creates a new assignment with no time constraints and not revoked.
    let create principal role =
        { Principal = principal
          Role = role
          NotBefore = Option.None
          NotAfter = Option.None
          Revoked = false }

    /// Returns true when the assignment is not revoked, NotBefore is None or not later than now,
    /// and NotAfter is None or later than now.
    let isActiveAt (now: DateTimeOffset) (assignment: Assignment) =
        not assignment.Revoked
        && (match assignment.NotBefore with
            | Some nb -> now >= nb
            | Option.None -> true)
        && (match assignment.NotAfter with
            | Some na -> now < na
            | Option.None -> true)

    /// Returns a copy of the assignment with Revoked set to true.
    let revoke (assignment: Assignment) = { assignment with Revoked = true }

/// The result of Engine.evaluateAsync: allowed, with the role and the pattern of the grant that
/// allowed the request, or denied, with the reason. <c>decision.IsAllowed</c> tests the case.
type AuthorizationDecision =
    /// Access is allowed: the role and the pattern of the first grant that allowed the request
    /// (which may be a wildcard pattern such as "*").
    | Allowed of Role: RoleId * Permission: PermissionPattern
    /// Access is denied.
    | Denied of Reason: DenyReason

/// One grant that admits a permission, and the role that carries it. <c>Engine.grantsAmongAsync</c>
/// returns one for every grant that admits a held permission, where evaluateAsync reports only the
/// first.
type GrantSource =
    { /// The role whose grant admits the permission.
      Role: RoleId
      /// The grant as the role holds it, so its Permission is the grant's pattern (such as "*:*"
      /// for an administrator) and not the permission that was asked about.
      Grant: PermissionGrant }

open System.Threading
open System.Threading.Tasks

/// Reads role definitions. The engine calls it from every request it evaluates, which may run on
/// several threads at once, so an implementation must be safe for concurrent calls.
type IRoleStore =
    /// Returns the role with this id, or None when there is none. The engine skips an assignment
    /// whose role is not found. <c>cancellationToken</c> is the token the caller passed to the
    /// Engine function.
    abstract GetRoleAsync: id: RoleId * cancellationToken: CancellationToken -> Task<Role option>

/// Reads role assignments. The engine calls it from every request it evaluates, which may run on
/// several threads at once, so an implementation must be safe for concurrent calls.
type IAssignmentStore =
    /// Returns the principal's assignments, which may include inactive ones because the engine
    /// filters them with Assignment.isActiveAt. The engine checks their roles in the returned
    /// order, so the order decides which role an Allowed decision names when more than one role
    /// allows the request. <c>cancellationToken</c> is the token the caller passed to the Engine
    /// function.
    abstract GetAssignmentsForPrincipalAsync:
        principal: PrincipalId * cancellationToken: CancellationToken -> Task<Assignment list>

/// Resolves scope markers (<see cref="ScopeValue.Marker"/>) for every Engine function. A marker is
/// never compared as text; it matches a requested value only when the resolver admits it. The
/// engine may call it once per grant and candidate, so an implementation that does not need I/O
/// should return a completed ValueTask.
type IScopeValueResolver =
    /// Returns true when <c>marker</c>, resolved for <c>principal</c> under <c>scopeKey</c>, admits
    /// <c>requestValue</c>. Return false for a marker this resolver does not recognise.
    /// <c>cancellationToken</c> is the token the caller passed to the Engine function.
    abstract AdmitsAsync:
        principal: PrincipalId *
        scopeKey: string *
        marker: MarkerName *
        requestValue: string *
        cancellationToken: CancellationToken ->
            ValueTask<bool>

/// The values one scope key may take: any value, or a finite set. IScopeValueEnumerator returns one
/// for a marker, and Engine.visibleScopeAsync builds the clauses of a ScopeConstraint from them.
type ScopeValueSet =
    /// Any value is admitted. An IScopeValueEnumerator returns it for a marker that admits every
    /// value. visibleScopeAsync drops such keys from their clause, so a ScopeConstraint it returns
    /// never contains AnyValue.
    | AnyValue
    /// Only the values in this set are admitted. An empty set admits none.
    | Values of Set<string>

/// Lists the values a scope marker admits for a principal, where
/// <see cref="IScopeValueResolver.AdmitsAsync"/> tests one value. Only
/// <c>Engine.visibleScopeAsync</c> uses it, and only when the engine's scope resolver object also
/// implements this interface; without it, visibleScopeAsync throws NotSupportedException for any
/// marker it has to materialise. Every other Engine function needs only
/// <see cref="IScopeValueResolver"/>.
type IScopeValueEnumerator =
    /// Returns Some with the values the marker admits for <c>principal</c> under <c>scopeKey</c>,
    /// or None when this resolver cannot list them, in which case visibleScopeAsync throws
    /// NotSupportedException. <c>cancellationToken</c> is the token the caller passed to
    /// visibleScopeAsync.
    abstract EnumerateScopeAsync:
        principal: PrincipalId * scopeKey: string * marker: MarkerName * cancellationToken: CancellationToken ->
            ValueTask<ScopeValueSet option>

/// The result of <c>Engine.visibleScopeAsync</c>: the resources a principal may act on for a
/// permission, in a form a caller can translate into a query filter. A resource is admitted by
/// <see cref="ScopeConstraint.Restricted"/> when it satisfies any of its clauses, and satisfies a
/// clause when its value for each key in the clause is in that key's ScopeValueSet. A key absent
/// from a clause does not constrain it.
type ScopeConstraint =
    /// The principal may act on every resource, because an active grant that covers the permission
    /// and admits the partial scope has no scope, or every key of its scope resolved to
    /// <see cref="ScopeValueSet.AnyValue"/>.
    | Everything
    /// The principal may act on no resource, because no active grant that covers the permission
    /// admits the partial scope.
    | Nothing
    /// One clause per active grant that covers the permission and admits the partial scope, each a
    /// map from scope key to the values it admits.
    | Restricted of Map<string, ScopeValueSet> list

/// Identifies a grant within a role by its permission pattern and scope, so IGrantStore can revoke
/// or reinstate one grant without rebuilding the role. Two grants have the same key exactly when
/// their patterns and scopes are equal; the condition and the metadata are not part of the key.
/// <see cref="Role.validate"/> rejects a role with two grants of equal pattern and scope, so a key
/// names at most one grant in a role. See <see cref="GrantKey.forGrant"/>.
type GrantKey =
    | GrantKey of string

    /// The key as text: lowercase hex.
    member key.Value =
        let (GrantKey value) = key
        value

    override key.ToString() = key.Value

/// Functions for constructing grant keys.
[<RequireQualifiedAccess>]
module GrantKey =

    /// The key as text.
    let value (key: GrantKey) = key.Value

    /// Creates a GrantKey from its text, such as a key read back from storage.
    let create (value: string) = GrantKey value

    /// The version tag that starts every encoding. Any change to the encoding must also change this
    /// tag, which changes every key.
    [<Literal>]
    let private EncodingVersion = "authzn-grant-key/2"

    /// Computes the key for a grant: the lowercase hex SHA-256 of a UTF-8 encoding of its
    /// permission pattern and scope, in which grants with different patterns or scopes never encode
    /// alike. Each piece of text is written as ';', its length in UTF-16 code units, ':' and the
    /// text, so no character in a name or a scope value can be read as a separator; each segment
    /// and scope value also carries a tag for its case. Throws ArgumentException when a scope key
    /// or literal value is null.
    let forGrant (grant: PermissionGrant) : GrantKey =
        let encoding = System.Text.StringBuilder(EncodingVersion)

        let text (s: string) =
            if isNull s then
                invalidArg (nameof grant) "A grant's scope keys and literal values cannot be null."

            encoding.Append(';').Append(s.Length).Append(':').Append(s) |> ignore

        let tag (t: char) = encoding.Append(';').Append(t) |> ignore

        let segment (value: 'Name -> string) (s: Segment<'Name>) =
            match s with
            | Segment.Any -> tag '*'
            | Segment.Exactly name ->
                tag '='
                text (value name)

        segment (fun (n: ResourceName) -> n.Value) grant.Permission.Resource
        segment (fun (n: ActionName) -> n.Value) grant.Permission.Action

        // A Map enumerates its keys in ordinal order, so the scope's order is canonical.
        for KeyValue(key, value) in grant.Scope do
            text key

            match value with
            | ScopeValue.Literal literal ->
                tag 'L'
                text literal
            | ScopeValue.Marker marker ->
                tag 'M'
                text marker.Value

        let bytes =
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(encoding.ToString()))

        bytes |> Array.map (fun b -> b.ToString("x2")) |> String.concat "" |> GrantKey

/// Functions for checking role definitions.
[<RequireQualifiedAccess>]
module Role =

    /// Throws ArgumentException when two grants in the role have the same
    /// <see cref="GrantKey.forGrant"/>, that is an equal permission pattern and scope. IGrantStore
    /// addresses a grant by its key, so it could not revoke one such grant without the other. Merge
    /// their conditions into one grant, or move one of them to another role. RoleBuilder.build and
    /// InMemoryRoleStore.Add call it; a custom IRoleStore should call it on the roles it loads.
    let validate (role: Role) =
        let duplicate =
            role.Grants
            |> List.groupBy GrantKey.forGrant
            |> List.tryPick (fun (_, grants) ->
                match grants with
                | first :: _ :: _ -> Some first
                | _ -> None)

        match duplicate with
        | Some grant ->
            let scope =
                ScopeValue.formatScope grant.Scope
                |> Seq.map (fun (KeyValue(key, value)) -> $"{key}={value}")
                |> String.concat ", "

            invalidArg
                (nameof role)
                $"Role '{RoleId.value role.Id}' has more than one grant of '{PermissionPattern.format grant.Permission}' with the scope {{{scope}}}. A role can hold only one grant per permission pattern and scope, because they share a GrantKey: merge their conditions into one grant, or move one of them to another role."
        | None -> ()

/// Revokes and reinstates individual grants without removing their role. The engine never calls
/// this interface; it reads <see cref="GrantMetadata.RevokedAt"/> from the grants that
/// IRoleStore.GetRoleAsync returns, so an implementation must write the change into the role
/// definitions that the engine's IRoleStore reads. InMemoryGrantStore rewrites the role in its
/// InMemoryRoleStore.
type IGrantStore =
    /// Sets RevokedAt to <c>at</c> and RevokedBy to <c>revokedBy</c> on the grants in the role
    /// whose <see cref="GrantKey.forGrant"/> equals <c>grantKey</c>. A grant that is already revoked
    /// keeps its RevokedAt and RevokedBy, so they record the first revocation. Does nothing when
    /// the role or key is not found.
    abstract RevokeGrantAsync:
        roleId: RoleId *
        grantKey: GrantKey *
        revokedBy: PrincipalId *
        at: DateTimeOffset *
        cancellationToken: CancellationToken ->
            Task

    /// Sets RevokedAt and RevokedBy back to None on the grants in the role whose key is
    /// <c>grantKey</c>, so they are active again unless <see cref="GrantMetadata.ExpiresAt"/> has
    /// passed. A grant that is not revoked is left as it is.
    abstract ReinstateGrantAsync: roleId: RoleId * grantKey: GrantKey * cancellationToken: CancellationToken -> Task

/// The proposed write that an <see cref="IGrantPolicy"/> evaluates: the principal adding the grant,
/// the role, the grant, and caller-defined properties.
type GrantPolicyContext =
    { /// The principal attempting to add the grant.
      Principal: PrincipalId
      /// The role the grant is being added to.
      Role: RoleId
      /// The proposed grant.
      Grant: PermissionGrant
      /// Caller-defined values for policies to read, such as an installation id or a tenant.
      /// Authzn defines no keys and does not read this map.
      Properties: Map<string, string> }

/// The decision an <see cref="IGrantPolicy"/> returns.
[<RequireQualifiedAccess>]
type GrantPolicyDecision =
    /// The grant may be added.
    | Allow
    /// The grant must not be added. <c>reason</c> is human-readable and <c>code</c> is a
    /// machine-readable identifier, both chosen by the policy.
    | Reject of Reason: string * Code: string
    /// The grant may be added only after explicit consent. The <c>tier</c> label is
    /// consumer-defined (e.g. "elevated", "restricted"); a caller with no consent step should treat
    /// RequireConsent as Reject.
    | RequireConsent of Reason: string * Tier: string

/// A check on a grant before it is added to a role. Nothing in Authzn calls it when adding a
/// grant: RoleBuilder, InMemoryRoleStore and AuthorizationHost.AddRole do not consult it. A caller
/// runs the policies through IGrantPolicyChain in its own grant-write code and enforces the
/// decision itself.
type IGrantPolicy =
    /// Returns the decision for the proposed grant. Implementations should be free of side effects,
    /// because GrantPolicyChain stops at the first decision that is not Allow, so a policy may not
    /// run, and a later policy can reject a grant this one allowed. They should be fast, because
    /// the chain awaits each policy in turn on the caller's grant-write path.
    abstract EvaluateAsync: context: GrantPolicyContext * cancellationToken: CancellationToken -> Task<GrantPolicyDecision>

/// Runs the registered <see cref="IGrantPolicy"/> implementations in registration order and returns
/// the first decision that is not Allow. Nothing in Authzn calls it; a caller runs it from its own
/// grant-write code.
type IGrantPolicyChain =
    /// Calls the registered policies in registration order until one returns <c>Reject</c> or
    /// <c>RequireConsent</c>, and returns that decision without calling the rest. Returns
    /// <c>Allow</c> when every policy allows or none is registered. Passes
    /// <c>cancellationToken</c> to each policy.
    abstract EvaluateAsync: context: GrantPolicyContext * cancellationToken: CancellationToken -> Task<GrantPolicyDecision>
