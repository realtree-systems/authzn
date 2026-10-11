/// Matching of request scopes against grant scopes, used by every Engine function.
module internal RealTree.Authzn.Permissions

open System.Threading
open System.Threading.Tasks
open RealTree.Authzn

/// The per-key rule shared by scopeMatchesAsync and scopeAdmitsAsync. A literal matches a requested
/// value by ordinal equality. A marker is never compared as text; it matches only when the resolver
/// admits the requested value, and matches nothing when there is no resolver.
let private matchValueAsync
    (principal: PrincipalId)
    (resolver: IScopeValueResolver option)
    (key: string)
    (grantValue: ScopeValue)
    (requestedValue: string)
    (cancellationToken: CancellationToken)
    : ValueTask<bool> =
    match grantValue with
    | ScopeValue.Literal literal -> ValueTask<bool>((literal = requestedValue))
    | ScopeValue.Marker marker ->
        match resolver with
        | Some r -> r.AdmitsAsync(principal, key, marker, requestedValue, cancellationToken)
        | None -> ValueTask<bool>(false)

/// Checks the grant's keys in key order and stops at the first that fails. <c>missing</c> is the
/// result for a grant key the scope lacks. Completes synchronously until the resolver returns a
/// ValueTask that has not completed, so a scope of literals, or a resolver that answers from
/// memory, allocates no Task.
let private allKeysAsync
    (principal: PrincipalId)
    (resolver: IScopeValueResolver option)
    (missing: bool)
    (grantScope: GrantScope)
    (scope: ScopeBag)
    (cancellationToken: CancellationToken)
    : ValueTask<bool> =
    let rec loop (keys: (string * ScopeValue) list) : ValueTask<bool> =
        match keys with
        | [] -> ValueTask<bool>(true)
        | (key, grantValue) :: rest ->
            match Map.tryFind key scope with
            | None -> if missing then loop rest else ValueTask<bool>(false)
            | Some requestedValue ->
                let pending = matchValueAsync principal resolver key grantValue requestedValue cancellationToken

                if pending.IsCompletedSuccessfully then
                    if pending.Result then loop rest else ValueTask<bool>(false)
                else
                    ValueTask<bool>(
                        task {
                            let! matched = pending

                            if matched then
                                return! (loop rest).AsTask()
                            else
                                return false
                        }
                    )

    loop (Map.toList grantScope)

/// True if the granted scope satisfies the requested scope. All keys in the grant scope must exist
/// in the request scope with matching values; request keys the grant scope lacks are ignored, so an
/// empty grant scope matches every request scope. Scope markers are resolved through the optional
/// IScopeValueResolver; a marker the resolver does not admit, or any marker when there is no
/// resolver, does not match.
let scopeMatchesAsync principal resolver (grantScope: GrantScope) (requestScope: ScopeBag) cancellationToken =
    allKeysAsync principal resolver false grantScope requestScope cancellationToken

/// True when every grant key that also appears in the partial scope matches its value there, by
/// the same per-key rule as scopeMatchesAsync. Grant keys absent from the partial scope are treated
/// as satisfiable without consulting the resolver, so true means only that no key of the partial
/// scope rules the grant out; the grant may still admit no resource, for example when its marker on
/// an absent key admits no value. Engine.mayAnyAsync and Engine.visibleScopeAsync use it to select
/// the grants that apply within a partial scope.
let scopeAdmitsAsync principal resolver (grantScope: GrantScope) (partialScope: ScopeBag) cancellationToken =
    allKeysAsync principal resolver true grantScope partialScope cancellationToken
