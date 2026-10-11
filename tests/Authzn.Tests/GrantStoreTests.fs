module RealTree.Authzn.Tests.GrantStoreTests

open System
open System.Threading
open RealTree.Authzn
open RealTree.Authzn.Tests.Helpers
open Xunit

let private makeRole () : Role =
    { Id = RoleId "r"
      Name = "Reader"
      Grants =
        [ { Permission = PermissionPattern.parse "documents:read"
            Scope = Map.ofList [ "tenant", ScopeValue.Literal "acme" ]
            Condition = None
            Metadata = GrantMetadata.empty } ] }

let private grantKey (role: Role) = GrantKey.forGrant role.Grants[0]

[<Fact>]
let ``forGrant leaves metadata out of the key`` () =
    let g1 =
        { Permission = PermissionPattern.parse "documents:read"
          Scope = Map.ofList [ "tenant", ScopeValue.Literal "acme"; "app", ScopeValue.Literal "billing" ]
          Condition = None
          Metadata = GrantMetadata.empty }
    let g2 =
        { g1 with
            Metadata =
                { GrantMetadata.empty with
                    Source = Some "x"
                    RevokedAt = Some DateTimeOffset.UtcNow } }
    Assert.Equal(GrantKey.forGrant g1, GrantKey.forGrant g2)

[<Fact>]
let ``forGrant differs when permission differs`` () =
    let g1 =
        { Permission = PermissionPattern.parse "documents:read"
          Scope = Map.empty
          Condition = None
          Metadata = GrantMetadata.empty }
    let g2 = { g1 with Permission = PermissionPattern.parse "documents:write" }
    Assert.NotEqual<GrantKey>(GrantKey.forGrant g1, GrantKey.forGrant g2)

[<Fact>]
let ``forGrant differs when scope differs`` () =
    let g1 =
        { Permission = PermissionPattern.parse "documents:read"
          Scope = Map.ofList [ "tenant", ScopeValue.Literal "acme" ]
          Condition = None
          Metadata = GrantMetadata.empty }
    let g2 = { g1 with Scope = Map.ofList [ "tenant", ScopeValue.Literal "other" ] }
    Assert.NotEqual<GrantKey>(GrantKey.forGrant g1, GrantKey.forGrant g2)

let private keyOf (permission: string) (scope: (string * ScopeValue) list) =
    GrantKey.forGrant
        { Permission = PermissionPattern.parse permission
          Scope = Map.ofList scope
          Condition = None
          Metadata = GrantMetadata.empty }

[<Fact>]
let ``forGrant tells apart a value holding separators from two keys`` () =
    // Joined as "k=v" pairs separated by ';', both scopes would read "a=1;b=2". The grants admit
    // different requests, and with a shared key RevokeGrantAsync on one would revoke both.
    Assert.NotEqual<GrantKey>(
        keyOf "docs:read" [ "a", ScopeValue.Literal "1;b=2" ],
        keyOf "docs:read" [ "a", ScopeValue.Literal "1"; "b", ScopeValue.Literal "2" ]
    )

[<Fact>]
let ``forGrant tells apart an action holding separators from an action and a scope`` () =
    // An action may hold ';'. Without the length prefix forGrant writes before each piece of text,
    // both grants would encode as "...;=;docs;=;a;k;L;v", because the action's ';' characters would
    // read as the scope's separators.
    Assert.NotEqual<GrantKey>(keyOf "docs:a" [ "k", ScopeValue.Literal "v" ], keyOf "docs:a;k;L;v" [])

[<Fact>]
let ``forGrant tells apart a literal from a marker of the same text`` () =
    Assert.NotEqual<GrantKey>(
        keyOf "docs:read" [ "owner", ScopeValue.Literal "principal" ],
        keyOf "docs:read" [ "owner", ScopeValue.principal ]
    )

[<Fact>]
let ``forGrant tells apart a wildcard from a name`` () =
    Assert.NotEqual<GrantKey>(keyOf "docs:*" [], keyOf "docs:read" [])

[<Fact>]
let ``forGrant encoding is pinned`` () =
    // Consumers store grant keys for later RevokeGrantAsync calls, so an encoding change must also
    // replace the version tag "authzn-grant-key/2". Any change to this grant's encoding fails here.
    Assert.Equal(
        GrantKey.create "32333d2afcc9b58b6b55e0fd5025b5781dbd4bd78fd84b20302d79be6838eaba",
        keyOf "documents:read" [ "tenant", ScopeValue.Literal "acme" ]
    )

[<Fact>]
let ``revoke stamps RevokedAt + RevokedBy on the matching grant`` () =
    task {
        let role = makeRole ()
        let roleStore = InMemoryRoleStore()
        roleStore.Add(role)
        let grantStore = InMemoryGrantStore(roleStore) :> IGrantStore
        let key = grantKey role
        let at = DateTimeOffset.UtcNow
        do! grantStore.RevokeGrantAsync(role.Id, key, testPrincipal, at, CancellationToken.None)
        let! refreshed = (roleStore :> IRoleStore).GetRoleAsync(role.Id, CancellationToken.None)
        let updated = refreshed.Value.Grants[0]
        Assert.Equal(Some at, updated.Metadata.RevokedAt)
        Assert.Equal(Some testPrincipal, updated.Metadata.RevokedBy)
    }

[<Fact>]
let ``revoking an already-revoked grant keeps the first RevokedAt and RevokedBy`` () =
    task {
        let role = makeRole ()
        let roleStore = InMemoryRoleStore()
        roleStore.Add(role)
        let grantStore = InMemoryGrantStore(roleStore) :> IGrantStore
        let key = grantKey role
        let first = DateTimeOffset.UtcNow
        do! grantStore.RevokeGrantAsync(role.Id, key, testPrincipal, first, CancellationToken.None)
        do! grantStore.RevokeGrantAsync(role.Id, key, PrincipalId "someone-else", first.AddHours 1.0, CancellationToken.None)
        let! refreshed = (roleStore :> IRoleStore).GetRoleAsync(role.Id, CancellationToken.None)
        let updated = refreshed.Value.Grants[0]
        Assert.Equal(Some first, updated.Metadata.RevokedAt)
        Assert.Equal(Some testPrincipal, updated.Metadata.RevokedBy)
    }

[<Fact>]
let ``reinstate clears RevokedAt + RevokedBy`` () =
    task {
        let role = makeRole ()
        let roleStore = InMemoryRoleStore()
        roleStore.Add(role)
        let grantStore = InMemoryGrantStore(roleStore) :> IGrantStore
        let key = grantKey role
        do! grantStore.RevokeGrantAsync(role.Id, key, testPrincipal, DateTimeOffset.UtcNow, CancellationToken.None)
        do! grantStore.ReinstateGrantAsync(role.Id, key, CancellationToken.None)
        let! refreshed = (roleStore :> IRoleStore).GetRoleAsync(role.Id, CancellationToken.None)
        let updated = refreshed.Value.Grants[0]
        Assert.Equal(None, updated.Metadata.RevokedAt)
        Assert.Equal(None, updated.Metadata.RevokedBy)
    }

[<Fact>]
let ``revoke on unknown role is a no-op`` () =
    task {
        let roleStore = InMemoryRoleStore()
        let grantStore = InMemoryGrantStore(roleStore) :> IGrantStore
        let key = GrantKey.create "deadbeef"
        do! grantStore.RevokeGrantAsync(RoleId "missing", key, testPrincipal, DateTimeOffset.UtcNow, CancellationToken.None)
        let! r = (roleStore :> IRoleStore).GetRoleAsync(RoleId "missing", CancellationToken.None)
        Assert.Equal(None, r)
    }

[<Fact>]
let ``revoke on unknown grant inside a known role is a no-op`` () =
    task {
        let role = makeRole ()
        let roleStore = InMemoryRoleStore()
        roleStore.Add(role)
        let grantStore = InMemoryGrantStore(roleStore) :> IGrantStore
        do! grantStore.RevokeGrantAsync(role.Id, GrantKey.create "deadbeef", testPrincipal, DateTimeOffset.UtcNow, CancellationToken.None)
        let! refreshed = (roleStore :> IRoleStore).GetRoleAsync(role.Id, CancellationToken.None)
        Assert.Equal(None, refreshed.Value.Grants[0].Metadata.RevokedAt)
    }

[<Fact>]
let ``revoke then evaluate denies with GrantNotActive`` () =
    task {
        let role = makeRole ()
        let roleStore = InMemoryRoleStore()
        roleStore.Add(role)
        let grantStore = InMemoryGrantStore(roleStore) :> IGrantStore
        let assignmentStore = InMemoryAssignmentStore()
        assignmentStore.Add(Assignment.create testPrincipal role.Id)
        do! grantStore.RevokeGrantAsync(role.Id, grantKey role, testPrincipal, DateTimeOffset.UtcNow, CancellationToken.None)
        let engine = AuthorizationEngine.create roleStore assignmentStore
        let req =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")
            |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "acme" ])
        let! d = Engine.evaluateAsync engine CancellationToken.None req
        Assert.False(d.IsAllowed)
        Assert.Equal(Denied DenyReason.GrantNotActive, d)
    }

[<Fact>]
let ``AuthorizationHost.RevokeGrant records the engine's time and ReinstateGrant clears it`` () =
    task {
        let now = DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero)

        let role =
            RoleBuilder.create "ops" "Ops"
            |> RoleBuilder.grantEverywhere "docs:read"
            |> RoleBuilder.grantEverywhere "docs:write"
            |> RoleBuilder.build

        let roleStore = InMemoryRoleStore()
        roleStore.Add role

        let host =
            AuthorizationConfig.defaultConfig
            |> AuthorizationConfig.useRoleStore roleStore
            |> AuthorizationConfig.assign "user-1" "ops"
            |> AuthorizationConfig.useTimeProvider (FixedTimeProvider now)
            |> AuthorizationHost.build

        let decide permission =
            AuthorizationRequest.create testPrincipal (PermissionId.parse permission)
            |> Engine.evaluateAsync host.Engine CancellationToken.None

        let readKey = GrantKey.forGrant role.Grants.Head
        host.RevokeGrant(role.Id, readKey, PrincipalId "admin")

        let! stored = (roleStore :> IRoleStore).GetRoleAsync(role.Id, CancellationToken.None)
        let read, write = stored.Value.Grants[0], stored.Value.Grants[1]
        Assert.Equal(Some now, read.Metadata.RevokedAt)
        Assert.Equal(Some(PrincipalId "admin"), read.Metadata.RevokedBy)
        Assert.Equal(None, write.Metadata.RevokedAt)

        let! readRevoked = decide "docs:read"
        let! writeKept = decide "docs:write"
        Assert.Equal(Denied DenyReason.GrantNotActive, readRevoked)
        Assert.True(writeKept.IsAllowed)

        host.ReinstateGrant(role.Id, readKey)

        let! readReinstated = decide "docs:read"
        Assert.True(readReinstated.IsAllowed)
    }

[<Fact>]
let ``AuthorizationHost.RevokeGrant and ReinstateGrant throw with a custom role store`` () =
    let customRoleStore =
        { new IRoleStore with
            member _.GetRoleAsync(_, _) = System.Threading.Tasks.Task.FromResult(None) }

    let host =
        AuthorizationConfig.defaultConfig
        |> AuthorizationConfig.useRoleStore customRoleStore
        |> AuthorizationHost.build

    let key = GrantKey.create "deadbeef"

    Assert.Throws<InvalidOperationException>(fun () -> host.RevokeGrant(RoleId "r", key, PrincipalId "admin"))
    |> ignore

    Assert.Throws<InvalidOperationException>(fun () -> host.ReinstateGrant(RoleId "r", key))
    |> ignore
