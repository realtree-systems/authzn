module Authzn.Tests.GrantMetadataTests

open System
open System.Threading
open Authzn
open Authzn.Tests.Helpers
open Xunit

[<Fact>]
let ``empty metadata has every field None`` () =
    let m = GrantMetadata.empty
    Assert.Equal(None, m.Source)
    Assert.Equal(None, m.Reason)
    Assert.Equal(None, m.ConsentedBy)
    Assert.Equal(None, m.ConsentedAt)
    Assert.Equal(None, m.ExpiresAt)
    Assert.Equal(None, m.RevokedAt)
    Assert.Equal(None, m.RevokedBy)

[<Fact>]
let ``isActiveAt true for empty metadata`` () =
    let now = DateTimeOffset.UtcNow
    Assert.True(GrantMetadata.isActiveAt now GrantMetadata.empty)

[<Fact>]
let ``isActiveAt false when RevokedAt is set`` () =
    let now = DateTimeOffset.UtcNow
    let m = { GrantMetadata.empty with RevokedAt = Some now }
    Assert.False(GrantMetadata.isActiveAt now m)

[<Fact>]
let ``isActiveAt false when ExpiresAt is in the past`` () =
    let now = DateTimeOffset.UtcNow
    let past = now.AddMinutes(-1.0)
    let m = { GrantMetadata.empty with ExpiresAt = Some past }
    Assert.False(GrantMetadata.isActiveAt now m)

[<Fact>]
let ``isActiveAt true when ExpiresAt is in the future`` () =
    let now = DateTimeOffset.UtcNow
    let future = now.AddMinutes(5.0)
    let m = { GrantMetadata.empty with ExpiresAt = Some future }
    Assert.True(GrantMetadata.isActiveAt now m)

let private grantWith (perm: string) (scope: GrantScope) (meta: GrantMetadata) : PermissionGrant =
    { Permission = PermissionPattern.parse perm
      Scope = scope
      Condition = None
      Metadata = meta }

let private roleWith (id: string) (grants: PermissionGrant list) : Role =
    { Id = RoleId id
      Name = id
      Grants = grants }

[<Fact>]
let ``revoked grant denies with GrantNotActive`` () =
    task {
        let now = DateTimeOffset.UtcNow
        let revoked =
            { GrantMetadata.empty with
                RevokedAt = Some now
                RevokedBy = Some testPrincipal }
        let role = roleWith "r" [ grantWith "documents:read" Map.empty revoked ]
        let engine = buildEngine [ role ] [ Assignment.create testPrincipal (RoleId "r") ]
        let req = AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")
        let! d = Engine.evaluateAsync engine CancellationToken.None req
        Assert.False(d.IsAllowed)
        Assert.Equal(Denied DenyReason.GrantNotActive, d)
    }

[<Fact>]
let ``expired grant denies with GrantNotActive`` () =
    task {
        let past = DateTimeOffset.UtcNow.AddMinutes(-1.0)
        let expired = { GrantMetadata.empty with ExpiresAt = Some past }
        let role = roleWith "r" [ grantWith "documents:read" Map.empty expired ]
        let engine = buildEngine [ role ] [ Assignment.create testPrincipal (RoleId "r") ]
        let req = AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")
        let! d = Engine.evaluateAsync engine CancellationToken.None req
        Assert.False(d.IsAllowed)
        Assert.Equal(Denied DenyReason.GrantNotActive, d)
    }

[<Fact>]
let ``active grant with metadata allows`` () =
    task {
        let future = DateTimeOffset.UtcNow.AddMinutes(5.0)
        let meta = { GrantMetadata.empty with ExpiresAt = Some future }
        let role = roleWith "r" [ grantWith "documents:read" Map.empty meta ]
        let engine = buildEngine [ role ] [ Assignment.create testPrincipal (RoleId "r") ]
        let req = AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")
        let! d = Engine.evaluateAsync engine CancellationToken.None req
        Assert.True(d.IsAllowed)
    }

[<Fact>]
let ``scope mismatch wins over a revoked grant whose scope also mismatches`` () =
    task {
        let now = DateTimeOffset.UtcNow
        let active = grantWith "documents:read" (Map.ofList [ "tenant", ScopeValue.Literal "acme" ]) GrantMetadata.empty
        let inactive =
            grantWith "documents:read" (Map.ofList [ "tenant", ScopeValue.Literal "other" ])
                { GrantMetadata.empty with RevokedAt = Some now }
        let role = roleWith "r" [ active; inactive ]
        let engine = buildEngine [ role ] [ Assignment.create testPrincipal (RoleId "r") ]
        let req =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")
            |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "third" ])
        let! d = Engine.evaluateAsync engine CancellationToken.None req
        Assert.False(d.IsAllowed)
        // GrantNotActive needs a revoked or expired grant whose scope matches the request, and the
        // revoked grant's tenant "other" does not match "third". Both grants cover documents:read
        // and neither scope matches, so the result is ScopeMismatch.
        Assert.Equal(Denied DenyReason.ScopeMismatch, d)
    }

[<Fact>]
let ``revoked grant with matching scope reports GrantNotActive when no active grant matches`` () =
    task {
        let now = DateTimeOffset.UtcNow
        let revoked =
            grantWith "documents:read" (Map.ofList [ "tenant", ScopeValue.Literal "acme" ])
                { GrantMetadata.empty with RevokedAt = Some now }
        let role = roleWith "r" [ revoked ]
        let engine = buildEngine [ role ] [ Assignment.create testPrincipal (RoleId "r") ]
        let req =
            AuthorizationRequest.create testPrincipal (PermissionId.create "documents" "read")
            |> AuthorizationRequest.withScope (Map.ofList [ "tenant", "acme" ])
        let! d = Engine.evaluateAsync engine CancellationToken.None req
        Assert.False(d.IsAllowed)
        Assert.Equal(Denied DenyReason.GrantNotActive, d)
    }
