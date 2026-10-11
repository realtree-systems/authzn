module Authzn.Tests.TypeTests

open System
open Xunit
open Authzn

[<Fact>]
let ``PermissionId.parse parses resource:action format`` () =
    let p = PermissionId.parse "documents:read"
    Assert.Equal("documents", p.Resource.Value)
    Assert.Equal("read", p.Action.Value)

[<Fact>]
let ``PermissionId.parse handles hierarchical resources`` () =
    let p = PermissionId.parse "project:task:read"
    Assert.Equal("project:task", p.Resource.Value)
    Assert.Equal("read", p.Action.Value)

[<Theory>]
[<InlineData("")>]
[<InlineData("nocolon")>]
[<InlineData(":read")>]
[<InlineData("documents:")>]
[<InlineData("*")>]
[<InlineData("*:*")>]
[<InlineData("invoices:*")>]
[<InlineData("*:read")>]
[<InlineData("documents :read")>]
[<InlineData("project::read")>]
[<InlineData("docs*:read")>]
let ``PermissionId.parse rejects text that is not a concrete permission`` (text: string) =
    Assert.Throws<ArgumentException>(fun () -> PermissionId.parse text |> ignore) |> ignore
    Assert.True((PermissionId.tryParse text).IsNone)

[<Fact>]
let ``PermissionId.parse rejects null`` () =
    Assert.Throws<ArgumentException>(fun () -> PermissionId.parse null |> ignore) |> ignore

[<Fact>]
let ``PermissionId.create rejects an action holding a colon, which would not round-trip`` () =
    Assert.Throws<ArgumentException>(fun () -> PermissionId.create "a" "b:c" |> ignore) |> ignore

[<Fact>]
let ``PermissionId.tryParse returns Some for valid`` () =
    let result = PermissionId.tryParse "docs:read"
    Assert.True(result.IsSome)
    Assert.Equal("docs", result.Value.Resource.Value)

[<Theory>]
[<InlineData("documents:write")>]
[<InlineData("project:task:read")>]
let ``PermissionId text round-trips`` (text: string) =
    let p = PermissionId.parse text
    Assert.Equal(text, PermissionId.format p)
    Assert.Equal(p, PermissionId.parse (PermissionId.format p))

[<Fact>]
let ``PermissionPattern.parse reads star alone and star:star as everything`` () =
    Assert.Equal(PermissionPattern.everything, PermissionPattern.parse "*")
    Assert.Equal(PermissionPattern.everything, PermissionPattern.parse "*:*")
    Assert.Equal("*", PermissionPattern.format PermissionPattern.everything)

[<Fact>]
let ``PermissionPattern.parse reads a wildcard in either segment`` () =
    Assert.Equal(
        { Resource = Segment.Exactly(ResourceName.create "documents"); Action = Segment.Any },
        PermissionPattern.parse "documents:*"
    )

    Assert.Equal(
        { Resource = Segment.Any; Action = Segment.Exactly(ActionName.create "read") },
        PermissionPattern.parse "*:read"
    )

[<Theory>]
[<InlineData("project:*:read")>]
[<InlineData("docs*:read")>]
[<InlineData("documents:re*d")>]
[<InlineData("documents :read")>]
[<InlineData("nocolon")>]
[<InlineData("")>]
let ``PermissionPattern.parse rejects text that is not a pattern`` (text: string) =
    Assert.Throws<ArgumentException>(fun () -> PermissionPattern.parse text |> ignore) |> ignore
    Assert.True((PermissionPattern.tryParse text).IsNone)

[<Theory>]
[<InlineData("*")>]
[<InlineData("documents:*")>]
[<InlineData("*:read")>]
[<InlineData("documents:read")>]
[<InlineData("project:task:*")>]
let ``PermissionPattern text round-trips`` (text: string) =
    let p = PermissionPattern.parse text
    Assert.Equal(text, PermissionPattern.format p)
    Assert.Equal(p, PermissionPattern.parse (PermissionPattern.format p))

[<Fact>]
let ``isWildcard is true when the resource or the action is any`` () =
    Assert.True(PermissionPattern.isWildcard (PermissionPattern.parse "*"))
    Assert.True(PermissionPattern.isWildcard (PermissionPattern.parse "documents:*"))
    Assert.True(PermissionPattern.isWildcard (PermissionPattern.parse "*:read"))
    Assert.False(PermissionPattern.isWildcard (PermissionPattern.parse "documents:read"))

[<Fact>]
let ``covers matches each segment exactly or as any`` () =
    let covers pattern permission =
        PermissionPattern.covers (PermissionId.parse permission) (PermissionPattern.parse pattern)

    Assert.True(covers "*" "documents:read")
    Assert.True(covers "documents:*" "documents:read")
    Assert.True(covers "*:read" "documents:read")
    Assert.True(covers "project:task:*" "project:task:read")
    Assert.False(covers "documents:*" "invoices:read")
    Assert.False(covers "*:read" "documents:write")
    Assert.False(covers "project:*" "project:task:read")

[<Fact>]
let ``exactly covers one permission and nothing else`` () =
    let read = PermissionId.parse "documents:read"
    Assert.Equal(PermissionPattern.parse "documents:read", PermissionPattern.exactly read)
    Assert.True(PermissionPattern.covers read (PermissionPattern.exactly read))
    Assert.False(PermissionPattern.covers (PermissionId.parse "documents:write") (PermissionPattern.exactly read))

[<Theory>]
[<InlineData("acme")>]
[<InlineData("")>]
[<InlineData("@acme")>]
[<InlineData("@@acme")>]
[<InlineData("a@b")>]
let ``a literal reads back as the same literal, whatever its text`` (text: string) =
    let value = ScopeValue.Literal text
    Assert.Equal(value, ScopeValue.parse (ScopeValue.format value))

[<Fact>]
let ``a literal starting with the prefix is written with the prefix doubled`` () =
    Assert.Equal("@@acme", ScopeValue.format (ScopeValue.Literal "@acme"))
    Assert.Equal(ScopeValue.Literal "@acme", ScopeValue.parse "@@acme")

[<Fact>]
let ``the text form reads markers and literals`` () =
    Assert.Equal(ScopeValue.principal, ScopeValue.parse "@principal")
    Assert.Equal(ScopeValue.marker "custom", ScopeValue.parse "@custom")
    Assert.Equal(ScopeValue.Literal "acme", ScopeValue.parse "acme")
    Assert.Equal("@principal", ScopeValue.format ScopeValue.principal)

[<Theory>]
[<InlineData("")>]
[<InlineData("@principal")>]
[<InlineData("my marker")>]
let ``a marker name is non-empty, has no whitespace and does not start with the prefix`` (name: string) =
    Assert.Throws<ArgumentException>(fun () -> MarkerName.create name |> ignore) |> ignore

[<Fact>]
let ``parseScope and formatScope are inverses`` () =
    let scope: GrantScope =
        Map.ofList [ "tenant", ScopeValue.Literal "@acme"; "owner", ScopeValue.principal; "org", ScopeValue.Literal "o1" ]

    Assert.Equal<GrantScope>(scope, ScopeValue.parseScope (ScopeValue.formatScope scope))

[<Fact>]
let ``PrincipalId value extracts string`` () =
    let pid = PrincipalId "alice"
    Assert.Equal("alice", PrincipalId.value pid)

[<Fact>]
let ``RoleId value extracts string`` () =
    let rid = RoleId "admin"
    Assert.Equal("admin", RoleId.value rid)

[<Fact>]
let ``PrincipalId equality`` () =
    Assert.Equal(PrincipalId "a", PrincipalId "a")
    Assert.NotEqual(PrincipalId "a", PrincipalId "b")

[<Fact>]
let ``RoleId equality`` () =
    Assert.Equal(RoleId "x", RoleId "x")
    Assert.NotEqual(RoleId "x", RoleId "y")

[<Fact>]
let ``Assignment.isActiveAt returns true for simple active assignment`` () =
    let a = Assignment.create (PrincipalId "u") (RoleId "r")
    Assert.True(Assignment.isActiveAt DateTimeOffset.UtcNow a)

[<Fact>]
let ``Assignment.isActiveAt returns false for revoked assignment`` () =
    let a = Assignment.create (PrincipalId "u") (RoleId "r") |> Assignment.revoke
    Assert.False(Assignment.isActiveAt DateTimeOffset.UtcNow a)

[<Fact>]
let ``Assignment.isActiveAt respects NotBefore`` () =
    let future = DateTimeOffset.UtcNow.AddHours(1.0)

    let a =
        { Assignment.create (PrincipalId "u") (RoleId "r") with
            NotBefore = Some future }

    Assert.False(Assignment.isActiveAt DateTimeOffset.UtcNow a)
    Assert.True(Assignment.isActiveAt (future.AddMinutes(1.0)) a)

[<Fact>]
let ``Assignment.isActiveAt respects NotAfter`` () =
    let past = DateTimeOffset.UtcNow.AddHours(-1.0)

    let a =
        { Assignment.create (PrincipalId "u") (RoleId "r") with
            NotAfter = Some past }

    Assert.False(Assignment.isActiveAt DateTimeOffset.UtcNow a)
    Assert.True(Assignment.isActiveAt (past.AddMinutes(-1.0)) a)

[<Fact>]
let ``an allowed decision carries the role and permission that matched`` () =
    let d = Allowed(RoleId "r", PermissionPattern.parse "a:b")
    Assert.True(d.IsAllowed)

    match d with
    | Allowed(role, permission) ->
        Assert.Equal(RoleId "r", role)
        Assert.Equal(PermissionPattern.parse "a:b", permission)
    | Denied reason -> failwith $"expected Allowed, got Denied {reason}"

[<Fact>]
let ``a denied decision carries the reason and nothing else`` () =
    let d = Denied DenyReason.NoAssignments
    Assert.False(d.IsAllowed)

    match d with
    | Denied reason -> Assert.Equal(DenyReason.NoAssignments, reason)
    | Allowed(role, permission) -> failwith $"expected Denied, got Allowed {role} {permission}"

[<Fact>]
let ``identifiers expose their text as Value and ToString`` () =
    Assert.Equal("alice", (PrincipalId "alice").Value)
    Assert.Equal("alice", (PrincipalId "alice").ToString())
    Assert.Equal("editor", (RoleId "editor").Value)
    Assert.Equal("editor", (RoleId "editor").ToString())
    Assert.Equal("abc", (GrantKey "abc").Value)
    Assert.Equal("abc", (GrantKey "abc").ToString())

[<Theory>]
[<InlineData("documents:read")>]
[<InlineData("project:task:write")>]
let ``PermissionId.ToString is the text parse reads`` (text: string) =
    Assert.Equal(text, (PermissionId.parse text).ToString())

[<Theory>]
[<InlineData("*")>]
[<InlineData("documents:*")>]
[<InlineData("*:read")>]
[<InlineData("documents:read")>]
let ``PermissionPattern.ToString is the text parse reads`` (text: string) =
    Assert.Equal(text, (PermissionPattern.parse text).ToString())

[<Theory>]
[<InlineData("acme")>]
[<InlineData("@principal")>]
[<InlineData("@@literal")>]
let ``ScopeValue.ToString is the text parse reads`` (text: string) =
    Assert.Equal(text, (ScopeValue.parse text).ToString())

[<Fact>]
let ``tryParse and tryCreate return None for invalid text`` () =
    Assert.Equal(None, ScopeValue.tryParse "@")
    Assert.Equal(Some(ScopeValue.Literal "acme"), ScopeValue.tryParse "acme")
    Assert.Equal(None, MarkerName.tryCreate "@principal")
    Assert.True((MarkerName.tryCreate "principal").IsSome)
