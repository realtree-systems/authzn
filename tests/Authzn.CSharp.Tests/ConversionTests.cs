using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Authzn.CSharp;
using Microsoft.FSharp.Collections;
using Xunit;

namespace Authzn.CSharp.Tests;

/// <summary>
/// Tests the internal conversion layer (<c>Interop</c>, <c>ToFs</c>, <c>FromFs</c>) directly. The
/// C# compiler does not check a switch over an F# union for exhaustiveness, so each union the
/// facade maps has a guard test that fails when the F# core adds a case the facade does not map.
/// </summary>
public class ConversionTests
{
    [Fact]
    public void Option_reference_round_trips()
    {
        Assert.Equal("x", Interop.FromOption(Interop.ToOption<string>("x")));
        Assert.Null(Interop.FromOption(Interop.ToOption<string>(null)));
    }

    [Fact]
    public void Option_value_round_trips()
    {
        var dto = DateTimeOffset.UtcNow;
        Assert.Equal(dto, Interop.FromOptionStruct(Interop.ToOptionStruct<DateTimeOffset>(dto)));
        Assert.Null(Interop.FromOptionStruct(Interop.ToOptionStruct<DateTimeOffset>(null)));
    }

    [Fact]
    public void String_map_round_trips()
    {
        var source = new Dictionary<string, string> { ["a"] = "1", ["b"] = "2" };
        var result = Interop.FromStringMap(Interop.ToStringMap(source));

        Assert.Equal(2, result.Count);
        Assert.Equal("1", result["a"]);
        Assert.Equal("2", result["b"]);
    }

    [Fact]
    public void Null_dictionary_becomes_empty_map()
    {
        Assert.Empty(Interop.FromStringMap(Interop.ToStringMap((IReadOnlyDictionary<string, string>?)null)));
    }

    [Fact]
    public void Condition_bridge_passes_attributes_to_the_predicate()
    {
        var condition = Interop.ToCondition(attrs =>
            attrs.TryGetValue("amount", out var v) && v is int amount && amount < 10);

        Assert.True(condition.Invoke(Interop.ToObjectMap(new Dictionary<string, object> { ["amount"] = 5 })));
        Assert.False(condition.Invoke(Interop.ToObjectMap(new Dictionary<string, object> { ["amount"] = 50 })));
    }

    [Fact]
    public void Identifiers_round_trip()
    {
        Assert.Equal("alice", PrincipalRef.FromFs(new PrincipalRef("alice").ToFs()).Value);
        Assert.Equal("editor", RoleRef.FromFs(new RoleRef("editor").ToFs()).Value);
        Assert.Equal("abc123", GrantRef.FromFs(new GrantRef("abc123").ToFs()).Value);
    }

    [Fact]
    public void Permission_parses_and_round_trips()
    {
        var permission = new Permission("documents", "read");
        Assert.Equal(permission, Permission.FromFs(permission.ToFs()));
        Assert.Equal("documents:read", permission.ToString());

        Assert.True(Permission.TryParse("project:task:write", out var parsed));
        Assert.Equal(new Permission("project:task", "write"), parsed);

        Assert.False(Permission.TryParse("no-colon", out _));
    }

    [Fact]
    public void GrantMetadata_round_trips_through_the_core()
    {
        var at = DateTimeOffset.UtcNow;
        var metadata = new GrantMetadata
        {
            Source = "app:foo@1.0.0",
            Reason = "needed for install",
            ConsentedBy = new PrincipalRef("admin"),
            ConsentedAt = at,
            ExpiresAt = at.AddDays(30),
            RevokedAt = null,
            RevokedBy = null,
        };

        Assert.Equal(metadata, GrantMetadata.FromFs(metadata.ToFs()));
    }

    [Fact]
    public void Assignment_factories_round_trip()
    {
        var notBefore = DateTimeOffset.UtcNow;
        var notAfter = notBefore.AddDays(1);
        var assignment = Assignment.ForWindow("u", "r", notBefore, notAfter);

        Assert.Equal("u", assignment.Principal.Value);
        Assert.Equal("r", assignment.Role.Value);
        Assert.Equal(notBefore, assignment.NotBefore);
        Assert.Equal(notAfter, assignment.NotAfter);
        Assert.False(assignment.Revoked);
        Assert.True(assignment.AsRevoked().Revoked);

        var simple = Assignment.Create("u", "r");
        Assert.Null(simple.NotBefore);
        Assert.Null(simple.NotAfter);
    }

    [Fact]
    public void DenyReason_mapping_is_exhaustive_and_correct()
    {
        Assert.Equal(DenyReason.NoAssignments, Interop.FromDenyReason(global::Authzn.DenyReason.NoAssignments));
        Assert.Equal(DenyReason.NoMatchingPermission, Interop.FromDenyReason(global::Authzn.DenyReason.NoMatchingPermission));
        Assert.Equal(DenyReason.ScopeMismatch, Interop.FromDenyReason(global::Authzn.DenyReason.ScopeMismatch));
        Assert.Equal(DenyReason.AssignmentNotActive, Interop.FromDenyReason(global::Authzn.DenyReason.AssignmentNotActive));
        Assert.Equal(DenyReason.GrantNotActive, Interop.FromDenyReason(global::Authzn.DenyReason.GrantNotActive));
        Assert.Equal(DenyReason.AttributeEvaluationFailed, Interop.FromDenyReason(global::Authzn.DenyReason.AttributeEvaluationFailed));
    }

    [Fact]
    public void DenyReason_enum_matches_the_fsharp_union_case_set()
    {
        var tags = typeof(global::Authzn.DenyReason).GetNestedType("Tags");
        Assert.NotNull(tags);

        var fsharpCases = tags!
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Select(f => f.Name)
            .ToHashSet();

        var csharpCases = Enum.GetNames<DenyReason>().ToHashSet();

        Assert.Equal(fsharpCases, csharpCases);
    }

    [Fact]
    public void DenyReason_has_no_zero_member()
    {
        // A reason numbered 0 could not be told apart from default(DenyReason), an unset value.
        Assert.False(Enum.IsDefined(default(DenyReason)));
    }

    /// <summary>The cases of an F# union, from the Tags constants the F# compiler emits.</summary>
    private static HashSet<string> FSharpCases(Type union) =>
        union.GetNestedType("Tags")!
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Select(f => f.Name)
            .ToHashSet();

    /// <summary>The cases of a C# closed hierarchy: the sealed records nested in it that derive from it.</summary>
    private static HashSet<string> CSharpCases(Type closed) =>
        closed.GetNestedTypes()
            .Where(t => t.IsSealed && closed.IsAssignableFrom(t))
            .Select(t => t.Name)
            .ToHashSet();

    [Fact]
    public void AuthorizationDecision_matches_the_fsharp_union_case_set() =>
        Assert.Equal(FSharpCases(typeof(global::Authzn.AuthorizationDecision)), CSharpCases(typeof(AuthorizationDecision)));

    [Fact]
    public void ScopeConstraint_matches_the_fsharp_union_case_set() =>
        Assert.Equal(FSharpCases(typeof(global::Authzn.ScopeConstraint)), CSharpCases(typeof(ScopeConstraint)));

    [Fact]
    public void ScopeValueSet_matches_the_fsharp_union_case_set()
    {
        // The C# cases have C# names; this table is the correspondence ScopeValueSet.FromFs implements.
        var mapping = new Dictionary<string, string>
        {
            ["AnyValue"] = nameof(ScopeValueSet.Any),
            ["Values"] = nameof(ScopeValueSet.Of),
        };

        Assert.Equal(FSharpCases(typeof(global::Authzn.ScopeValueSet)), mapping.Keys.ToHashSet());
        Assert.Equal(CSharpCases(typeof(ScopeValueSet)), mapping.Values.ToHashSet());
    }

    [Fact]
    public void GrantPolicyDecision_matches_the_fsharp_union_case_set() =>
        Assert.Equal(FSharpCases(typeof(global::Authzn.GrantPolicyDecision)), CSharpCases(typeof(GrantPolicyDecision)));

    [Fact]
    public void AuthorizationDecision_maps_every_case()
    {
        var allowed = AuthorizationDecision.FromFs(global::Authzn.AuthorizationDecision.NewAllowed(
            global::Authzn.RoleId.NewRoleId("r"), global::Authzn.PermissionPatternModule.parse("a:b")));
        Assert.Equal(new AuthorizationDecision.Allowed("r", PermissionPattern.Parse("a:b")), allowed);
        Assert.True(allowed.IsAllowed);

        var denied = AuthorizationDecision.FromFs(
            global::Authzn.AuthorizationDecision.NewDenied(global::Authzn.DenyReason.ScopeMismatch));
        Assert.Equal(new AuthorizationDecision.Denied(DenyReason.ScopeMismatch), denied);
        Assert.False(denied.IsAllowed);
    }

    [Fact]
    public void ScopeValueSet_maps_every_case()
    {
        Assert.IsType<ScopeValueSet.Any>(ScopeValueSet.FromFs(global::Authzn.ScopeValueSet.AnyValue));

        var of = Assert.IsType<ScopeValueSet.Of>(
            ScopeValueSet.FromFs(global::Authzn.ScopeValueSet.NewValues(SetModule.OfSeq(new[] { "a" }))));
        Assert.Equal(new[] { "a" }, of.Values);
    }

    [Fact]
    public void ScopeConstraint_maps_every_case()
    {
        Assert.IsType<ScopeConstraint.Everything>(ScopeConstraint.FromFs(global::Authzn.ScopeConstraint.Everything));
        Assert.IsType<ScopeConstraint.Nothing>(ScopeConstraint.FromFs(global::Authzn.ScopeConstraint.Nothing));

        var clause = MapModule.OfSeq(new[] { Tuple.Create("tenant", global::Authzn.ScopeValueSet.AnyValue) });
        var restricted = Assert.IsType<ScopeConstraint.Restricted>(
            ScopeConstraint.FromFs(global::Authzn.ScopeConstraint.NewRestricted(ListModule.OfSeq(new[] { clause }))));
        Assert.IsType<ScopeValueSet.Any>(Assert.Single(restricted.Clauses)["tenant"]);
    }

    [Fact]
    public void PermissionSegment_matches_the_fsharp_union_case_set()
    {
        var mapping = new Dictionary<string, string>
        {
            ["Any"] = nameof(PermissionSegment.Any),
            ["Exactly"] = nameof(PermissionSegment.Exactly),
        };

        Assert.Equal(FSharpCases(typeof(global::Authzn.Segment<string>)), mapping.Keys.ToHashSet());
        Assert.Equal(CSharpCases(typeof(PermissionSegment)), mapping.Values.ToHashSet());
    }

    [Fact]
    public void ScopeValue_matches_the_fsharp_union_case_set() =>
        Assert.Equal(FSharpCases(typeof(global::Authzn.ScopeValue)), CSharpCases(typeof(ScopeValue)));

    [Fact]
    public void PermissionPattern_maps_every_segment_case()
    {
        var pattern = PermissionPattern.Parse("documents:*");
        Assert.Equal(new PermissionSegment.Exactly("documents"), pattern.Resource);
        Assert.IsType<PermissionSegment.Any>(pattern.Action);
        Assert.Equal("documents:*", pattern.ToString());
    }

    [Fact]
    public void ScopeValue_maps_every_case_and_round_trips_its_text()
    {
        var literal = new ScopeValue.Literal("@acme");
        var marker = new ScopeValue.Marker("custom");

        Assert.Equal(literal, ScopeValue.FromFs(literal.ToFs()));
        Assert.Equal(marker, ScopeValue.FromFs(marker.ToFs()));
        Assert.Equal(ScopeValue.Principal, ScopeValue.FromFs(global::Authzn.ScopeValueModule.principal));

        Assert.Equal("@@acme", literal.ToString());
        Assert.Equal(literal, ScopeValue.Parse(literal.ToString()));
        Assert.Equal(marker, ScopeValue.Parse("@custom"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("@principal")]
    [InlineData("my marker")]
    public void A_marker_name_is_validated(string name) =>
        Assert.Throws<ArgumentException>(() => new ScopeValue.Marker(name));

    [Fact]
    public void A_permission_is_concrete_and_validated()
    {
        Assert.Throws<ArgumentException>(() => new Permission("a", "b:c"));
        Assert.Throws<ArgumentException>(() => new Permission("*", "read"));
        Assert.Throws<ArgumentException>(() => Permission.Parse("invoices:*"));
        Assert.False(Permission.TryParse("*", out _));
        Assert.Equal(new Permission("project:task", "read"), Permission.Parse("project:task:read"));
    }

    [Fact]
    public void Wildcards_follow_the_fsharp_core()
    {
        var role = new RoleRef("r");
        Assert.True(new GrantSource(role, Grant("documents:*")).IsWildcard);
        Assert.True(new GrantSource(role, Grant("*")).IsWildcard);
        Assert.False(new GrantSource(role, Grant("documents:read")).IsWildcard);
    }

    private static PermissionGrant Grant(string permission) =>
        new(new global::Authzn.PermissionGrant(
            global::Authzn.PermissionPatternModule.parse(permission),
            MapModule.Empty<string, global::Authzn.ScopeValue>(),
            Interop.ToConditionOption(null),
            global::Authzn.GrantMetadataModule.empty));
}
