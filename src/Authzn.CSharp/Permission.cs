using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.FSharp.Core;
using Fs = RealTree.Authzn;

namespace RealTree.Authzn.CSharp;

/// <summary>
/// A permission a request asks for: a concrete resource and action, written <c>resource:action</c>
/// (e.g. <c>documents:read</c>, <c>project:task:write</c>). The rightmost colon separates the
/// action; everything before it is the resource. A permission never holds a wildcard; wildcards
/// belong to a <see cref="PermissionPattern"/>, which describes what a grant covers.
/// </summary>
/// <remarks>
/// Each colon-separated part is non-empty and holds no whitespace and no <c>*</c>, and the action holds no
/// colon, so <see cref="Parse"/> reads <see cref="ToString"/> back to the same permission. Names are compared
/// as exact, case-sensitive text.
/// </remarks>
public sealed record Permission
{
    private readonly Fs.PermissionId _fs;

    private Permission(Fs.PermissionId fs) => _fs = fs;

    /// <summary>
    /// Creates a permission. Throws <see cref="ArgumentException"/> when <paramref name="resource"/> or
    /// <paramref name="action"/> is not a valid name.
    /// </summary>
    public Permission(string resource, string action)
        : this(Fs.PermissionIdModule.create(resource, action))
    {
    }

    /// <summary>The resource, e.g. <c>documents</c> or <c>project:task</c>.</summary>
    public string Resource => _fs.Resource.Value;

    /// <summary>The action, e.g. <c>read</c>.</summary>
    public string Action => _fs.Action.Value;

    /// <summary>
    /// Parses a <c>resource:action</c> string. Throws <see cref="ArgumentException"/> if it is not one,
    /// including when it holds a wildcard.
    /// </summary>
    public static Permission Parse(string value) => new(Fs.PermissionIdModule.parse(value));

    /// <summary>
    /// Tries to parse a <c>resource:action</c> string, returning <see langword="false"/> on failure.
    /// </summary>
    public static bool TryParse(string? value, [NotNullWhen(true)] out Permission? permission)
    {
        var parsed = Fs.PermissionIdModule.tryParse(value);
        permission = FSharpOption<Fs.PermissionId>.get_IsSome(parsed) ? new Permission(parsed.Value) : null;
        return permission is not null;
    }

    /// <summary>Returns the <c>resource:action</c> string, which <see cref="Parse"/> reads back.</summary>
    public override string ToString() => _fs.ToString();

    /// <summary>
    /// Parses a string into a <see cref="Permission"/>. Explicit because <see cref="Parse"/> can throw.
    /// </summary>
    public static explicit operator Permission(string value) => Parse(value);

    /// <summary>
    /// Returns whether the pattern <paramref name="grant"/> covers <paramref name="required"/>, by
    /// the same rule the engine applies. Scope, conditions and grant metadata are not considered.
    /// </summary>
    /// <remarks>
    /// Use it to test patterns without a store, for example to list which known permission names a
    /// wildcard covers. To decide for a principal, use <see cref="Authorizer"/>, which also checks
    /// assignments, scope, conditions and grant metadata.
    /// </remarks>
    public static bool Matches(Permission required, PermissionPattern grant)
    {
        ArgumentNullException.ThrowIfNull(required);
        ArgumentNullException.ThrowIfNull(grant);
        return grant.Covers(required);
    }

    /// <summary>
    /// The same test over two strings: <paramref name="required"/> as a <see cref="Permission"/>,
    /// <paramref name="grant"/> as a <see cref="PermissionPattern"/>. Returns false, without
    /// throwing, when either does not parse, which includes a <paramref name="required"/> that
    /// holds a wildcard.
    /// </summary>
    public static bool Matches(string required, string grant) =>
        TryParse(required, out var wanted) && PermissionPattern.TryParse(grant, out var granted) && granted.Covers(wanted);

    internal Fs.PermissionId ToFs() => _fs;

    internal static Permission FromFs(Fs.PermissionId permission) => new(permission);
}

/// <summary>
/// The permissions a grant covers: a resource and an action, either of which may be any. Written
/// like a permission with <c>*</c> for any: <c>documents:read</c>, <c>documents:*</c>,
/// <c>*:read</c>, or <c>*</c> for everything (<c>*:*</c> parses to the same pattern).
/// </summary>
public sealed record PermissionPattern
{
    private readonly Fs.PermissionPattern _fs;

    private PermissionPattern(Fs.PermissionPattern fs) => _fs = fs;

    /// <summary>Every resource and every action: <c>*</c>.</summary>
    public static PermissionPattern Everything { get; } = new(Fs.PermissionPatternModule.everything);

    /// <summary>The pattern that covers exactly <paramref name="permission"/>.</summary>
    public static PermissionPattern Exactly(Permission permission)
    {
        ArgumentNullException.ThrowIfNull(permission);
        return new(Fs.PermissionPatternModule.exactly(permission.ToFs()));
    }

    /// <summary>The resource the pattern covers.</summary>
    public PermissionSegment Resource => PermissionSegment.FromFs(_fs.Resource, name => name.Value);

    /// <summary>The action the pattern covers.</summary>
    public PermissionSegment Action => PermissionSegment.FromFs(_fs.Action, name => name.Value);

    /// <summary>
    /// Whether the resource or the action is any, so the pattern covers more than one permission. False means
    /// the pattern names one permission exactly.
    /// </summary>
    public bool IsWildcard => Fs.PermissionPatternModule.isWildcard(_fs);

    /// <summary>Whether the pattern covers <paramref name="permission"/>.</summary>
    public bool Covers(Permission permission)
    {
        ArgumentNullException.ThrowIfNull(permission);
        return Fs.PermissionPatternModule.covers(permission.ToFs(), _fs);
    }

    /// <summary>
    /// Parses <c>resource:action</c> with <c>*</c> for either part, or <c>*</c> alone. Throws
    /// <see cref="ArgumentException"/> if the text is not a pattern.
    /// </summary>
    public static PermissionPattern Parse(string value) => new(Fs.PermissionPatternModule.parse(value));

    /// <summary>Tries to parse a pattern, returning <see langword="false"/> on failure.</summary>
    public static bool TryParse(string? value, [NotNullWhen(true)] out PermissionPattern? pattern)
    {
        var parsed = Fs.PermissionPatternModule.tryParse(value);
        pattern = FSharpOption<Fs.PermissionPattern>.get_IsSome(parsed) ? new PermissionPattern(parsed.Value) : null;
        return pattern is not null;
    }

    /// <summary>Returns the pattern's text, which <see cref="Parse"/> reads back.</summary>
    public override string ToString() => _fs.ToString();

    internal Fs.PermissionPattern ToFs() => _fs;

    internal static PermissionPattern FromFs(Fs.PermissionPattern pattern) => new(pattern);
}

/// <summary>One part of a <see cref="PermissionPattern"/>: any resource (or action), or exactly one.</summary>
public abstract record PermissionSegment
{
    private PermissionSegment() { }

    /// <summary>Any resource, or any action. Written <c>*</c>.</summary>
    public sealed record Any : PermissionSegment
    {
        /// <inheritdoc />
        public override string ToString() => Fs.PermissionPatternModule.Wildcard;
    }

    /// <summary>Exactly this resource or action.</summary>
    /// <param name="Name">The resource or action name.</param>
    public sealed record Exactly(string Name) : PermissionSegment
    {
        /// <inheritdoc />
        public override string ToString() => Name;
    }

    internal static PermissionSegment FromFs<TName>(Fs.Segment<TName> segment, Func<TName, string> name) => segment switch
    {
        { IsAny: true } => new Any(),
        Fs.Segment<TName>.Exactly exactly => new Exactly(name(exactly.Item)),
        _ => throw new InvalidOperationException($"Unmapped RealTree.Authzn.Segment case '{segment}'."),
    };
}
