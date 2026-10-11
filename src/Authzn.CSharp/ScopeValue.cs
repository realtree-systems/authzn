using System;
using Fs = RealTree.Authzn;

namespace RealTree.Authzn.CSharp;

/// <summary>
/// One value in a grant's scope: a <see cref="Literal"/> the requested value must equal exactly, or
/// a <see cref="Marker"/> the <see cref="ScopeValueResolver"/> resolves for the principal at
/// evaluation time. A marker is never compared as text, and with no scope resolver configured it
/// matches no value.
/// </summary>
public abstract record ScopeValue
{
    private ScopeValue() { }

    /// <summary>The requested value must be exactly <see cref="Value"/>.</summary>
    public sealed record Literal : ScopeValue
    {
        /// <summary>
        /// Creates a literal. Any text is allowed, including text that starts with <c>@</c>.
        /// Throws <see cref="ArgumentNullException"/> when <paramref name="value"/> is null.
        /// </summary>
        public Literal(string value) => Value = value ?? throw new ArgumentNullException(nameof(value));

        /// <summary>The text the requested value must equal.</summary>
        public string Value { get; }
    }

    /// <summary>
    /// A marker. <see cref="ScopeValueResolver.AdmitsAsync"/> determines which requested values it
    /// admits.
    /// </summary>
    public sealed record Marker : ScopeValue
    {
        /// <summary>
        /// Creates a marker by name, e.g. <c>principal</c>. Throws <see cref="ArgumentException"/>
        /// when the name is null or empty, holds whitespace, or starts with <c>@</c>.
        /// </summary>
        public Marker(string name) => Name = Fs.MarkerNameModule.create(name).Value;

        /// <summary>The marker's name, as <see cref="ScopeValueResolver.AdmitsAsync"/> receives it.</summary>
        public string Name { get; }
    }

    /// <summary>The <c>principal</c> marker: the principal's own value for the scope key.</summary>
    public static ScopeValue Principal { get; } = new Marker(ScopeMarkers.Principal);

    /// <summary>The <c>hierarchy</c> marker: membership in the principal's organizational hierarchy.</summary>
    public static ScopeValue Hierarchy { get; } = new Marker(ScopeMarkers.Hierarchy);

    /// <summary>
    /// Reads the text form, for configuration and storage: <c>@name</c> is the marker <c>name</c>,
    /// <c>@@text</c> is the literal <c>@text</c>, and anything else is a literal. Throws
    /// <see cref="ArgumentException"/> when <paramref name="text"/> is null, or starts with
    /// <c>@</c> (not <c>@@</c>) followed by an empty name or a name that holds whitespace.
    /// </summary>
    public static ScopeValue Parse(string text) => FromFs(Fs.ScopeValueModule.parse(text));

    /// <summary>Returns the text form, which <see cref="Parse"/> reads back to the same value.</summary>
    public sealed override string ToString() => ToFs().ToString();

    internal Fs.ScopeValue ToFs() => this switch
    {
        Literal literal => Fs.ScopeValue.NewLiteral(literal.Value),
        Marker marker => Fs.ScopeValue.NewMarker(Fs.MarkerNameModule.create(marker.Name)),
        _ => throw new InvalidOperationException($"Unknown ScopeValue '{GetType().Name}'."),
    };

    internal static ScopeValue FromFs(Fs.ScopeValue value) => value switch
    {
        Fs.ScopeValue.Literal literal => new Literal(literal.Item),
        Fs.ScopeValue.Marker marker => new Marker(marker.Item.Value),
        _ => throw new InvalidOperationException($"Unmapped RealTree.Authzn.ScopeValue case '{value}'."),
    };
}
