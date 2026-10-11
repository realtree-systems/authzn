using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.FSharp.Collections;
using Fs = Authzn;

namespace Authzn.CSharp;

/// <summary>
/// The set of concrete values a scope key may take for a principal: either unbounded
/// (<see cref="Any"/>) or a finite set (<see cref="Of"/>). A scope resolver's
/// <see cref="ScopeValueResolver.EnumerateScopeAsync"/> returns one for a marker, and each clause of
/// <see cref="ScopeConstraint.Restricted"/> holds one per constrained key.
/// </summary>
public abstract record ScopeValueSet
{
    private ScopeValueSet() { }

    /// <summary>The key is unconstrained; any value is admitted.</summary>
    public sealed record Any : ScopeValueSet;

    /// <summary>The key is constrained to a finite set of values.</summary>
    public sealed record Of(IReadOnlySet<string> Values) : ScopeValueSet;

    /// <summary>The unconstrained value set, an instance of <see cref="Any"/>.</summary>
    public static ScopeValueSet Anything { get; } = new Any();

    /// <summary>A value set restricted to the given values.</summary>
    public static ScopeValueSet From(IEnumerable<string> values) => new Of(values.ToHashSet());

    internal Fs.ScopeValueSet ToFs() => this switch
    {
        Any => Fs.ScopeValueSet.AnyValue,
        Of of => Fs.ScopeValueSet.NewValues(SetModule.OfSeq(of.Values)),
        _ => throw new InvalidOperationException($"Unknown ScopeValueSet '{this}'."),
    };

    internal static ScopeValueSet FromFs(Fs.ScopeValueSet value) => value switch
    {
        { IsAnyValue: true } => Anything,
        Fs.ScopeValueSet.Values values => new Of(values.Item.ToHashSet()),
        _ => throw new InvalidOperationException($"Unmapped Authzn.ScopeValueSet case '{value}'."),
    };
}

/// <summary>
/// The set of resources a principal may act on for a permission, produced by
/// <see cref="Authorizer.VisibleScopeAsync"/> so the caller can push it into a query.
/// <see cref="Everything"/> means no restriction; <see cref="Nothing"/> means no access;
/// <see cref="Restricted"/> holds one clause per contributing grant. A resource is admitted when it
/// satisfies any clause, and satisfies a clause when its value for each key in the clause is in
/// that key's <see cref="ScopeValueSet"/>. A key absent from a clause is unconstrained for it.
/// </summary>
public abstract record ScopeConstraint
{
    private ScopeConstraint() { }

    /// <summary>The principal may act on every resource.</summary>
    public sealed record Everything : ScopeConstraint;

    /// <summary>The principal may act on no resource.</summary>
    public sealed record Nothing : ScopeConstraint;

    /// <summary>A union of conjunctive clauses; a resource is admitted when it satisfies any one of them.</summary>
    public sealed record Restricted(IReadOnlyList<IReadOnlyDictionary<string, ScopeValueSet>> Clauses) : ScopeConstraint;

    internal static ScopeConstraint FromFs(Fs.ScopeConstraint constraint) => constraint switch
    {
        { IsEverything: true } => new Everything(),
        { IsNothing: true } => new Nothing(),
        Fs.ScopeConstraint.Restricted restricted => new Restricted(
            restricted.Item
                .Select(clause => (IReadOnlyDictionary<string, ScopeValueSet>)
                    clause.ToDictionary(kv => kv.Key, kv => ScopeValueSet.FromFs(kv.Value)))
                .ToList()),
        _ => throw new InvalidOperationException($"Unmapped Authzn.ScopeConstraint case '{constraint}'."),
    };
}
