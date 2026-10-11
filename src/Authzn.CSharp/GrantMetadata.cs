using System;
using Microsoft.FSharp.Core;
using Fs = Authzn;

namespace Authzn.CSharp;

/// <summary>
/// Optional audit and lifecycle metadata attached to a permission grant: who added it, why,
/// who consented, when it expires, and whether it has been revoked. Every member is optional;
/// use <see cref="Empty"/> when no metadata is needed.
/// </summary>
public sealed record GrantMetadata
{
    /// <summary>What added this grant (free-form, e.g. <c>"app:foo@1.0.0"</c>, <c>"bootstrap"</c>).</summary>
    public string? Source { get; init; }

    /// <summary>Human-readable justification captured at write time.</summary>
    public string? Reason { get; init; }

    /// <summary>The principal who explicitly consented to the grant.</summary>
    public PrincipalRef? ConsentedBy { get; init; }

    /// <summary>When consent was captured.</summary>
    public DateTimeOffset? ConsentedAt { get; init; }

    /// <summary>When the grant expires. The engine treats it as inactive from this time on.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>When the grant was revoked. Non-null marks the grant inactive.</summary>
    public DateTimeOffset? RevokedAt { get; init; }

    /// <summary>The principal who revoked the grant.</summary>
    public PrincipalRef? RevokedBy { get; init; }

    /// <summary>Metadata with every member unset.</summary>
    public static GrantMetadata Empty { get; } = new();

    /// <summary>
    /// Returns whether the grant is active at <paramref name="at"/>: <see cref="RevokedAt"/> is
    /// <see langword="null"/>, and <see cref="ExpiresAt"/> is <see langword="null"/> or later than
    /// <paramref name="at"/>.
    /// </summary>
    public bool IsActiveAt(DateTimeOffset at) => Fs.GrantMetadataModule.isActiveAt(at, ToFs());

    internal Fs.GrantMetadata ToFs() => new(
        Interop.ToOption(Source),
        Interop.ToOption(Reason),
        ConsentedBy is { } consentedBy
            ? FSharpOption<Fs.PrincipalId>.Some(consentedBy.ToFs())
            : FSharpOption<Fs.PrincipalId>.None,
        Interop.ToOptionStruct(ConsentedAt),
        Interop.ToOptionStruct(ExpiresAt),
        Interop.ToOptionStruct(RevokedAt),
        RevokedBy is { } revokedBy
            ? FSharpOption<Fs.PrincipalId>.Some(revokedBy.ToFs())
            : FSharpOption<Fs.PrincipalId>.None);

    internal static GrantMetadata FromFs(Fs.GrantMetadata metadata) => new()
    {
        Source = Interop.FromOption(metadata.Source),
        Reason = Interop.FromOption(metadata.Reason),
        ConsentedBy = FSharpOption<Fs.PrincipalId>.get_IsSome(metadata.ConsentedBy)
            ? PrincipalRef.FromFs(metadata.ConsentedBy.Value)
            : (PrincipalRef?)null,
        ConsentedAt = Interop.FromOptionStruct(metadata.ConsentedAt),
        ExpiresAt = Interop.FromOptionStruct(metadata.ExpiresAt),
        RevokedAt = Interop.FromOptionStruct(metadata.RevokedAt),
        RevokedBy = FSharpOption<Fs.PrincipalId>.get_IsSome(metadata.RevokedBy)
            ? PrincipalRef.FromFs(metadata.RevokedBy.Value)
            : (PrincipalRef?)null,
    };
}
