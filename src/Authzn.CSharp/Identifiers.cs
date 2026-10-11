using Fs = Authzn;

namespace Authzn.CSharp;

/// <summary>
/// Identifies a principal (user, service, or group). Converts implicitly from <see cref="string"/>
/// so call sites can pass a plain id; <see cref="Value"/> and <see cref="ToString"/> return the id.
/// There is no implicit conversion back to <see cref="string"/>, so swapped arguments such as
/// <c>AuthorizeAsync(permission, principal)</c> fail to compile.
/// </summary>
public readonly record struct PrincipalRef(string Value)
{
    /// <summary>Wraps a string as a <see cref="PrincipalRef"/>.</summary>
    public static implicit operator PrincipalRef(string value) => new(value);

    /// <inheritdoc />
    public override string ToString() => Value;

    internal Fs.PrincipalId ToFs() => Fs.PrincipalIdModule.create(Value);

    internal static PrincipalRef FromFs(Fs.PrincipalId principal) => new(principal.Value);
}

/// <summary>
/// Identifies a role. Converts implicitly from <see cref="string"/>; <see cref="Value"/> and
/// <see cref="ToString"/> return the id. There is no implicit conversion back to
/// <see cref="string"/>, for the reason given on <see cref="PrincipalRef"/>.
/// </summary>
public readonly record struct RoleRef(string Value)
{
    /// <summary>Wraps a string as a <see cref="RoleRef"/>.</summary>
    public static implicit operator RoleRef(string value) => new(value);

    /// <inheritdoc />
    public override string ToString() => Value;

    internal Fs.RoleId ToFs() => Fs.RoleIdModule.create(Value);

    internal static RoleRef FromFs(Fs.RoleId role) => new(role.Value);
}

/// <summary>
/// The stable, canonical key for a specific grant within a role: the lowercase hex SHA-256 of the
/// grant's permission pattern and scope; the condition and the metadata are not part of it. A role
/// cannot hold two grants with the same pattern and scope (<see cref="RoleBuilder.Build"/> throws),
/// so the key names one grant in a role. <see cref="Authorizer.RevokeGrant"/> and
/// <see cref="Authorizer.ReinstateGrant"/> revoke or reinstate that grant by this value without
/// rebuilding the role.
/// </summary>
public readonly record struct GrantRef(string Value)
{
    /// <inheritdoc />
    public override string ToString() => Value;

    internal Fs.GrantKey ToFs() => Fs.GrantKeyModule.create(Value);

    internal static GrantRef FromFs(Fs.GrantKey key) => new(key.Value);
}
