using System;
using System.Collections.Generic;
using Fs = RealTree.Authzn;

namespace RealTree.Authzn.CSharp;

/// <summary>
/// A request to evaluate: can <see cref="Principal"/> perform <see cref="Permission"/> in
/// <see cref="Scope"/>, given <see cref="Attributes"/>? Construct one and pass it to
/// <see cref="Authorizer.AuthorizeAsync(AuthorizationRequest, System.Threading.CancellationToken)"/>,
/// or call the <c>Authorizer.AuthorizeAsync(principal, permission, ...)</c> overload, which builds
/// one from a permission string.
/// </summary>
public sealed class AuthorizationRequest
{
    /// <summary>The principal requesting access.</summary>
    public PrincipalRef Principal { get; }

    /// <summary>The permission being requested.</summary>
    public Permission Permission { get; }

    /// <summary>
    /// The scope values of the resource acted on, by key (for example its tenant). A grant matches
    /// only when every key in its grant scope is present here with a matching value, so an empty
    /// scope matches only grants whose grant scope is empty.
    /// </summary>
    public IReadOnlyDictionary<string, string> Scope { get; }

    /// <summary>The runtime attributes passed to a grant's ABAC condition.</summary>
    public IReadOnlyDictionary<string, object> Attributes { get; }

    /// <summary>
    /// Creates an authorization request. Throws <see cref="ArgumentNullException"/> when
    /// <paramref name="permission"/> is <see langword="null"/>. A <see langword="null"/>
    /// <paramref name="scope"/> or <paramref name="attributes"/> becomes an empty dictionary.
    /// </summary>
    public AuthorizationRequest(
        PrincipalRef principal,
        Permission permission,
        IReadOnlyDictionary<string, string>? scope = null,
        IReadOnlyDictionary<string, object>? attributes = null)
    {
        ArgumentNullException.ThrowIfNull(permission);
        Principal = principal;
        Permission = permission;
        Scope = scope ?? Interop.EmptyScope;
        Attributes = attributes ?? Interop.EmptyAttributes;
    }

    /// <summary>Returns a copy of this request with the given scope.</summary>
    public AuthorizationRequest WithScope(IReadOnlyDictionary<string, string> scope) =>
        new(Principal, Permission, scope, Attributes);

    /// <summary>Returns a copy of this request with the given attributes.</summary>
    public AuthorizationRequest WithAttributes(IReadOnlyDictionary<string, object> attributes) =>
        new(Principal, Permission, Scope, attributes);

    internal Fs.AuthorizationRequest ToFs()
    {
        var request = Fs.AuthorizationRequestModule.create(Principal.ToFs(), Permission.ToFs());
        request = Fs.AuthorizationRequestModule.withScope(Interop.ToStringMap(Scope), request);
        request = Fs.AuthorizationRequestModule.withAttributes(Interop.ToObjectMap(Attributes), request);
        return request;
    }
}
