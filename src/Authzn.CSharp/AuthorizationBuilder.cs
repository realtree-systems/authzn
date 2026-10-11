using System;
using Fs = RealTree.Authzn;

namespace RealTree.Authzn.CSharp;

/// <summary>
/// The entry point for configuring authorization. Add roles, assign them to principals, plug in
/// custom stores or a scope resolver, then <see cref="Build"/> an <see cref="Authorizer"/>.
/// </summary>
public sealed class AuthorizationBuilder
{
    private Fs.AuthorizationConfig _config = Fs.AuthorizationConfigModule.defaultConfig;

    /// <summary>
    /// Defines a role and adds it to the configuration. Throws <see cref="ArgumentException"/> when
    /// a role with the same id is already configured, or as <see cref="Role.Define"/> does.
    /// </summary>
    public AuthorizationBuilder AddRole(string id, string name, Action<RoleBuilder> configure)
    {
        var role = Role.Define(id, name, configure);
        _config = Fs.AuthorizationConfigModule.addRole(role.ToFs(), _config);
        return this;
    }

    /// <summary>
    /// Adds an already-built role to the configuration. Throws <see cref="ArgumentException"/>
    /// when a role with the same id is already configured.
    /// </summary>
    public AuthorizationBuilder AddRole(Role role)
    {
        _config = Fs.AuthorizationConfigModule.addRole(role.ToFs(), _config);
        return this;
    }

    /// <summary>
    /// Assigns a role to a principal with no time constraints. Assignments are stored, and their
    /// roles checked by
    /// <see cref="Authorizer.AuthorizeAsync(AuthorizationRequest, System.Threading.CancellationToken)"/>,
    /// in the order they are added.
    /// </summary>
    public AuthorizationBuilder Assign(PrincipalRef principal, RoleRef role)
    {
        _config = Fs.AuthorizationConfigModule.assign(principal.Value, role.Value, _config);
        return this;
    }

    /// <summary>
    /// Assigns a role to a principal, active from <paramref name="notBefore"/> (inclusive) until
    /// <paramref name="notAfter"/> (exclusive), after the assignments already added. Either bound
    /// may be <see langword="null"/>, leaving that side open.
    /// </summary>
    public AuthorizationBuilder AssignForWindow(
        PrincipalRef principal,
        RoleRef role,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        _config = Fs.AuthorizationConfigModule.assignForWindow(
            principal.Value,
            role.Value,
            Interop.ToOptionStruct(notBefore),
            Interop.ToOptionStruct(notAfter),
            _config);
        return this;
    }

    /// <summary>
    /// Revokes the assignments of <paramref name="role"/> to <paramref name="principal"/> added
    /// before this call; an assignment added after it is not revoked. Ignored when
    /// <see cref="UseAssignmentStore"/> supplies the store.
    /// </summary>
    public AuthorizationBuilder Revoke(PrincipalRef principal, RoleRef role)
    {
        _config = Fs.AuthorizationConfigModule.revoke(principal.Value, role.Value, _config);
        return this;
    }

    /// <summary>
    /// Uses a custom role store instead of the default in-memory store. Roles added with
    /// <c>AddRole</c> are then ignored, and <c>Authorizer.AddRole</c> throws
    /// <see cref="InvalidOperationException"/>.
    /// </summary>
    public AuthorizationBuilder UseRoleStore(RoleStore store)
    {
        _config = Fs.AuthorizationConfigModule.useRoleStore(store, _config);
        return this;
    }

    /// <summary>
    /// Uses a custom assignment store instead of the default in-memory store. Calls to
    /// <see cref="Assign"/>, <see cref="AssignForWindow"/> and <see cref="Revoke"/> are then
    /// ignored, and <see cref="Authorizer.AddAssignment"/> and <see cref="Authorizer.Revoke"/>
    /// throw <see cref="InvalidOperationException"/>.
    /// </summary>
    public AuthorizationBuilder UseAssignmentStore(AssignmentStore store)
    {
        _config = Fs.AuthorizationConfigModule.useAssignmentStore(store, _config);
        return this;
    }

    /// <summary>Registers a scope resolver for markers such as <c>@principal</c> or <c>@hierarchy</c>.</summary>
    public AuthorizationBuilder UseScopeResolver(ScopeValueResolver resolver)
    {
        _config = Fs.AuthorizationConfigModule.useScopeResolver(resolver, _config);
        return this;
    }

    /// <summary>
    /// Sets the clock the authorizer reads the current UTC time from, instead of
    /// <see cref="TimeProvider.System"/>. It decides which assignments and grants are active, so a
    /// test can check expiry and assignment windows without waiting.
    /// </summary>
    public AuthorizationBuilder UseTimeProvider(TimeProvider timeProvider)
    {
        _config = Fs.AuthorizationConfigModule.useTimeProvider(timeProvider, _config);
        return this;
    }

    /// <summary>
    /// Builds an <see cref="Authorizer"/>. Without <see cref="UseRoleStore"/>, it creates an
    /// in-memory role store holding the roles added to this builder. Without
    /// <see cref="UseAssignmentStore"/>, it creates an in-memory assignment store holding the
    /// assignments added to this builder, in the order they were added.
    /// </summary>
    public Authorizer Build() => new(Fs.AuthorizationHostModule.build(_config));

    internal Fs.AuthorizationConfig ToFsConfig() => _config;
}
