using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Fs = Authzn;

namespace Authzn.CSharp;

/// <summary>
/// Extension methods for registering Authzn with the dependency injection container.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Runs <paramref name="configure"/> on a new <see cref="AuthorizationBuilder"/> immediately,
    /// builds it, and registers as singletons the <see cref="Authorizer"/>, the
    /// <see cref="GrantPolicyChain"/>, and the core's <c>AuthorizationHost</c>,
    /// <c>AuthorizationEngine</c> and <c>IGrantPolicyChain</c>.
    /// </summary>
    public static IServiceCollection AddAuthzn(this IServiceCollection services, Action<AuthorizationBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var builder = new AuthorizationBuilder();
        configure(builder);
        var host = Fs.AuthorizationHostModule.build(builder.ToFsConfig());
        return Register(services, _ => host);
    }

    /// <summary>
    /// Registers an <see cref="Authorizer"/> backed by custom stores, with an optional scope
    /// resolver, and the same core singletons as the overload that takes a builder action.
    /// </summary>
    public static IServiceCollection AddAuthzn(
        this IServiceCollection services,
        RoleStore roleStore,
        AssignmentStore assignmentStore,
        ScopeValueResolver? scopeResolver = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(roleStore);
        ArgumentNullException.ThrowIfNull(assignmentStore);

        var builder = new AuthorizationBuilder()
            .UseRoleStore(roleStore)
            .UseAssignmentStore(assignmentStore);

        if (scopeResolver is not null)
        {
            builder.UseScopeResolver(scopeResolver);
        }

        var host = Fs.AuthorizationHostModule.build(builder.ToFsConfig());
        return Register(services, _ => host);
    }

    /// <summary>
    /// Registers an <see cref="Authorizer"/> over a <typeparamref name="TRoleStore"/> and a
    /// <typeparamref name="TAssignmentStore"/> that the container creates, so a store can take its
    /// own dependencies, such as an <c>IDbContextFactory</c>. Each store type is registered as a
    /// singleton unless the container already has a registration for it; the engine calls the
    /// stores from concurrent requests, so a store must not hold a scoped dependency such as a
    /// <c>DbContext</c>. It registers the same singletons as the overload that takes a builder
    /// action, but builds them when the first of them is resolved. <paramref name="configure"/> runs
    /// then, with the service provider, for example to call
    /// <see cref="AuthorizationBuilder.UseScopeResolver"/> or
    /// <see cref="AuthorizationBuilder.UseTimeProvider"/> with services from the container. The
    /// builder's roles and assignments are ignored, because the stores replace the in-memory ones.
    /// </summary>
    public static IServiceCollection AddAuthzn<TRoleStore, TAssignmentStore>(
        this IServiceCollection services,
        Action<IServiceProvider, AuthorizationBuilder>? configure = null)
        where TRoleStore : RoleStore
        where TAssignmentStore : AssignmentStore
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<TRoleStore>();
        services.TryAddSingleton<TAssignmentStore>();

        return Register(services, provider =>
        {
            var builder = new AuthorizationBuilder();
            configure?.Invoke(provider, builder);
            builder
                .UseRoleStore(provider.GetRequiredService<TRoleStore>())
                .UseAssignmentStore(provider.GetRequiredService<TAssignmentStore>());
            return Fs.AuthorizationHostModule.build(builder.ToFsConfig());
        });
    }

    /// <summary>
    /// Registers <typeparamref name="T"/> as a singleton write-time <see cref="GrantPolicy"/>. The
    /// <see cref="GrantPolicyChain"/> that <c>AddAuthzn</c> registers runs the policies in
    /// registration order and returns the first decision that is not
    /// <see cref="GrantPolicyDecision.Allow"/>, or Allow when every policy allows.
    /// </summary>
    public static IServiceCollection AddGrantPolicy<T>(this IServiceCollection services)
        where T : GrantPolicy
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<Fs.IGrantPolicy, T>();
        return services;
    }

    private static IServiceCollection Register(
        IServiceCollection services,
        Func<IServiceProvider, Fs.AuthorizationHost> host)
    {
        services.AddSingleton<Fs.AuthorizationHost>(host);
        services.AddSingleton(provider => provider.GetRequiredService<Fs.AuthorizationHost>().Engine);
        services.AddSingleton(provider => new Authorizer(provider.GetRequiredService<Fs.AuthorizationHost>()));
        services.AddSingleton<Fs.IGrantPolicyChain, Fs.GrantPolicyChain>();
        services.AddSingleton(provider => new GrantPolicyChain(provider.GetRequiredService<Fs.IGrantPolicyChain>()));
        return services;
    }
}
