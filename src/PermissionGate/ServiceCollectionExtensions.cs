using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace PermissionGate;

/// <summary>Extension methods for registering PermissionGate services.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the <see cref="IPermissionGate"/> scoped service.
    /// </summary>
    /// <remarks>
    /// The host app must also have:
    /// <list type="bullet">
    ///   <item><description><c>AddAuthorizationCore()</c> (or <c>AddAuthorization()</c>) with the relevant policies.</description></item>
    ///   <item><description>A cascading authentication state (<c>AddCascadingAuthenticationState()</c> or a <c>&lt;CascadingAuthenticationState&gt;</c> wrapper).</description></item>
    ///   <item><description>An <see cref="AuthenticationStateProvider"/>.</description></item>
    /// </list>
    /// </remarks>
    public static IServiceCollection AddPermissionGate(this IServiceCollection services)
    {
        services.AddScoped<IPermissionGate, PermissionGateService>();
        return services;
    }
}
