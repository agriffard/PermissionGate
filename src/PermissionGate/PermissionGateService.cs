using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;

namespace PermissionGate;

/// <summary>
/// Default implementation of <see cref="IPermissionGate"/>.
/// Obtains the current principal via <see cref="AuthenticationStateProvider"/> and delegates
/// all checks to <see cref="IAuthorizationService"/>.
/// </summary>
internal sealed class PermissionGateService : IPermissionGate
{
    private readonly IAuthorizationService _authorizationService;
    private readonly AuthenticationStateProvider _authStateProvider;

    public PermissionGateService(
        IAuthorizationService authorizationService,
        AuthenticationStateProvider authStateProvider)
    {
        _authorizationService = authorizationService;
        _authStateProvider = authStateProvider;
    }

    /// <inheritdoc/>
    public async Task<bool> CanAsync(string policy, object? resource = null, CancellationToken ct = default)
    {
        var user = await GetUserAsync();
        var result = await _authorizationService.AuthorizeAsync(user, resource, policy);
        return result.Succeeded;
    }

    /// <inheritdoc/>
    public async Task<bool> CanAllAsync(IEnumerable<string> policies, object? resource = null, CancellationToken ct = default)
    {
        var user = await GetUserAsync();
        foreach (var policy in policies)
        {
            var result = await _authorizationService.AuthorizeAsync(user, resource, policy);
            if (!result.Succeeded) return false;
        }
        return true;
    }

    /// <inheritdoc/>
    public async Task<bool> CanAnyAsync(IEnumerable<string> policies, object? resource = null, CancellationToken ct = default)
    {
        var user = await GetUserAsync();
        foreach (var policy in policies)
        {
            var result = await _authorizationService.AuthorizeAsync(user, resource, policy);
            if (result.Succeeded) return true;
        }
        return false;
    }

    /// <inheritdoc/>
    public async Task<bool> IsInRoleAsync(string role, CancellationToken ct = default)
    {
        var user = await GetUserAsync();
        return user.IsInRole(role);
    }

    private async Task<ClaimsPrincipal> GetUserAsync()
    {
        var state = await _authStateProvider.GetAuthenticationStateAsync();
        return state.User;
    }
}
