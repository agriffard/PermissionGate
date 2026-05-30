namespace PermissionGate;

/// <summary>
/// Imperative authorization service for use in <c>@code</c> blocks and page logic.
/// Delegates to the app's configured <see cref="Microsoft.AspNetCore.Authorization.IAuthorizationService"/>.
/// </summary>
/// <remarks>
/// UI gating is <strong>presentation only</strong>. The server must still authorize every
/// operation independently. Never rely solely on this service for security enforcement.
/// </remarks>
public interface IPermissionGate
{
    /// <summary>Returns <see langword="true"/> if the current user satisfies <paramref name="policy"/>.</summary>
    /// <param name="policy">The policy name to evaluate.</param>
    /// <param name="resource">Optional resource for resource-based authorization handlers.</param>
    /// <param name="ct">Cancellation token.</param>
    Task<bool> CanAsync(string policy, object? resource = null, CancellationToken ct = default);

    /// <summary>Returns <see langword="true"/> if the current user satisfies <em>all</em> of <paramref name="policies"/>.</summary>
    /// <param name="policies">The policy names to evaluate.</param>
    /// <param name="resource">Optional resource for resource-based authorization handlers.</param>
    /// <param name="ct">Cancellation token.</param>
    Task<bool> CanAllAsync(IEnumerable<string> policies, object? resource = null, CancellationToken ct = default);

    /// <summary>Returns <see langword="true"/> if the current user satisfies <em>any</em> of <paramref name="policies"/>.</summary>
    /// <param name="policies">The policy names to evaluate.</param>
    /// <param name="resource">Optional resource for resource-based authorization handlers.</param>
    /// <param name="ct">Cancellation token.</param>
    Task<bool> CanAnyAsync(IEnumerable<string> policies, object? resource = null, CancellationToken ct = default);

    /// <summary>Returns <see langword="true"/> if the current user is in <paramref name="role"/>.</summary>
    /// <param name="role">The role name to check.</param>
    /// <param name="ct">Cancellation token.</param>
    Task<bool> IsInRoleAsync(string role, CancellationToken ct = default);
}
