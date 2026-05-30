using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;

namespace PermissionGate.Components;

/// <summary>
/// Abstract base for <see cref="Can"/> and <see cref="Cannot"/>.
/// Handles authorization evaluation, cascading auth state subscription,
/// and re-evaluation when auth state or parameters change.
/// </summary>
public abstract class GateComponentBase : ComponentBase, IDisposable
{
    [CascadingParameter] private Task<AuthenticationState>? AuthenticationStateTask { get; set; }
    [Inject] private IAuthorizationService AuthorizationService { get; set; } = default!;
    [Inject] private AuthenticationStateProvider AuthenticationStateProvider { get; set; } = default!;

    /// <summary>Single policy name to evaluate.</summary>
    [Parameter] public string? Policy { get; set; }

    /// <summary>Multiple policy names combined per <see cref="Mode"/>.</summary>
    [Parameter] public IEnumerable<string>? Policies { get; set; }

    /// <summary>Comma-separated roles. The check succeeds when the user is in at least one listed role.</summary>
    [Parameter] public string? Roles { get; set; }

    /// <summary>Resource passed to resource-based authorization handlers.</summary>
    [Parameter] public object? Resource { get; set; }

    /// <summary>
    /// How multiple requirements are combined. Default is <see cref="GateMode.All"/> (AND).
    /// </summary>
    [Parameter] public GateMode Mode { get; set; } = GateMode.All;

    /// <summary>
    /// Content rendered when the gate condition is met. Receives the current
    /// <see cref="AuthenticationState"/> as <c>@context</c>.
    /// </summary>
    [Parameter] public RenderFragment<AuthenticationState>? ChildContent { get; set; }

    /// <summary>Content rendered while the authorization check is pending.</summary>
    [Parameter] public RenderFragment? Authorizing { get; set; }

    /// <summary>Whether the authorization check is still in progress.</summary>
    protected bool IsAuthorizing { get; private set; } = true;

    /// <summary>Whether the most recent authorization check succeeded.</summary>
    protected bool IsAuthorized { get; private set; }

    /// <summary>The authentication state resolved during the last evaluation.</summary>
    protected AuthenticationState? CurrentAuthState { get; private set; }

    /// <inheritdoc/>
    protected override void OnInitialized()
        => AuthenticationStateProvider.AuthenticationStateChanged += OnAuthStateChanged;

    /// <inheritdoc/>
    protected override async Task OnParametersSetAsync()
        => await EvaluateAsync(AuthenticationStateTask);

    private async void OnAuthStateChanged(Task<AuthenticationState> authStateTask)
    {
        await EvaluateAsync(authStateTask);
        await InvokeAsync(StateHasChanged);
    }

    private async Task EvaluateAsync(Task<AuthenticationState>? authStateTask)
    {
        IsAuthorizing = true;

        var state = authStateTask is not null
            ? await authStateTask
            : new AuthenticationState(new ClaimsPrincipal());

        CurrentAuthState = state;

        ValidateRequirements();

        IsAuthorized = await CheckAsync(state.User);
        IsAuthorizing = false;
    }

    private void ValidateRequirements()
    {
        var hasPolicies = Policy is not null || Policies?.Any() == true;
        var hasRoles = Roles is not null;

        if (!hasPolicies && !hasRoles)
        {
            throw new InvalidOperationException(
                $"The '{GetType().Name}' component requires at least one of " +
                $"'{nameof(Policy)}', '{nameof(Policies)}', or '{nameof(Roles)}' to be specified.");
        }
    }

    private async Task<bool> CheckAsync(ClaimsPrincipal user)
    {
        var checks = BuildChecks(user);

        if (Mode == GateMode.All)
        {
            foreach (var check in checks)
                if (!await check()) return false;
            return true;
        }
        else
        {
            foreach (var check in checks)
                if (await check()) return true;
            return false;
        }
    }

    private List<Func<Task<bool>>> BuildChecks(ClaimsPrincipal user)
    {
        var checks = new List<Func<Task<bool>>>();

        if (Policy is not null)
            checks.Add(() => CheckPolicyAsync(user, Policy));

        if (Policies is not null)
            foreach (var p in Policies)
                checks.Add(() => CheckPolicyAsync(user, p));

        if (Roles is not null)
        {
            var roles = Roles.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            checks.Add(() => Task.FromResult(roles.Any(user.IsInRole)));
        }

        return checks;
    }

    private async Task<bool> CheckPolicyAsync(ClaimsPrincipal user, string policy)
    {
        var result = await AuthorizationService.AuthorizeAsync(user, Resource, policy);
        return result.Succeeded;
    }

    /// <inheritdoc/>
    public void Dispose()
        => AuthenticationStateProvider.AuthenticationStateChanged -= OnAuthStateChanged;
}
