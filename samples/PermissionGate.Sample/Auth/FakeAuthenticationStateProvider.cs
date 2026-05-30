using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace PermissionGate.Sample.Auth;

/// <summary>
/// In-memory <see cref="AuthenticationStateProvider"/> for the demo. Lets the UI
/// switch between predefined sample users so you can watch <c>&lt;Can&gt;</c> /
/// <c>&lt;Cannot&gt;</c> react live. NOT for production use.
/// </summary>
public sealed class FakeAuthenticationStateProvider : AuthenticationStateProvider
{
    private ClaimsPrincipal _current = SampleUsers.Anonymous.Principal;

    public SampleUser Current { get; private set; } = SampleUsers.Anonymous;

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
        => Task.FromResult(new AuthenticationState(_current));

    /// <summary>Switches the active user and notifies the component tree.</summary>
    public void SignInAs(SampleUser user)
    {
        Current = user;
        _current = user.Principal;
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    /// <summary>Signs out, reverting to an anonymous principal.</summary>
    public void SignOut() => SignInAs(SampleUsers.Anonymous);
}
