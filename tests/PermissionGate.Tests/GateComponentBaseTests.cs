using Bunit;
using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using System.Security.Claims;
using PermissionGate.Components;

namespace PermissionGate.Tests;

/// <summary>
/// Tests for behavior shared by <see cref="Can"/> and <see cref="Cannot"/> via
/// <see cref="GateComponentBase"/>: pending state, role trimming, combined requirements,
/// resource forwarding on <c>Cannot</c>, null cascading state, and disposal.
/// </summary>
public class GateComponentBaseTests : BunitContext
{
    private static RenderFragment<AuthenticationState> C(string markup)
        => _ => b => b.AddMarkupContent(0, markup);

    public GateComponentBaseTests()
    {
        Services.AddOptions();
        Services.AddAuthorizationCore();
    }

    private FakeAuthenticationStateProvider SetupAuth(ClaimsPrincipal user)
    {
        var provider = new FakeAuthenticationStateProvider(user);
        Services.AddSingleton<AuthenticationStateProvider>(provider);
        Services.AddCascadingValue<Task<AuthenticationState>>(_ => provider.GetAuthenticationStateAsync());
        return provider;
    }

    // ──────────────────────────────────────────────
    // Authorizing (pending) state
    // ──────────────────────────────────────────────

    [Fact]
    public void Renders_Authorizing_While_Check_Pending()
    {
        var tcs = new TaskCompletionSource<AuthorizationResult>();
        var authService = Substitute.For<IAuthorizationService>();
        authService
            .AuthorizeAsync(Arg.Any<ClaimsPrincipal>(), Arg.Any<object?>(), Arg.Any<string>())
            .Returns(tcs.Task);
        Services.AddSingleton(authService);
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Can>(p => p
            .Add(c => c.Policy, "Edit")
            .Add(c => c.Authorizing, (RenderFragment)(b => b.AddMarkupContent(0, "<span>Loading</span>")))
            .Add(c => c.ChildContent, C("<span>Done</span>")));

        cut.Find("span").TextContent.Should().Be("Loading");

        tcs.SetResult(AuthorizationResult.Success());

        cut.WaitForAssertion(() => cut.Find("span").TextContent.Should().Be("Done"));
    }

    // ──────────────────────────────────────────────
    // Role trimming / whitespace
    // ──────────────────────────────────────────────

    [Fact]
    public void Trims_Whitespace_In_CommaSeparated_Roles()
    {
        TestHelpers.SetupAuthorizationService(Services);
        SetupAuth(TestHelpers.AuthenticatedUser("Editor"));

        var cut = Render<Can>(p => p
            .Add(c => c.Roles, "  Admin ,  Editor  ")
            .Add(c => c.ChildContent, C("<span>Allowed</span>")));

        cut.Find("span").TextContent.Should().Be("Allowed");
    }

    [Fact]
    public void Ignores_Empty_Entries_In_Roles()
    {
        TestHelpers.SetupAuthorizationService(Services);
        SetupAuth(TestHelpers.AuthenticatedUser("Editor"));

        var cut = Render<Can>(p => p
            .Add(c => c.Roles, "Admin,,,Editor,")
            .Add(c => c.ChildContent, C("<span>Allowed</span>")));

        cut.Find("span").TextContent.Should().Be("Allowed");
    }

    // ──────────────────────────────────────────────
    // Combined Policy + Roles
    // ──────────────────────────────────────────────

    [Fact]
    public void ModeAll_Requires_Both_Policy_And_Role()
    {
        TestHelpers.SetupAuthorizationService(Services, "Edit");
        SetupAuth(TestHelpers.AuthenticatedUser("Editor")); // not Admin

        var cut = Render<Can>(p => p
            .Add(c => c.Policy, "Edit")
            .Add(c => c.Roles, "Admin")
            .Add(c => c.Mode, GateMode.All)
            .Add(c => c.ChildContent, C("<span>Both</span>")));

        cut.Markup.Trim().Should().BeEmpty();
    }

    [Fact]
    public void ModeAny_Passes_When_Only_Role_Matches()
    {
        TestHelpers.SetupAuthorizationService(Services /* Edit denied */);
        SetupAuth(TestHelpers.AuthenticatedUser("Admin"));

        var cut = Render<Can>(p => p
            .Add(c => c.Policy, "Edit")
            .Add(c => c.Roles, "Admin")
            .Add(c => c.Mode, GateMode.Any)
            .Add(c => c.ChildContent, C("<span>Either</span>")));

        cut.Find("span").TextContent.Should().Be("Either");
    }

    // ──────────────────────────────────────────────
    // Null cascading auth state → anonymous
    // ──────────────────────────────────────────────

    [Fact]
    public void Treats_Missing_Cascading_State_As_Anonymous()
    {
        TestHelpers.SetupAuthorizationService(Services);
        // Provide a provider but NO cascading value → AuthenticationStateTask is null.
        Services.AddSingleton<AuthenticationStateProvider>(
            new FakeAuthenticationStateProvider(TestHelpers.AnonymousUser()));

        var cut = Render<Cannot>(p => p
            .Add(c => c.Roles, "Admin")
            .Add(c => c.ChildContent, C("<span>Not Admin</span>")));

        cut.Find("span").TextContent.Should().Be("Not Admin");
    }

    // ──────────────────────────────────────────────
    // Cannot — resource forwarding
    // ──────────────────────────────────────────────

    [Fact]
    public async Task Cannot_Forwards_Resource_To_AuthorizationService()
    {
        var authService = Substitute.For<IAuthorizationService>();
        authService
            .AuthorizeAsync(Arg.Any<ClaimsPrincipal>(), Arg.Any<object?>(), Arg.Any<string>())
            .Returns(Task.FromResult(AuthorizationResult.Failed()));
        Services.AddSingleton(authService);
        SetupAuth(TestHelpers.AuthenticatedUser());

        var resource = new { Id = 7 };

        Render<Cannot>(p => p
            .Add(c => c.Policy, "Edit")
            .Add(c => c.Resource, resource)
            .Add(c => c.ChildContent, C("<span>Denied</span>")));

        await authService.Received(1)
            .AuthorizeAsync(Arg.Any<ClaimsPrincipal>(), resource, Arg.Any<string>());
    }

    // ──────────────────────────────────────────────
    // Cannot — Mode.Any renders when all denied
    // ──────────────────────────────────────────────

    [Fact]
    public void Cannot_Renders_ChildContent_When_All_Policies_Denied_ModeAny()
    {
        TestHelpers.SetupAuthorizationService(Services);
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Cannot>(p => p
            .Add(c => c.Policies, new[] { "Manage", "Approve" })
            .Add(c => c.Mode, GateMode.Any)
            .Add(c => c.ChildContent, C("<span>Limited</span>")));

        cut.Find("span").TextContent.Should().Be("Limited");
    }

    // ──────────────────────────────────────────────
    // Re-evaluates when parameters change
    // ──────────────────────────────────────────────

    [Fact]
    public void Re_Evaluates_When_Policy_Parameter_Changes()
    {
        TestHelpers.SetupAuthorizationService(Services, "Read");
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Can>(p => p
            .Add(c => c.Policy, "Read")
            .Add(c => c.ChildContent, C("<span>OK</span>")));

        cut.Find("span").TextContent.Should().Be("OK");

        cut.Render(p => p
            .Add(c => c.Policy, "Write") // denied
            .Add(c => c.ChildContent, C("<span>OK</span>")));

        cut.Markup.Trim().Should().BeEmpty();
    }

    // ──────────────────────────────────────────────
    // Dispose unsubscribes from auth state changes
    // ──────────────────────────────────────────────

    [Fact]
    public void Dispose_Unsubscribes_From_AuthStateChanged()
    {
        TestHelpers.SetupAuthorizationService(Services, "Admin");
        var provider = SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Can>(p => p
            .Add(c => c.Policy, "Admin")
            .Add(c => c.ChildContent, C("<span>Admin</span>")));

        cut.Find("span").TextContent.Should().Be("Admin");

        cut.Instance.Dispose();

        // Firing a change after dispose must not throw (handler detached).
        var act = () => provider.SetUser(TestHelpers.AnonymousUser());
        act.Should().NotThrow();
    }
}
