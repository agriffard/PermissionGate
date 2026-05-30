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

public class CanComponentTests : BunitContext
{
    // Helper: wraps markup string into RenderFragment<AuthenticationState>
    private static RenderFragment<AuthenticationState> C(string markup)
        => _ => b => b.AddMarkupContent(0, markup);

    public CanComponentTests()
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
    // Authorized → renders ChildContent
    // ──────────────────────────────────────────────

    [Fact]
    public void Renders_ChildContent_When_Policy_Authorized()
    {
        TestHelpers.SetupAuthorizationService(Services, "Edit");
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Can>(p => p
            .Add(c => c.Policy, "Edit")
            .Add(c => c.ChildContent, C("<span>Allowed</span>")));

        cut.Find("span").TextContent.Should().Be("Allowed");
    }

    [Fact]
    public void Renders_Nothing_When_Policy_Denied()
    {
        TestHelpers.SetupAuthorizationService(Services);
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Can>(p => p
            .Add(c => c.Policy, "Edit")
            .Add(c => c.ChildContent, C("<span>Should not show</span>")));

        cut.Markup.Trim().Should().BeEmpty();
    }

    // ──────────────────────────────────────────────
    // Else branch
    // ──────────────────────────────────────────────

    [Fact]
    public void Renders_Else_When_Policy_Denied()
    {
        TestHelpers.SetupAuthorizationService(Services);
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Can>(p => p
            .Add(c => c.Policy, "Export")
            .Add(c => c.Else, (RenderFragment)(b => b.AddMarkupContent(0, "<span>Upgrade</span>")))
            .Add(c => c.ChildContent, C("<span>Export</span>")));

        cut.Find("span").TextContent.Should().Be("Upgrade");
    }

    [Fact]
    public void Does_Not_Render_Else_When_Policy_Authorized()
    {
        TestHelpers.SetupAuthorizationService(Services, "Export");
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Can>(p => p
            .Add(c => c.Policy, "Export")
            .Add(c => c.Else, (RenderFragment)(b => b.AddMarkupContent(0, "<span>Upgrade</span>")))
            .Add(c => c.ChildContent, C("<span>Export</span>")));

        cut.Find("span").TextContent.Should().Be("Export");
    }

    // ──────────────────────────────────────────────
    // Role-based
    // ──────────────────────────────────────────────

    [Fact]
    public void Renders_ChildContent_When_User_In_Role()
    {
        TestHelpers.SetupAuthorizationService(Services);
        SetupAuth(TestHelpers.AuthenticatedUser("Admin"));

        var cut = Render<Can>(p => p
            .Add(c => c.Roles, "Admin")
            .Add(c => c.ChildContent, C("<span>Admin content</span>")));

        cut.Find("span").TextContent.Should().Be("Admin content");
    }

    [Fact]
    public void Renders_Nothing_When_User_Not_In_Role()
    {
        TestHelpers.SetupAuthorizationService(Services);
        SetupAuth(TestHelpers.AuthenticatedUser("Editor"));

        var cut = Render<Can>(p => p
            .Add(c => c.Roles, "Admin")
            .Add(c => c.ChildContent, C("<span>Admin content</span>")));

        cut.Markup.Trim().Should().BeEmpty();
    }

    [Fact]
    public void Renders_ChildContent_When_User_In_Any_CommaSeparated_Role()
    {
        TestHelpers.SetupAuthorizationService(Services);
        SetupAuth(TestHelpers.AuthenticatedUser("Editor"));

        var cut = Render<Can>(p => p
            .Add(c => c.Roles, "Admin, Editor")
            .Add(c => c.ChildContent, C("<span>Allowed</span>")));

        cut.Find("span").TextContent.Should().Be("Allowed");
    }

    // ──────────────────────────────────────────────
    // Multiple policies — Mode.All
    // ──────────────────────────────────────────────

    [Fact]
    public void Renders_When_All_Policies_Approved_ModeAll()
    {
        TestHelpers.SetupAuthorizationService(Services, "Read", "Write");
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Can>(p => p
            .Add(c => c.Policies, new[] { "Read", "Write" })
            .Add(c => c.Mode, GateMode.All)
            .Add(c => c.ChildContent, C("<span>Both</span>")));

        cut.Find("span").TextContent.Should().Be("Both");
    }

    [Fact]
    public void Renders_Nothing_When_One_Policy_Denied_ModeAll()
    {
        TestHelpers.SetupAuthorizationService(Services, "Read" /* Write denied */);
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Can>(p => p
            .Add(c => c.Policies, new[] { "Read", "Write" })
            .Add(c => c.Mode, GateMode.All)
            .Add(c => c.ChildContent, C("<span>Both</span>")));

        cut.Markup.Trim().Should().BeEmpty();
    }

    // ──────────────────────────────────────────────
    // Multiple policies — Mode.Any
    // ──────────────────────────────────────────────

    [Fact]
    public void Renders_When_Any_Policy_Approved_ModeAny()
    {
        TestHelpers.SetupAuthorizationService(Services, "Approve" /* Manage denied */);
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Can>(p => p
            .Add(c => c.Policies, new[] { "Manage", "Approve" })
            .Add(c => c.Mode, GateMode.Any)
            .Add(c => c.ChildContent, C("<span>Any</span>")));

        cut.Find("span").TextContent.Should().Be("Any");
    }

    [Fact]
    public void Renders_Nothing_When_All_Policies_Denied_ModeAny()
    {
        TestHelpers.SetupAuthorizationService(Services);
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Can>(p => p
            .Add(c => c.Policies, new[] { "Manage", "Approve" })
            .Add(c => c.Mode, GateMode.Any)
            .Add(c => c.ChildContent, C("<span>Any</span>")));

        cut.Markup.Trim().Should().BeEmpty();
    }

    // ──────────────────────────────────────────────
    // Resource forwarding
    // ──────────────────────────────────────────────

    [Fact]
    public async Task Forwards_Resource_To_AuthorizationService()
    {
        var authService = Substitute.For<IAuthorizationService>();
        authService
            .AuthorizeAsync(Arg.Any<ClaimsPrincipal>(), Arg.Any<object?>(), Arg.Any<string>())
            .Returns(Task.FromResult(AuthorizationResult.Success()));

        Services.AddSingleton(authService);
        SetupAuth(TestHelpers.AuthenticatedUser());

        var resource = new { Id = 42 };

        Render<Can>(p => p
            .Add(c => c.Policy, "Edit")
            .Add(c => c.Resource, resource)
            .Add(c => c.ChildContent, C("<span>OK</span>")));

        await authService.Received(1)
            .AuthorizeAsync(Arg.Any<ClaimsPrincipal>(), resource, Arg.Any<string>());
    }

    // ──────────────────────────────────────────────
    // AuthContext re-evaluation
    // ──────────────────────────────────────────────

    [Fact]
    public void Re_Renders_When_AuthState_Changes()
    {
        var authService = Substitute.For<IAuthorizationService>();
        authService
            .AuthorizeAsync(Arg.Any<ClaimsPrincipal>(), Arg.Any<object?>(), Arg.Any<string>())
            .Returns(callInfo =>
            {
                var user = callInfo.Arg<ClaimsPrincipal>();
                return user.IsInRole("Admin")
                    ? Task.FromResult(AuthorizationResult.Success())
                    : Task.FromResult(AuthorizationResult.Failed());
            });
        Services.AddSingleton(authService);

        var provider = SetupAuth(TestHelpers.AnonymousUser());

        var cut = Render<Can>(p => p
            .Add(c => c.Policy, "AdminOnly")
            .Add(c => c.ChildContent, C("<span>Admin</span>")));

        cut.Markup.Trim().Should().BeEmpty();

        provider.SetUser(TestHelpers.AuthenticatedUser("Admin"));

        cut.WaitForAssertion(() =>
            cut.Find("span").TextContent.Should().Be("Admin"));
    }

    // ──────────────────────────────────────────────
    // Validation
    // ──────────────────────────────────────────────

    [Fact]
    public void Throws_When_No_Requirements_Specified()
    {
        TestHelpers.SetupAuthorizationService(Services);
        SetupAuth(TestHelpers.AuthenticatedUser());

        var act = () => Render<Can>(p => p
            .Add(c => c.ChildContent, C("<span>Content</span>")));

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*'Can'*Policy*Policies*Roles*");
    }

    // ──────────────────────────────────────────────
    // ChildContent receives AuthenticationState context
    // ──────────────────────────────────────────────

    [Fact]
    public void ChildContent_Receives_AuthenticationState_Context()
    {
        TestHelpers.SetupAuthorizationService(Services, "Read");
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Can>(p => p
            .Add(c => c.Policy, "Read")
            .Add(c => c.ChildContent, (RenderFragment<AuthenticationState>)(
                authState => builder =>
                    builder.AddMarkupContent(0, $"<span>{authState.User.Identity?.Name}</span>"))));

        cut.Find("span").TextContent.Should().Be("testuser");
    }
}

/// <summary>A fake <see cref="AuthenticationStateProvider"/> that supports changing the user mid-test.</summary>
internal sealed class FakeAuthenticationStateProvider : AuthenticationStateProvider
{
    private AuthenticationState _state;

    public FakeAuthenticationStateProvider(ClaimsPrincipal user)
        => _state = new AuthenticationState(user);

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
        => Task.FromResult(_state);

    public void SetUser(ClaimsPrincipal user)
    {
        _state = new AuthenticationState(user);
        NotifyAuthenticationStateChanged(Task.FromResult(_state));
    }
}

