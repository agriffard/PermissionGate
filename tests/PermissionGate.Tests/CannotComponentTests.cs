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

public class CannotComponentTests : BunitContext
{
    // Helper: wraps markup string into RenderFragment<AuthenticationState>
    private static RenderFragment<AuthenticationState> C(string markup)
        => _ => b => b.AddMarkupContent(0, markup);

    public CannotComponentTests()
    {
        Services.AddOptions();
        Services.AddAuthorizationCore();
    }

    private void SetupAuth(ClaimsPrincipal user)
    {
        var provider = new FakeAuthenticationStateProvider(user);
        Services.AddSingleton<AuthenticationStateProvider>(provider);
        Services.AddCascadingValue<Task<AuthenticationState>>(_ => provider.GetAuthenticationStateAsync());
    }

    // ──────────────────────────────────────────────
    // Cannot renders when denied, hides when authorized
    // ──────────────────────────────────────────────

    [Fact]
    public void Renders_ChildContent_When_Policy_Denied()
    {
        TestHelpers.SetupAuthorizationService(Services);
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Cannot>(p => p
            .Add(c => c.Policy, "Admin")
            .Add(c => c.ChildContent, C("<span>Read-only</span>")));

        cut.Find("span").TextContent.Should().Be("Read-only");
    }

    [Fact]
    public void Renders_Nothing_When_Policy_Authorized()
    {
        TestHelpers.SetupAuthorizationService(Services, "Admin");
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Cannot>(p => p
            .Add(c => c.Policy, "Admin")
            .Add(c => c.ChildContent, C("<span>Read-only</span>")));

        cut.Markup.Trim().Should().BeEmpty();
    }

    // ──────────────────────────────────────────────
    // Role-based inverse
    // ──────────────────────────────────────────────

    [Fact]
    public void Renders_ChildContent_When_User_Not_In_Role()
    {
        TestHelpers.SetupAuthorizationService(Services);
        SetupAuth(TestHelpers.AuthenticatedUser("Editor"));

        var cut = Render<Cannot>(p => p
            .Add(c => c.Roles, "Admin")
            .Add(c => c.ChildContent, C("<span>Not Admin</span>")));

        cut.Find("span").TextContent.Should().Be("Not Admin");
    }

    [Fact]
    public void Renders_Nothing_When_User_In_Role()
    {
        TestHelpers.SetupAuthorizationService(Services);
        SetupAuth(TestHelpers.AuthenticatedUser("Admin"));

        var cut = Render<Cannot>(p => p
            .Add(c => c.Roles, "Admin")
            .Add(c => c.ChildContent, C("<span>Not Admin</span>")));

        cut.Markup.Trim().Should().BeEmpty();
    }

    // ──────────────────────────────────────────────
    // Mode.All / Mode.Any for Cannot
    // ──────────────────────────────────────────────

    [Fact]
    public void Renders_ChildContent_When_Not_All_Policies_Pass_ModeAll()
    {
        TestHelpers.SetupAuthorizationService(Services, "Read");
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Cannot>(p => p
            .Add(c => c.Policies, new[] { "Read", "Write" })
            .Add(c => c.Mode, GateMode.All)
            .Add(c => c.ChildContent, C("<span>Partial</span>")));

        cut.Find("span").TextContent.Should().Be("Partial");
    }

    [Fact]
    public void Renders_Nothing_When_All_Policies_Pass_ModeAll()
    {
        TestHelpers.SetupAuthorizationService(Services, "Read", "Write");
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Cannot>(p => p
            .Add(c => c.Policies, new[] { "Read", "Write" })
            .Add(c => c.Mode, GateMode.All)
            .Add(c => c.ChildContent, C("<span>Full</span>")));

        cut.Markup.Trim().Should().BeEmpty();
    }

    [Fact]
    public void Renders_Nothing_When_Any_Policy_Passes_ModeAny()
    {
        TestHelpers.SetupAuthorizationService(Services, "Approve");
        SetupAuth(TestHelpers.AuthenticatedUser());

        var cut = Render<Cannot>(p => p
            .Add(c => c.Policies, new[] { "Manage", "Approve" })
            .Add(c => c.Mode, GateMode.Any)
            .Add(c => c.ChildContent, C("<span>Limited</span>")));

        cut.Markup.Trim().Should().BeEmpty();
    }

    // ──────────────────────────────────────────────
    // Validation
    // ──────────────────────────────────────────────

    [Fact]
    public void Throws_When_No_Requirements_Specified()
    {
        TestHelpers.SetupAuthorizationService(Services);
        SetupAuth(TestHelpers.AuthenticatedUser());

        var act = () => Render<Cannot>(p => p
            .Add(c => c.ChildContent, C("<span>Content</span>")));

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*'Cannot'*Policy*Policies*Roles*");
    }
}
