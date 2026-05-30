using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using NSubstitute;
using System.Security.Claims;

namespace PermissionGate.Tests;

public class PermissionGateServiceTests
{
    private readonly IAuthorizationService _authService;
    private readonly AuthenticationStateProvider _authStateProvider;
    private readonly IPermissionGate _gate;

    public PermissionGateServiceTests()
    {
        _authService = Substitute.For<IAuthorizationService>();
        _authStateProvider = Substitute.For<AuthenticationStateProvider>();

        var user = new ClaimsPrincipal(
            new ClaimsIdentity(
                [new Claim(ClaimTypes.Role, "Admin"), new Claim(ClaimTypes.Role, "Editor")],
                "test"));

        _authStateProvider
            .GetAuthenticationStateAsync()
            .Returns(Task.FromResult(new AuthenticationState(user)));

        _gate = new PermissionGateService(_authService, _authStateProvider);
    }

    // ──────────────────────────────────────────────
    // CanAsync
    // ──────────────────────────────────────────────

    [Fact]
    public async Task CanAsync_Returns_True_When_Policy_Succeeds()
    {
        _authService
            .AuthorizeAsync(Arg.Any<ClaimsPrincipal>(), Arg.Is<object?>(x => x == null), Arg.Is<string>(s => s == "Edit"))
            .Returns(Task.FromResult(AuthorizationResult.Success()));

        var result = await _gate.CanAsync("Edit");

        result.Should().BeTrue();
    }

    [Fact]
    public async Task CanAsync_Returns_False_When_Policy_Fails()
    {
        _authService
            .AuthorizeAsync(Arg.Any<ClaimsPrincipal>(), Arg.Is<object?>(x => x == null), Arg.Is<string>(s => s == "Delete"))
            .Returns(Task.FromResult(AuthorizationResult.Failed()));

        var result = await _gate.CanAsync("Delete");

        result.Should().BeFalse();
    }

    [Fact]
    public async Task CanAsync_Forwards_Resource_To_AuthorizationService()
    {
        var resource = new { Id = 99 };
        _authService
            .AuthorizeAsync(Arg.Any<ClaimsPrincipal>(), resource, "Edit")
            .Returns(Task.FromResult(AuthorizationResult.Success()));

        await _gate.CanAsync("Edit", resource);

        await _authService.Received(1)
            .AuthorizeAsync(Arg.Any<ClaimsPrincipal>(), resource, "Edit");
    }

    // ──────────────────────────────────────────────
    // CanAllAsync
    // ──────────────────────────────────────────────

    [Fact]
    public async Task CanAllAsync_Returns_True_When_All_Policies_Succeed()
    {
        _authService
            .AuthorizeAsync(Arg.Any<ClaimsPrincipal>(), Arg.Any<object?>(), Arg.Any<string>())
            .Returns(Task.FromResult(AuthorizationResult.Success()));

        var result = await _gate.CanAllAsync(["Read", "Write"]);

        result.Should().BeTrue();
    }

    [Fact]
    public async Task CanAllAsync_Returns_False_When_Any_Policy_Fails()
    {
        _authService
            .AuthorizeAsync(Arg.Any<ClaimsPrincipal>(), Arg.Any<object?>(), Arg.Any<string>())
            .Returns(callInfo =>
            {
                var policy = callInfo.Arg<string>();
                return policy == "Read"
                    ? Task.FromResult(AuthorizationResult.Success())
                    : Task.FromResult(AuthorizationResult.Failed());
            });

        var result = await _gate.CanAllAsync(["Read", "Write"]);

        result.Should().BeFalse();
    }

    // ──────────────────────────────────────────────
    // CanAnyAsync
    // ──────────────────────────────────────────────

    [Fact]
    public async Task CanAnyAsync_Returns_True_When_Any_Policy_Succeeds()
    {
        _authService
            .AuthorizeAsync(Arg.Any<ClaimsPrincipal>(), Arg.Any<object?>(), Arg.Any<string>())
            .Returns(callInfo =>
            {
                var policy = callInfo.Arg<string>();
                return policy == "Approve"
                    ? Task.FromResult(AuthorizationResult.Success())
                    : Task.FromResult(AuthorizationResult.Failed());
            });

        var result = await _gate.CanAnyAsync(["Manage", "Approve"]);

        result.Should().BeTrue();
    }

    [Fact]
    public async Task CanAnyAsync_Returns_False_When_All_Policies_Fail()
    {
        _authService
            .AuthorizeAsync(Arg.Any<ClaimsPrincipal>(), Arg.Any<object?>(), Arg.Any<string>())
            .Returns(Task.FromResult(AuthorizationResult.Failed()));

        var result = await _gate.CanAnyAsync(["Manage", "Approve"]);

        result.Should().BeFalse();
    }

    // ──────────────────────────────────────────────
    // IsInRoleAsync
    // ──────────────────────────────────────────────

    [Fact]
    public async Task IsInRoleAsync_Returns_True_When_User_Has_Role()
    {
        var result = await _gate.IsInRoleAsync("Admin");

        result.Should().BeTrue();
    }

    [Fact]
    public async Task IsInRoleAsync_Returns_False_When_User_Lacks_Role()
    {
        var result = await _gate.IsInRoleAsync("SuperAdmin");

        result.Should().BeFalse();
    }
}
