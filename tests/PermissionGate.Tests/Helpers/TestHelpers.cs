using Bunit;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using System.Security.Claims;
using PermissionGate.Components;

namespace PermissionGate.Tests;

/// <summary>Helper utilities shared across test classes.</summary>
internal static class TestHelpers
{
    /// <summary>Creates an authenticated <see cref="ClaimsPrincipal"/> with optional roles.</summary>
    public static ClaimsPrincipal AuthenticatedUser(params string[] roles)
    {
        var claims = roles.Select(r => new Claim(ClaimTypes.Role, r)).ToList();
        claims.Add(new Claim(ClaimTypes.Name, "testuser"));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
    }

    /// <summary>Creates an anonymous (unauthenticated) <see cref="ClaimsPrincipal"/>.</summary>
    public static ClaimsPrincipal AnonymousUser() => new ClaimsPrincipal(new ClaimsIdentity());

    /// <summary>
    /// Registers a fake <see cref="IAuthorizationService"/> that approves the given policies
    /// and rejects all others.
    /// </summary>
    public static IAuthorizationService SetupAuthorizationService(
        IServiceCollection services,
        params string[] approvedPolicies)
    {
        var authService = Substitute.For<IAuthorizationService>();

        authService
            .AuthorizeAsync(Arg.Any<ClaimsPrincipal>(), Arg.Any<object?>(), Arg.Any<string>())
            .Returns(callInfo =>
            {
                var policy = callInfo.Arg<string>();
                return approvedPolicies.Contains(policy)
                    ? Task.FromResult(AuthorizationResult.Success())
                    : Task.FromResult(AuthorizationResult.Failed());
            });

        services.AddSingleton(authService);
        return authService;
    }
}
