using System.Security.Claims;

namespace PermissionGate.Sample.Auth;

/// <summary>A named sample identity selectable from the demo's user switcher.</summary>
public sealed record SampleUser(string Name, string Description, ClaimsPrincipal Principal);

/// <summary>
/// Predefined demo identities. Each carries roles and <c>permission</c> claims that
/// the policies in <c>Program.cs</c> evaluate against.
/// </summary>
public static class SampleUsers
{
    /// <summary>Custom claim type used by the permission-based policies.</summary>
    public const string PermissionClaim = "permission";

    public static readonly SampleUser Anonymous =
        new("Guest", "Not signed in — no roles, no permissions.",
            new ClaimsPrincipal(new ClaimsIdentity()));

    public static readonly SampleUser Viewer = Build(
        "Viewer", "Read-only. Can see posts and reports.",
        roles: ["Viewer"],
        permissions: ["posts.read", "reports.view"]);

    public static readonly SampleUser Editor = Build(
        "Editor", "Can read and edit posts, but not delete or manage users.",
        roles: ["Editor"],
        permissions: ["posts.read", "posts.write", "reports.view"]);

    public static readonly SampleUser Admin = Build(
        "Admin", "Full access — every role and permission.",
        roles: ["Admin", "Editor", "Viewer"],
        permissions: ["posts.read", "posts.write", "posts.delete", "reports.view", "users.manage"]);

    /// <summary>All selectable identities, in switcher order.</summary>
    public static readonly IReadOnlyList<SampleUser> All = [Anonymous, Viewer, Editor, Admin];

    private static SampleUser Build(string name, string description, string[] roles, string[] permissions)
    {
        var claims = new List<Claim> { new(ClaimTypes.Name, name) };
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));
        claims.AddRange(permissions.Select(p => new Claim(PermissionClaim, p)));

        var identity = new ClaimsIdentity(claims, authenticationType: "Demo");
        return new SampleUser(name, description, new ClaimsPrincipal(identity));
    }
}
