using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using PermissionGate;
using PermissionGate.Sample;
using PermissionGate.Sample.Auth;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

// --- Authentication (demo only) -------------------------------------------------
// A switchable in-memory provider so you can impersonate sample users at runtime.
builder.Services.AddScoped<FakeAuthenticationStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(sp =>
    sp.GetRequiredService<FakeAuthenticationStateProvider>());
builder.Services.AddCascadingAuthenticationState();

// --- Authorization policies -----------------------------------------------------
// Each policy requires a "permission" claim. Roles are checked directly by <Can Roles=..>.
builder.Services.AddAuthorizationCore(options =>
{
    options.AddPermissionPolicy("ReadPosts", "posts.read");
    options.AddPermissionPolicy("EditPosts", "posts.write");
    options.AddPermissionPolicy("DeletePosts", "posts.delete");
    options.AddPermissionPolicy("ViewReports", "reports.view");
    options.AddPermissionPolicy("ManageUsers", "users.manage");
});

// --- PermissionGate -------------------------------------------------------------
builder.Services.AddPermissionGate();

await builder.Build().RunAsync();

file static class PolicyRegistration
{
    public static void AddPermissionPolicy(this AuthorizationOptions options, string policy, string permission)
        => options.AddPolicy(policy, p => p.RequireClaim(SampleUsers.PermissionClaim, permission));
}
