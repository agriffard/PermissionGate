# PermissionGate

Declarative authorization components and an imperative service for ASP.NET Core Blazor, built on top of `IAuthorizationService`.

> ⚠️ **Security notice — UI only**
> `<Can>`, `<Cannot>`, and `IPermissionGate` control what users *see*, not what they can *do*.
> They are **not** a substitute for server-side authorization.
> Always protect your API endpoints and server-side actions with proper authorization attributes or middleware.

---

## Installation

```bash
dotnet add package PermissionGate
```

Register the service in your DI container (requires `AddAuthorizationCore` and a `CascadingAuthenticationState`):

```csharp
// Program.cs
builder.Services.AddAuthorizationCore();
builder.Services.AddPermissionGate();
```

Add the cascading authentication state to your `App.razor` (or `Routes.razor`):

```razor
<CascadingAuthenticationState>
    <Router AppAssembly="@typeof(App).Assembly">
        ...
    </Router>
</CascadingAuthenticationState>
```

---

## Components

### `<Can>` — render when authorized

Shows `ChildContent` when the user satisfies the specified requirements.
The optional `Else` parameter renders when the user is denied.

```razor
@* Policy *@
<Can Policy="EditPost">
    <button>Edit</button>
</Can>

@* Policy with an Else branch *@
<Can Policy="EditPost">
    <button>Edit</button>
    <Else>
        <span>Read-only</span>
    </Else>
</Can>

@* Roles — any matching role is sufficient *@
<Can Roles="Admin, Editor">
    <NavLink href="/admin">Admin panel</NavLink>
</Can>

@* Multiple policies — all must pass (default) *@
<Can Policies="@(new[] { "Read", "Write" })" Mode="GateMode.All">
    <button>Save</button>
</Can>

@* Multiple policies — any one passing is sufficient *@
<Can Policies="@(new[] { "Approve", "Manage" })" Mode="GateMode.Any">
    <button>Approve</button>
</Can>

@* Access the AuthenticationState via @context *@
<Can Policy="ViewProfile">
    Hello, @context.User.Identity?.Name!
</Can>

@* Resource-based authorization *@
<Can Policy="EditPost" Resource="@myPost">
    <button>Edit</button>
</Can>
```

### `<Cannot>` — render when denied

The inverse of `<Can>`. Shows `ChildContent` when the user **does not** satisfy the requirements.

```razor
<Cannot Policy="ManageUsers">
    <span>You do not have permission to manage users.</span>
</Cannot>

<Cannot Roles="Admin">
    <p>Upgrade your account to access this feature.</p>
</Cannot>
```

### Parameters (both components)

| Parameter  | Type              | Description                                             |
|------------|-------------------|---------------------------------------------------------|
| `Policy`   | `string?`         | A single authorization policy name                      |
| `Policies` | `string[]?`       | Multiple policy names, evaluated with `Mode`            |
| `Mode`     | `GateMode`        | `GateMode.All` (default) or `GateMode.Any`              |
| `Roles`    | `string?`         | Comma-separated role names (any matching role passes)   |
| `Resource` | `object?`         | Resource forwarded to `IAuthorizationService`           |
| `ChildContent` | `RenderFragment<AuthenticationState>` | Content to render when condition is met |
| `Else`     | `RenderFragment?` | (`<Can>` only) Rendered when denied                     |
| `Authorizing` | `RenderFragment?` | Shown while the auth state is loading                |

At least one of `Policy`, `Policies`, or `Roles` must be specified.

---

## Imperative service

Inject `IPermissionGate` for programmatic checks in C# code:

```csharp
@inject IPermissionGate Gate

@code {
    protected override async Task OnInitializedAsync()
    {
        if (await Gate.CanAsync("EditPost"))
        {
            // show edit UI
        }

        // Multiple policies — all must pass
        bool canReadAndWrite = await Gate.CanAllAsync(new[] { "Read", "Write" });

        // Multiple policies — any must pass
        bool canApproveOrManage = await Gate.CanAnyAsync(new[] { "Approve", "Manage" });

        // Role check
        bool isAdmin = await Gate.IsInRoleAsync("Admin");

        // Resource-based
        bool canEdit = await Gate.CanAsync("EditPost", resource: myPost);
    }
}
```

### `IPermissionGate` API

| Method | Description |
|--------|-------------|
| `CanAsync(policy, resource?)` | Returns `true` when the current user satisfies `policy` |
| `CanAllAsync(policies, resource?)` | Returns `true` when all policies pass |
| `CanAnyAsync(policies, resource?)` | Returns `true` when at least one policy passes |
| `IsInRoleAsync(role)` | Returns `true` when the current user is in `role` |

---

## `GateMode` enum

| Value | Description |
|-------|-------------|
| `All` | All specified policies must pass (default) |
| `Any` | At least one policy must pass |

---

## Prerequisites

- .NET 10 or later
- `Microsoft.AspNetCore.Components.Authorization` (transitively included)
- Authorization policies registered via `AddAuthorizationCore()` / `AddAuthorization()`
- `CascadingAuthenticationState` in the Blazor component tree

## License

MIT
