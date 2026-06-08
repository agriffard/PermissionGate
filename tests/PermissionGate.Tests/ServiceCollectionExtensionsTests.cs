using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;

namespace PermissionGate.Tests;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddPermissionGate_Registers_IPermissionGate_As_Scoped()
    {
        var services = new ServiceCollection();

        services.AddPermissionGate();

        var descriptor = services.Single(d => d.ServiceType == typeof(IPermissionGate));
        descriptor.Lifetime.Should().Be(ServiceLifetime.Scoped);
        descriptor.ImplementationType.Should().Be<PermissionGateService>();
    }

    [Fact]
    public void AddPermissionGate_Returns_Same_ServiceCollection()
    {
        var services = new ServiceCollection();

        var result = services.AddPermissionGate();

        result.Should().BeSameAs(services);
    }

    [Fact]
    public void AddPermissionGate_Resolves_Working_IPermissionGate()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Substitute.For<IAuthorizationService>());
        services.AddSingleton(Substitute.For<AuthenticationStateProvider>());
        services.AddPermissionGate();

        using var provider = services.BuildServiceProvider();
        var gate = provider.GetRequiredService<IPermissionGate>();

        gate.Should().BeOfType<PermissionGateService>();
    }
}
