namespace PermissionGate;

/// <summary>
/// Determines how multiple authorization requirements are combined.
/// </summary>
public enum GateMode
{
    /// <summary>All requirements must succeed (logical AND).</summary>
    All,

    /// <summary>At least one requirement must succeed (logical OR).</summary>
    Any,
}
