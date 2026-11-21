using Nbpf.Core.Native;
using Xunit;

namespace Nbpf.Core.Tests;

/// <summary>
/// A Linux fact that also needs the running kernel to offer a map type and/or a
/// program type, found by the feature probes; skipped (not failed) otherwise. This is
/// what lets one suite run unchanged across kernels: on 5.4 the ring buffer tests
/// skip, and under Apple container's default kernel (no tracepoint programs) the
/// object-load tests do.
/// </summary>
public sealed class KernelFeatureFactAttribute : FactAttribute
{
    public BpfMapType MapType { get; set; }
    public BpfProgType ProgType { get; set; }

    public override string? Skip
    {
        get => base.Skip ?? KernelFeatureRequirement.SkipReason(MapType, ProgType);
        set => base.Skip = value;
    }
}

/// <summary>The <see cref="TheoryAttribute"/> form of <see cref="KernelFeatureFactAttribute"/>.</summary>
public sealed class KernelFeatureTheoryAttribute : TheoryAttribute
{
    public BpfMapType MapType { get; set; }
    public BpfProgType ProgType { get; set; }

    public override string? Skip
    {
        get => base.Skip ?? KernelFeatureRequirement.SkipReason(MapType, ProgType);
        set => base.Skip = value;
    }
}

internal static class KernelFeatureRequirement
{
    /// <summary>Unspec means "no requirement" for either kind.</summary>
    internal static string? SkipReason(BpfMapType mapType, BpfProgType progType)
    {
        if (!OperatingSystem.IsLinux())
            return LinuxOnly.Reason;
        try
        {
            if (mapType != BpfMapType.Unspec && !KernelFeatures.Running.HasMapType(mapType))
                return $"The running kernel has no {KernelFeatureCatalog.Describe(mapType)}.";
            if (progType != BpfProgType.Unspec && !KernelFeatures.Running.HasProgramType(progType))
                return $"The running kernel has no {KernelFeatureCatalog.Describe(progType)}.";
        }
        catch (BpfPermissionException e)
        {
            return $"Can't probe kernel features without BPF privileges: {e.Message}";
        }
        return null;
    }
}
