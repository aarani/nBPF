using Xunit;

namespace Nbpf.Core.Tests;

/// <summary>
/// A fact that needs a kernel exposing its own BTF, not just Linux; skipped (not
/// failed) elsewhere. Notably, Docker Desktop's linuxkit kernel ships without
/// CONFIG_DEBUG_INFO_BTF, so these skip in local container runs and rely on CI's
/// Ubuntu kernel for coverage.
/// </summary>
public sealed class KernelBtfFactAttribute : FactAttribute
{
    public KernelBtfFactAttribute()
    {
        if (!OperatingSystem.IsLinux())
            Skip = "bpf(2) requires Linux — run via eng/test-linux.sh";
        else if (!File.Exists(KernelBtf.VmlinuxPath))
            Skip = $"This kernel does not expose {KernelBtf.VmlinuxPath} (CONFIG_DEBUG_INFO_BTF).";
    }
}
