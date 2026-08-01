using Xunit;

namespace Nbpf.Core.Tests;

/// <summary>A fact that only runs on Linux; skipped (not failed) elsewhere.</summary>
public sealed class LinuxFactAttribute : FactAttribute
{
    public LinuxFactAttribute()
    {
        if (!OperatingSystem.IsLinux())
            Skip = "bpf(2) requires Linux — run via eng/test-linux.sh";
    }
}
