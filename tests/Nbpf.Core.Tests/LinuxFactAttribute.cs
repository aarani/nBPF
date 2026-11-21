using Xunit;

namespace Nbpf.Core.Tests;

/// <summary>A fact that only runs on Linux; skipped (not failed) elsewhere.</summary>
public sealed class LinuxFactAttribute : FactAttribute
{
    public LinuxFactAttribute()
    {
        if (!OperatingSystem.IsLinux())
            Skip = LinuxOnly.Reason;
    }
}

/// <summary>A theory that only runs on Linux; skipped (not failed) elsewhere.</summary>
public sealed class LinuxTheoryAttribute : TheoryAttribute
{
    public LinuxTheoryAttribute()
    {
        if (!OperatingSystem.IsLinux())
            Skip = LinuxOnly.Reason;
    }
}

internal static class LinuxOnly
{
    internal const string Reason = "bpf(2) requires Linux — run via eng/test-linux.sh";
}
