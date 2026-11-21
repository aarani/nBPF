using Nbpf.Core.Maps;
using Nbpf.Core.Native;
using Xunit;

namespace Nbpf.Core.Tests;

/// <summary>
/// The RLIMIT_MEMLOCK bump (see <see cref="MemlockLimit"/>). It only does something
/// on kernels before 5.11, so the real check is the live 5.4 run in QEMU, where the
/// guest starts with the kernel's 64 KiB default. Before the bump, the suite passed
/// there only because every test map fit in that.
/// </summary>
public class MemlockLimitTests
{
    [LinuxFact]
    public void A_map_far_beyond_the_default_limit_creates_on_any_kernel()
    {
        // 1 Mi entries of 8 bytes: 8 MiB of values, 128x the 64 KiB default.
        using var map = BpfMap<uint, ulong>.Create(BpfMapType.Array, maxEntries: 1 << 20);

        Assert.False(map.Handle.IsInvalid);
    }

    [LinuxFact]
    public void The_limit_is_raised_exactly_where_the_kernel_charges_it()
    {
        using var _ = BpfMap<uint, ulong>.Create(BpfMapType.Array, maxEntries: 1);

        bool memcgAccounting = KernelFeatures.Running.HasHelper(BpfProgType.CgroupSkb, 160);
        Assert.Equal(memcgAccounting ? MemlockLimit.Outcome.NotNeeded : MemlockLimit.Outcome.Raised,
                     MemlockLimit.Result);

        if (!memcgAccounting)
        {
            Assert.Equal(0, Libc.getrlimit(Libc.RLIMIT_MEMLOCK, out var limit));
            Assert.Equal(Libc.RLIM_INFINITY, limit.Current);
        }
    }
}
