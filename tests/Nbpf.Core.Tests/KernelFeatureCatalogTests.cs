using Nbpf.Core.Native;
using Xunit;

namespace Nbpf.Core.Tests;

/// <summary>Turning verifier logs and probe results into named, versioned errors — pure.</summary>
public class KernelFeatureCatalogTests
{
    [Theory]
    // An id past the end of the helper list, on any kernel.
    [InlineData("0: (85) call unknown#100000\ninvalid func unknown#100000\n", 100000)]
    // A known helper the program type doesn't offer: older kernels...
    [InlineData("0: (85) call bpf_probe_read_kernel#113\nunknown func bpf_probe_read_kernel#113\n", 113)]
    // ...and newer ones.
    [InlineData("0: (85) call bpf_probe_read_kernel#113\nprogram of this type cannot use helper bpf_probe_read_kernel#113\n", 113)]
    public void Each_kernel_wording_of_a_missing_helper_is_recognized(string log, int helper)
    {
        Assert.Equal(helper, KernelFeatureCatalog.RejectedHelper(log));
    }

    [Fact]
    public void Other_rejections_name_no_helper()
    {
        Assert.Null(KernelFeatureCatalog.RejectedHelper("0: (95) exit\nR0 !read_ok\n"));
        Assert.Null(KernelFeatureCatalog.RejectedHelper(""));
    }

    [Fact]
    public void Known_features_carry_their_release()
    {
        var e = KernelFeatureCatalog.Unsupported(BpfMapType.RingBuf, errno: 22);

        Assert.Equal("BPF_MAP_TYPE_RINGBUF", e.Feature);
        Assert.Equal("5.8", e.MinimumKernel);
        Assert.Contains("introduced in Linux 5.8", e.Message);
    }

    [Fact]
    public void Unknown_features_are_named_by_number_without_a_release()
    {
        var e = KernelFeatureCatalog.Unsupported((BpfProgType)999, errno: 22);

        Assert.Equal("BPF program type 999", e.Feature);
        Assert.Null(e.MinimumKernel);
        Assert.Equal("The running kernel does not support BPF program type 999.", e.Message);
    }
}
