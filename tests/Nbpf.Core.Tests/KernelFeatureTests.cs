using Nbpf.Core.Insns;
using Nbpf.Core.Maps;
using Nbpf.Core.Native;
using Nbpf.Core.ObjectFile;
using Xunit;

namespace Nbpf.Core.Tests;

/// <summary>
/// The feature probes (DESIGN §4.5) against the running kernel, and the errors and
/// fallbacks built on them. Expectations hold on every kernel from the 5.4 floor up:
/// a "missing" case uses something no kernel has (an id past the end of the list, or
/// a helper no kernel offers to that program type), never something merely new.
/// </summary>
public class KernelFeatureTests
{
    private const BpfMapType NoSuchMapType = (BpfMapType)0xFFFF;
    private const BpfProgType NoSuchProgType = (BpfProgType)0xFFFF;
    private const int NoSuchHelper = 100_000;
    private const int ProbeRead = 4, ProbeReadKernel = 113;

    private static KernelFeatures Kernel => KernelFeatures.Running;

    [LinuxFact]
    public void Long_standing_map_and_program_types_are_found()
    {
        Assert.True(Kernel.HasMapType(BpfMapType.Hash));
        Assert.True(Kernel.HasMapType(BpfMapType.Array));
        Assert.True(Kernel.HasMapType(BpfMapType.LpmTrie)); // needs its special shape to probe
        Assert.True(Kernel.HasProgramType(BpfProgType.SocketFilter));
    }

    [LinuxFact]
    public void Types_no_kernel_has_are_reported_missing()
    {
        Assert.False(Kernel.HasMapType(NoSuchMapType));
        Assert.False(Kernel.HasProgramType(NoSuchProgType));
    }

    [LinuxFact]
    public void Program_types_needing_an_attach_target_are_not_probed_blind()
    {
        Assert.Throws<NotSupportedException>(() => Kernel.HasProgramType(BpfProgType.Tracing));
        Assert.Throws<NotSupportedException>(() => Kernel.HasHelper(BpfProgType.Tracing, 1));
    }

    [LinuxFact]
    public void A_helper_is_found_even_though_the_probe_program_is_invalid()
    {
        // map_lookup_elem with garbage arguments fails verification on the arguments,
        // which proves the helper itself was accepted.
        Assert.True(Kernel.HasHelper(BpfProgType.SocketFilter, 1));
        Assert.False(Kernel.HasHelper(BpfProgType.SocketFilter, NoSuchHelper));
    }

    [KernelFeatureFact(ProgType = BpfProgType.Tracepoint)]
    public void Helpers_are_probed_per_program_type()
    {
        // The legacy bpf_probe_read is a tracing-only helper on every kernel. (Its
        // 5.5 successors are not a usable example: newer kernels offer
        // bpf_probe_read_kernel to all program types via the base helper set.)
        Assert.True(Kernel.HasHelper(BpfProgType.Tracepoint, ProbeRead));
        Assert.False(Kernel.HasHelper(BpfProgType.SocketFilter, ProbeRead));
    }

    [LinuxFact]
    public void Creating_an_unknown_map_type_names_the_missing_feature()
    {
        var e = Assert.Throws<BpfFeatureUnsupportedException>(() =>
            BpfMap<uint, uint>.Create(NoSuchMapType, maxEntries: 1));

        Assert.Equal("BPF map type 65535", e.Feature);
    }

    [LinuxFact]
    public void Loading_an_unknown_program_type_names_the_missing_feature()
    {
        var e = Assert.Throws<BpfFeatureUnsupportedException>(() =>
            BpfProgram.Load(NoSuchProgType, [Asm.MovImm(Reg.R0, 0), Asm.Exit()]));

        Assert.Equal("BPF program type 65535", e.Feature);
    }

    [LinuxFact]
    public void Calling_a_helper_the_program_type_lacks_names_it_and_its_release()
    {
        var e = Assert.Throws<BpfFeatureUnsupportedException>(() =>
            BpfProgram.Load(BpfProgType.SocketFilter,
                [Asm.CallHelper(ProbeRead), Asm.MovImm(Reg.R0, 0), Asm.Exit()]));

        Assert.Equal("bpf_probe_read (#4) in BPF_PROG_TYPE_SOCKET_FILTER programs", e.Feature);
        Assert.Equal("4.1", e.MinimumKernel);
    }

    [LinuxFact]
    public void A_verifier_rejection_for_other_reasons_stays_a_verifier_error()
    {
        // r0 is never written: a program bug, not a missing feature.
        Assert.Throws<BpfVerifierException>(() =>
            BpfProgram.Load(BpfProgType.SocketFilter, [Asm.Exit()]));
    }

    [KernelFeatureFact(ProgType = BpfProgType.Tracepoint)]
    public void On_a_pre_5_5_kernel_probe_read_kernel_is_rewritten_and_still_verifies()
    {
        // The CO-RE sample calls bpf_probe_read_kernel. Told the kernel lacks it (as
        // 5.4 does), the loader must switch to bpf_probe_read — and the real verifier
        // must accept the result.
        var pre55 = new WithoutHelpers(Kernel, ProbeReadKernel);

        using var obj = BpfObject.Load(CoreSample, new BpfLoadOptions
        {
            TargetBtf = CoreSampleBtf, // identity relocations; this test is about helpers
            Features = pre55,
        });

        Assert.Contains("handle_exec", obj.Programs.Keys);
        Assert.Contains((BpfProgType.Tracepoint, ProbeReadKernel), pre55.Asked);
    }

    [KernelFeatureFact(ProgType = BpfProgType.Tracepoint)]
    public void Without_either_probe_read_the_object_is_refused_before_loading()
    {
        var e = Assert.Throws<BpfFeatureUnsupportedException>(() =>
            BpfObject.Load(CoreSample, new BpfLoadOptions
            {
                TargetBtf = CoreSampleBtf,
                Features = new WithoutHelpers(Kernel, ProbeReadKernel, ProbeRead),
            }));

        Assert.Contains("nor its pre-5.5 fallback bpf_probe_read (#4)", e.Feature);
    }

    private static byte[] CoreSample { get; } =
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "core-sample.bpf.o"));

    private static Btf.IBtfTypeGraph CoreSampleBtf =>
        Btf.BtfReader.Read(Elf.ElfReader.Read(CoreSample).FindSection(".BTF")!.Data);

    /// <summary>The running kernel, minus some helpers — an older kernel, as far as
    /// the fallbacks can tell.</summary>
    private sealed class WithoutHelpers(IKernelFeatures inner, params int[] missing) : IKernelFeatures
    {
        public List<(BpfProgType, int)> Asked { get; } = [];

        public bool HasMapType(BpfMapType type) => inner.HasMapType(type);
        public bool HasProgramType(BpfProgType type) => inner.HasProgramType(type);

        public bool HasHelper(BpfProgType programType, int helperId)
        {
            Asked.Add((programType, helperId));
            return !missing.Contains(helperId) && inner.HasHelper(programType, helperId);
        }
    }
}
