using Nbpf.Core.Insns;
using Nbpf.Core.Native;
using Xunit;

namespace Nbpf.Core.Tests;

/// <summary>
/// The probe_read fallback, instruction by instruction, against scripted kernels —
/// pure, so it runs on any host. The real-verifier half is in KernelFeatureTests.
/// </summary>
public class HelperFallbackTests
{
    private const int ProbeRead = 4, ProbeReadStr = 45,
                      ProbeReadUser = 112, ProbeReadKernel = 113,
                      ProbeReadUserStr = 114, ProbeReadKernelStr = 115;

    [Fact]
    public void A_missing_probe_read_kernel_becomes_probe_read()
    {
        var insns = Program(Asm.CallHelper(ProbeReadKernel));

        HelperFallbacks.Apply(BpfProgType.Tracepoint, insns, Kernel54());

        Assert.Equal(ProbeRead, insns[1].Imm);
        Assert.Equal(Asm.CallHelper(ProbeRead), insns[1]); // nothing but the id changes
    }

    [Theory]
    [InlineData(ProbeReadKernel, ProbeRead)]
    [InlineData(ProbeReadUser, ProbeRead)]
    [InlineData(ProbeReadKernelStr, ProbeReadStr)]
    [InlineData(ProbeReadUserStr, ProbeReadStr)]
    public void Each_split_variant_falls_back_to_its_combined_original(int helper, int fallback)
    {
        var insns = Program(Asm.CallHelper(helper));

        HelperFallbacks.Apply(BpfProgType.Kprobe, insns, Kernel54());

        Assert.Equal(fallback, insns[1].Imm);
    }

    [Fact]
    public void A_kernel_with_the_helper_keeps_the_call()
    {
        var insns = Program(Asm.CallHelper(ProbeReadKernel));

        HelperFallbacks.Apply(BpfProgType.Tracepoint, insns, new ScriptedKernel(ProbeRead, ProbeReadKernel));

        Assert.Equal(ProbeReadKernel, insns[1].Imm);
    }

    [Fact]
    public void A_kernel_with_neither_helper_is_reported_before_loading()
    {
        var insns = Program(Asm.CallHelper(ProbeReadKernel));

        var e = Assert.Throws<BpfFeatureUnsupportedException>(() =>
            HelperFallbacks.Apply(BpfProgType.Tracepoint, insns, new ScriptedKernel()));

        Assert.Contains("bpf_probe_read_kernel (#113)", e.Feature);
        Assert.Contains("bpf_probe_read (#4)", e.Feature);
        Assert.Equal("5.5", e.MinimumKernel);
    }

    [Fact]
    public void A_pseudo_call_with_the_same_imm_is_not_a_helper_call()
    {
        // src_reg 1 = bpf-to-bpf call; its imm (113 here) is an instruction offset.
        var pseudoCall = new BpfInsn(0x85, Reg.R0, (Reg)Asm.PseudoCall, 0, ProbeReadKernel);
        var insns = Program(pseudoCall);

        HelperFallbacks.Apply(BpfProgType.Tracepoint, insns, new ScriptedKernel(throwOnQuery: true));

        Assert.Equal(pseudoCall, insns[1]);
    }

    [Fact]
    public void A_program_without_probe_reads_never_probes()
    {
        var insns = Program(Asm.CallHelper(1), Asm.CallHelper(130));

        HelperFallbacks.Apply(BpfProgType.Tracepoint, insns, new ScriptedKernel(throwOnQuery: true));
    }

    [Fact]
    public void Each_helper_is_decided_once_per_program()
    {
        var kernel = Kernel54();
        var insns = Program(
            Asm.CallHelper(ProbeReadKernel), Asm.CallHelper(ProbeReadKernel), Asm.CallHelper(ProbeReadKernel));

        HelperFallbacks.Apply(BpfProgType.Tracepoint, insns, kernel);

        Assert.All(insns[1..4], i => Assert.Equal(ProbeRead, i.Imm));
        Assert.Equal(2, kernel.Queries); // the helper, then its fallback — not 6
    }

    [Fact]
    public void Program_types_newer_than_the_split_are_left_alone()
    {
        // BPF_PROG_TYPE_TRACING (fentry/fexit) arrived in 5.5 along with
        // bpf_probe_read_kernel, and can't be probed without an attach target anyway.
        var insns = Program(Asm.CallHelper(ProbeReadKernel));

        HelperFallbacks.Apply(BpfProgType.Tracing, insns, new ScriptedKernel(throwOnQuery: true));

        Assert.Equal(ProbeReadKernel, insns[1].Imm);
    }

    /// <summary>r0 = 0; the given calls; exit.</summary>
    private static BpfInsn[] Program(params BpfInsn[] body) =>
        [Asm.MovImm(Reg.R0, 0), .. body, Asm.Exit()];

    /// <summary>5.4 as far as these helpers go: the combined probe_reads only.</summary>
    private static ScriptedKernel Kernel54() => new(ProbeRead, ProbeReadStr);

    private sealed class ScriptedKernel(params int[] helpers) : IKernelFeatures
    {
        private readonly bool _throwOnQuery;

        public ScriptedKernel(bool throwOnQuery) : this() => _throwOnQuery = throwOnQuery;

        public int Queries { get; private set; }

        public bool HasMapType(BpfMapType type) => throw new InvalidOperationException("not scripted");
        public bool HasProgramType(BpfProgType type) => throw new InvalidOperationException("not scripted");

        public bool HasHelper(BpfProgType programType, int helperId)
        {
            if (_throwOnQuery)
                throw new InvalidOperationException($"probed helper #{helperId} unexpectedly");
            Queries++;
            return helpers.Contains(helperId);
        }
    }
}
