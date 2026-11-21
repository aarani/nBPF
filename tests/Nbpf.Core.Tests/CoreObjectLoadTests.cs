using Nbpf.Btf;
using Nbpf.Core.Native;
using Nbpf.Core.ObjectFile;
using Nbpf.Elf;
using Xunit;

namespace Nbpf.Core.Tests;

/// <summary>
/// The phase 2 exit path end to end: a clang object carrying CO-RE relocations (see
/// tests/Nbpf.Elf.Tests/Fixtures/core-sample.bpf.c) relocates and loads. The
/// cross-kernel half of the exit criterion — same binary on 5.4 and 6.8 — is checked
/// offline in Nbpf.Btf.Tests' CoreReloCrossKernelTests and still needs booted 5.4/6.8
/// kernels for the live half; these prove the engine against whatever kernel runs
/// the tests.
/// </summary>
public class CoreObjectLoadTests
{
    private static byte[] Bytes { get; } =
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "core-sample.bpf.o"));

    [KernelBtfFact]
    public void A_core_object_loads_against_the_running_kernel()
    {
        // No options: the loader must find /sys/kernel/btf/vmlinux on its own and
        // relocate task_struct.pid to wherever this kernel really keeps it.
        using var obj = BpfObject.Load(Bytes);

        Assert.Contains("handle_exec", obj.Programs.Keys);
    }

    [KernelFeatureFact(ProgType = BpfProgType.Tracepoint)]
    public void A_core_object_loads_against_an_explicit_target_btf()
    {
        // The object's own BTF as the target: every relocation is an identity, so this
        // exercises the full pipeline without depending on kernel struct layouts.
        var elf = ElfReader.Read(Bytes);
        var ownBtf = BtfReader.Read(elf.FindSection(".BTF")!.Data);

        using var obj = BpfObject.Load(Bytes, new BpfLoadOptions { TargetBtf = ownBtf });

        Assert.Contains("handle_exec", obj.Programs.Keys);
    }

    [KernelFeatureTheory(ProgType = BpfProgType.Tracepoint)]
    [InlineData("5.4.0-26-generic")]
    [InlineData("6.8.0-31-generic")]
    public void The_cross_kernel_object_relocates_for_another_kernel_and_passes_the_verifier(string release)
    {
        // Relocated for a kernel other than the one running the tests: the offsets are
        // wrong for *this* kernel, but bpf_probe_read_kernel tolerates any address, so
        // the verifier only judges control flow — and each target poisons the side of
        // the state/__state rename it lacks, which must be dead code for the load to
        // succeed. See core-kernels.bpf.c and Nbpf.Btf.Tests' CoreReloCrossKernelTests.
        var bytes = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "core-kernels.bpf.o"));
        var target = BtfReader.Read(File.ReadAllBytes(
            Path.Combine(AppContext.BaseDirectory, "Fixtures", $"vmlinux-{release}.min.btf")));

        using var obj = BpfObject.Load(bytes, new BpfLoadOptions { TargetBtf = target });

        Assert.Contains("handle_exec", obj.Programs.Keys);
    }

    [KernelFeatureFact(ProgType = BpfProgType.Tracepoint)]
    public void A_target_without_the_type_poisons_the_unguarded_access()
    {
        // The phase 1 sample's BTF has no task_struct. The exists-guarded tgid access
        // compiles away, but the unguarded pid access poisons — and the verifier
        // rejects the invalid call because that path is live.
        Assert.ThrowsAny<BpfException>(() =>
            BpfObject.Load(Bytes, new BpfLoadOptions { TargetBtf = ObjectFixture.Btf }));
    }
}
