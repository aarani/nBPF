using Nbpf.Core.Insns;
using Nbpf.Core.Native;

namespace Nbpf.Core;

/// <summary>
/// A loaded BPF program. Phase 0 cut: load from a hand-assembled instruction
/// array. ELF loading (Phase 1) will layer on top of the same syscall path.
/// </summary>
public sealed class BpfProgram : IDisposable
{
    public BpfProgHandle Handle { get; }
    public BpfProgType Type { get; }

    internal BpfProgram(BpfProgHandle handle, BpfProgType type)
    {
        Handle = handle;
        Type = type;
    }

    public static BpfProgram Load(
        BpfProgType type, ReadOnlySpan<BpfInsn> insns, string license = "GPL", string? name = null)
    {
        var handle = BpfSyscall.LoadProgram(type, insns, license, name);
        return new BpfProgram(handle, type);
    }

    /// <summary>
    /// Runs the program with the given input via BPF_PROG_TEST_RUN and returns
    /// its return value. For packet program types the input must be a plausible
    /// packet (at least 14 bytes for an Ethernet header).
    /// </summary>
    public uint TestRun(ReadOnlySpan<byte> dataIn, uint repeat = 1)
        => BpfSyscall.ProgTestRun(Handle, dataIn, repeat);

    public void Dispose() => Handle.Dispose();
}
