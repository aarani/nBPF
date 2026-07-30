using Ebpf.Core.Insns;
using Ebpf.Core.Native;

namespace Ebpf.Core;

/// <summary>
/// A loaded BPF program. Phase 0 cut: load from a hand-assembled instruction
/// array. ELF loading (Phase 1) will layer on top of the same syscall path.
/// </summary>
public sealed class BpfProgram : IDisposable
{
    public BpfProgHandle Handle { get; }
    public BpfProgType Type { get; }

    private BpfProgram(BpfProgHandle handle, BpfProgType type)
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

    public void Dispose() => Handle.Dispose();
}
