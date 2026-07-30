using System.Runtime.InteropServices;

namespace Ebpf.Core.Native;

/// <summary>Base SafeHandle over a BPF file descriptor.</summary>
public abstract partial class BpfFdHandle : SafeHandle
{
    protected BpfFdHandle() : base(invalidHandleValue: (nint)(-1), ownsHandle: true) { }

    public override bool IsInvalid => (int)handle < 0;

    /// <summary>The raw fd. Valid only while the handle is alive; do not close it yourself.</summary>
    public int Fd => (int)handle;

    internal void SetFd(int fd) => SetHandle(fd);

    protected override bool ReleaseHandle() => close((int)handle) == 0;

    [LibraryImport("libc", SetLastError = true)]
    private static partial int close(int fd);
}

public sealed class BpfMapHandle : BpfFdHandle { }
public sealed class BpfProgHandle : BpfFdHandle { }
public sealed class BpfLinkHandle : BpfFdHandle { }
