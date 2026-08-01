using System.Runtime.InteropServices;

namespace Nbpf.Core.Native;

/// <summary>Minimal epoll wrapper: add fds with a token, wait for readiness.</summary>
internal sealed unsafe class Epoll : IDisposable
{
    private const int EPOLL_CLOEXEC = 0x80000;
    private const int EPOLL_CTL_ADD = 1;
    private const uint EPOLLIN = 0x1;
    private const int EINTR = 4;

    // x86-64 packs struct epoll_event to 12 bytes; every other 64-bit arch
    // naturally aligns it to 16. Getting this wrong corrupts the token.
    private static readonly bool IsPacked =
        RuntimeInformation.ProcessArchitecture is Architecture.X64 or Architecture.X86;

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct PackedEvent { public uint Events; public ulong Data; }

    [StructLayout(LayoutKind.Sequential)]
    private struct AlignedEvent { public uint Events; public ulong Data; }

    private readonly int _fd;

    public Epoll()
    {
        _fd = Libc.epoll_create1(EPOLL_CLOEXEC);
        if (_fd < 0) ThrowErrno("epoll_create1");
    }

    public void Add(int fd, ulong token)
    {
        int rc;
        if (IsPacked)
        {
            var ev = new PackedEvent { Events = EPOLLIN, Data = token };
            rc = Libc.epoll_ctl(_fd, EPOLL_CTL_ADD, fd, &ev);
        }
        else
        {
            var ev = new AlignedEvent { Events = EPOLLIN, Data = token };
            rc = Libc.epoll_ctl(_fd, EPOLL_CTL_ADD, fd, &ev);
        }
        if (rc < 0) ThrowErrno("epoll_ctl(ADD)");
    }

    /// <summary>
    /// Blocks until at least one fd is ready and writes their tokens into
    /// <paramref name="tokens"/>. Returns the ready count; 0 on EINTR.
    /// </summary>
    public int Wait(Span<ulong> tokens, int timeoutMs)
    {
        int n;
        if (IsPacked)
        {
            PackedEvent* evs = stackalloc PackedEvent[tokens.Length];
            n = Libc.epoll_wait(_fd, evs, tokens.Length, timeoutMs);
            for (int i = 0; i < n; i++) tokens[i] = evs[i].Data;
        }
        else
        {
            AlignedEvent* evs = stackalloc AlignedEvent[tokens.Length];
            n = Libc.epoll_wait(_fd, evs, tokens.Length, timeoutMs);
            for (int i = 0; i < n; i++) tokens[i] = evs[i].Data;
        }

        if (n < 0)
        {
            int errno = Marshal.GetLastPInvokeError();
            if (errno == EINTR) return 0;
            ThrowErrno("epoll_wait", errno);
        }
        return n;
    }

    public void Dispose() => Libc.close(_fd);

    private static void ThrowErrno(string what, int? errno = null)
        => throw new IOException($"{what} failed with errno {errno ?? Marshal.GetLastPInvokeError()}.");
}
