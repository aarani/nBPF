using System.Runtime.InteropServices;

namespace Nbpf.Core.Native;

/// <summary>Raw libc wrappers for the mmap/epoll/eventfd plumbing the ring buffer needs.</summary>
internal static unsafe partial class Libc
{
    internal const int PROT_READ = 0x1, PROT_WRITE = 0x2;
    private const int MAP_SHARED = 0x01;
    private const int EFD_NONBLOCK = 0x800, EFD_CLOEXEC = 0x80000;

    [LibraryImport("libc", SetLastError = true)]
    private static partial void* mmap(void* addr, nuint length, int prot, int flags, int fd, long offset);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int munmap(void* addr, nuint length);

    [LibraryImport("libc", SetLastError = true)]
    internal static partial int epoll_create1(int flags);

    [LibraryImport("libc", SetLastError = true)]
    internal static partial int epoll_ctl(int epfd, int op, int fd, void* ev);

    [LibraryImport("libc", SetLastError = true)]
    internal static partial int epoll_wait(int epfd, void* events, int maxEvents, int timeoutMs);

    [LibraryImport("libc", SetLastError = true)]
    private static partial int eventfd(uint initval, int flags);

    [LibraryImport("libc", SetLastError = true)]
    internal static partial long read(int fd, void* buf, nuint count);

    [LibraryImport("libc", SetLastError = true)]
    internal static partial long write(int fd, void* buf, nuint count);

    [LibraryImport("libc", SetLastError = true)]
    internal static partial int close(int fd);

    internal static void* Mmap(nuint length, int prot, int fd, long offset)
    {
        void* p = mmap(null, length, prot, MAP_SHARED, fd, offset);
        if (p == (void*)(-1))
            throw new IOException($"mmap({length} bytes, offset {offset}) failed with errno {Marshal.GetLastPInvokeError()}.");
        return p;
    }

    internal static void Munmap(void* addr, nuint length) => munmap(addr, length);

    internal static int EventFd()
    {
        int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (fd < 0)
            throw new IOException($"eventfd failed with errno {Marshal.GetLastPInvokeError()}.");
        return fd;
    }
}
