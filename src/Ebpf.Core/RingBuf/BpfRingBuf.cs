using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Ebpf.Core.Native;

namespace Ebpf.Core;

/// <summary>
/// Zero-copy record handler. The ref points directly into the mmap'd ring;
/// <c>scoped</c> makes escaping it past the callback a compile error.
/// </summary>
public delegate void RingBufferHandler<T>(scoped ref readonly T record) where T : unmanaged;

/// <summary>
/// A BPF_MAP_TYPE_RINGBUF map plus its user-space consumer (single shared MPSC
/// ring, kernel 5.8+). Single consumer at a time.
/// </summary>
public sealed unsafe class BpfRingBuf<TEvent> : IDisposable where TEvent : unmanaged
{
    private const uint BusyBit = 1u << 31;
    private const uint DiscardBit = 1u << 30;
    private const uint LenMask = (1u << 30) - 1;
    private const int HeaderSize = 8;
    private const ulong DataToken = 0, WakeupToken = 1;

    public BpfMapHandle Handle { get; }

    /// <summary>Data area size in bytes.</summary>
    public uint Size { get; }

    private readonly byte* _consumerPage;  // RW; consumer_pos lives at offset 0
    private readonly byte* _producerPages; // RO; producer_pos at offset 0, data area one page in
    private readonly byte* _data;
    private readonly nuint _consumerLen, _producerLen;
    private readonly ulong _mask;
    private readonly Epoll _epoll;
    private readonly int _eventFd;
    private int _consuming;
    private bool _disposed;

    public static BpfRingBuf<TEvent> Create(uint sizeBytes, string? name = null)
    {
        int page = Environment.SystemPageSize;
        if (sizeBytes == 0 || (sizeBytes & (sizeBytes - 1)) != 0 || sizeBytes % (uint)page != 0)
            throw new ArgumentException(
                $"Ring buffer size must be a power-of-two multiple of the page size ({page}); got {sizeBytes}.",
                nameof(sizeBytes));

        var handle = BpfSyscall.CreateMap(BpfMapType.RingBuf, keySize: 0, valueSize: 0, sizeBytes, flags: 0, name);
        try
        {
            return new BpfRingBuf<TEvent>(handle, sizeBytes);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private BpfRingBuf(BpfMapHandle handle, uint size)
    {
        Handle = handle;
        Size = size;
        _mask = size - 1;

        nuint page = (nuint)Environment.SystemPageSize;
        _consumerLen = page;
        // The kernel maps the data area twice back-to-back here, so a record
        // that wraps the ring end is still contiguous in our address space.
        _producerLen = page + 2 * (nuint)size;

        try
        {
            _consumerPage = (byte*)Libc.Mmap(_consumerLen, Libc.PROT_READ | Libc.PROT_WRITE, handle.Fd, offset: 0);
            _producerPages = (byte*)Libc.Mmap(_producerLen, Libc.PROT_READ, handle.Fd, offset: (long)page);
            _data = _producerPages + page;

            _eventFd = Libc.EventFd();
            _epoll = new Epoll();
            _epoll.Add(handle.Fd, DataToken);
            _epoll.Add(_eventFd, WakeupToken);
        }
        catch
        {
            ReleaseNative();
            throw;
        }
    }

    /// <summary>
    /// Consumes records zero-copy on the calling thread until the token is
    /// cancelled. Blocks in epoll_wait while the ring is empty.
    /// </summary>
    public void Consume(RingBufferHandler<TEvent> handler, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Interlocked.Exchange(ref _consuming, 1) != 0)
            throw new InvalidOperationException("BpfRingBuf supports one concurrent consumer.");
        try
        {
            using var reg = ct.Register(SignalWakeup);
            while (!ct.IsCancellationRequested)
            {
                Drain(handler, ct);
                if (ct.IsCancellationRequested) break;
                WaitForData();
            }
        }
        finally
        {
            Volatile.Write(ref _consuming, 0);
        }
    }

    /// <summary>
    /// Copies records out as an async stream. The epoll loop runs on a
    /// dedicated thread (a pool thread blocked in epoll_wait is a stolen pool
    /// thread); the enumeration ends when the token is cancelled or the
    /// enumerator is disposed.
    /// </summary>
    public async IAsyncEnumerable<TEvent> ReadAllAsync([EnumeratorCancellation] CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var channel = Channel.CreateUnbounded<TEvent>(
            new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var thread = new Thread(() =>
        {
            try
            {
                Consume((scoped ref readonly TEvent e) => channel.Writer.TryWrite(e), linked.Token);
                channel.Writer.TryComplete();
            }
            catch (Exception ex)
            {
                channel.Writer.TryComplete(ex);
            }
        })
        { IsBackground = true, Name = "nbpf-ringbuf-consumer" };
        thread.Start();

        try
        {
            while (await channel.Reader.WaitToReadAsync(CancellationToken.None).ConfigureAwait(false))
            {
                while (channel.Reader.TryRead(out var e))
                    yield return e;
            }
        }
        finally
        {
            linked.Cancel();
            thread.Join();
        }
    }

    /// <summary>libbpf's ring__process loop: drain until empty or a producer is mid-write.</summary>
    private void Drain(RingBufferHandler<TEvent> handler, CancellationToken ct)
    {
        ref ulong consumerPos = ref Unsafe.AsRef<ulong>(_consumerPage);
        ref ulong producerPos = ref Unsafe.AsRef<ulong>(_producerPages);

        ulong cons = Volatile.Read(ref consumerPos);
        for (;;)
        {
            ulong prod = Volatile.Read(ref producerPos);
            if (cons >= prod) return;

            while (cons < prod)
            {
                if (ct.IsCancellationRequested) return;

                byte* record = _data + (cons & _mask);
                uint header = Volatile.Read(ref Unsafe.AsRef<uint>(record));
                if ((header & BusyBit) != 0)
                    return; // producer reserved but not yet submitted; epoll fires on submit

                uint sampleLen = header & LenMask;
                cons += (HeaderSize + sampleLen + 7ul) & ~7ul;

                if ((header & DiscardBit) == 0)
                {
                    if (sampleLen != (uint)sizeof(TEvent))
                        throw new InvalidOperationException(
                            $"Ring buffer record is {sampleLen} bytes but {typeof(TEvent).Name} is {sizeof(TEvent)} — " +
                            "the producer and consumer disagree on the event type.");
                    handler(in Unsafe.AsRef<TEvent>(record + HeaderSize));
                }

                // Publish our progress; this is what lets the kernel reuse the space.
                Volatile.Write(ref consumerPos, cons);
            }
        }
    }

    private void WaitForData()
    {
        Span<ulong> tokens = stackalloc ulong[2];
        int n = _epoll.Wait(tokens, timeoutMs: -1);
        for (int i = 0; i < n; i++)
        {
            if (tokens[i] == WakeupToken)
                DrainWakeupFd();
        }
    }

    private void SignalWakeup()
    {
        ulong one = 1;
        Libc.write(_eventFd, &one, sizeof(ulong));
    }

    private void DrainWakeupFd()
    {
        ulong counter;
        Libc.read(_eventFd, &counter, sizeof(ulong)); // EFD_NONBLOCK: EAGAIN is fine
    }

    private void ReleaseNative()
    {
        if (_consumerPage != null) Libc.Munmap(_consumerPage, _consumerLen);
        if (_producerPages != null) Libc.Munmap(_producerPages, _producerLen);
        _epoll?.Dispose();
        if (_eventFd > 0) Libc.close(_eventFd);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        ReleaseNative();
        Handle.Dispose();
    }
}
