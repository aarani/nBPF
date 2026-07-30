using Ebpf.Core;
using Ebpf.Core.Insns;
using Ebpf.Core.Native;
using Xunit;

namespace Ebpf.Core.Tests;

public class RingBufTests
{
    // 64 KiB: a power-of-two multiple of the page size whether pages are 4k, 16k, or 64k.
    private const uint RingSize = 1 << 16;

    /// <summary>
    /// Hand-assembles the Phase 0 producer:
    ///   *(u64*)(fp - 8) = value
    ///   r1 = ringbuf; r2 = fp - 8; r3 = 8; r4 = 0
    ///   call bpf_ringbuf_output(ringbuf, &value, 8, 0)
    ///   r0 = 0; exit
    /// </summary>
    private static BpfProgram BuildEmitter(BpfRingBuf<ulong> rb, int value)
    {
        var (lo, hi) = Asm.LoadMapFd(Reg.R1, rb.Handle.Fd);
        ReadOnlySpan<BpfInsn> insns =
        [
            Asm.StoreDwordImm(Reg.R10, -8, value),
            lo, hi,
            Asm.MovReg(Reg.R2, Reg.R10),
            Asm.AddImm(Reg.R2, -8),
            Asm.MovImm(Reg.R3, 8),
            Asm.MovImm(Reg.R4, 0),
            Asm.CallHelper(Asm.HelperRingbufOutput),
            Asm.MovImm(Reg.R0, 0),
            Asm.Exit(),
        ];
        return BpfProgram.Load(BpfProgType.SocketFilter, insns, name: "t_rb_emit");
    }

    [Fact]
    public void Create_rejects_non_power_of_two_size()
    {
        Assert.Throws<ArgumentException>(() => BpfRingBuf<ulong>.Create(12345));
    }

    [LinuxFact]
    public void Consume_delivers_an_emitted_event()
    {
        using var rb = BpfRingBuf<ulong>.Create(RingSize, name: "t_rb");
        using var prog = BuildEmitter(rb, 0x1234ABCD);
        Span<byte> packet = stackalloc byte[64];
        Assert.Equal(0u, prog.TestRun(packet));

        ulong received = 0;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        rb.Consume((scoped ref readonly ulong e) =>
        {
            received = e;
            cts.Cancel();
        }, cts.Token);

        Assert.Equal(0x1234ABCDUL, received);
    }

    [LinuxFact]
    public async Task ReadAllAsync_streams_events()
    {
        using var rb = BpfRingBuf<ulong>.Create(RingSize);
        using var prog = BuildEmitter(rb, 7);
        prog.TestRun(new byte[64], repeat: 3);

        var events = new List<ulong>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await foreach (var e in rb.ReadAllAsync(cts.Token))
        {
            events.Add(e);
            if (events.Count == 3) break;
        }

        Assert.Equal([7UL, 7UL, 7UL], events);
    }

    [LinuxFact]
    public void Records_survive_wraparound()
    {
        using var rb = BpfRingBuf<ulong>.Create(RingSize);
        using var prog = BuildEmitter(rb, 42);
        Span<byte> packet = stackalloc byte[64];

        // Each event occupies 16 bytes (8 header + 8 payload); 3000 events are
        // 48000 bytes, so the second and third rounds cross the 64 KiB boundary.
        for (int round = 0; round < 3; round++)
        {
            prog.TestRun(packet, repeat: 3000);

            int seen = 0;
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            rb.Consume((scoped ref readonly ulong e) =>
            {
                Assert.Equal(42UL, e);
                if (++seen == 3000) cts.Cancel();
            }, cts.Token);

            Assert.Equal(3000, seen);
        }
    }

    [LinuxFact]
    public void Consume_exits_promptly_on_cancellation_with_empty_ring()
    {
        using var rb = BpfRingBuf<ulong>.Create(RingSize);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

        var sw = System.Diagnostics.Stopwatch.StartNew();
        rb.Consume((scoped ref readonly ulong _) => { }, cts.Token);
        sw.Stop();

        // The eventfd wakeup must break the epoll_wait; without it this blocks forever.
        Assert.True(sw.ElapsedMilliseconds < 5000, $"took {sw.ElapsedMilliseconds}ms");
    }
}
