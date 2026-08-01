using Nbpf.Core.Native;
using Nbpf.Core.ObjectFile;
using Xunit;

namespace Nbpf.Core.Tests;

/// <summary>
/// The Phase 1 exit criterion: real clang output for a tracepoint object loads
/// through the managed pipeline — maps created from BTF, global data materialized,
/// relocations applied, and the kernel verifier accepting the result.
/// </summary>
public class ObjectLoadTests
{
    [LinuxFact]
    public void Fixture_tracepoint_object_loads()
    {
        using var obj = BpfObject.Load(ObjectFixture.Bytes);

        Assert.Equal(
            ["handle_exec", "handle_open"],
            obj.Programs.Keys.Order());
        Assert.All(obj.Programs.Values, p =>
        {
            Assert.False(p.Handle.IsInvalid);
            Assert.Equal(BpfProgType.Tracepoint, p.Type);
        });

        Assert.Equal(
            [".bss", ".rodata", "counts", "events"],
            obj.Maps.Keys.Order());
        Assert.All(obj.Maps.Values, m => Assert.False(m.Handle.IsInvalid));
    }

    [LinuxFact]
    public void Rodata_map_is_frozen_against_userspace_writes()
    {
        using var obj = BpfObject.Load(ObjectFixture.Bytes);

        // BPF_MAP_FREEZE makes the kernel refuse any further userspace update with
        // EPERM — this failing write is the proof the freeze actually happened.
        var rodata = obj.Maps[".rodata"].AsTyped<uint, uint>();
        Assert.Throws<BpfPermissionException>(() => rodata.Update(0u, 1000u));
    }

    [LinuxFact]
    public void Bss_map_reads_back_zero_initialized()
    {
        using var obj = BpfObject.Load(ObjectFixture.Bytes);

        // `u64 dropped` lives at offset 0 of .bss; array map values start zeroed.
        var bss = obj.Maps[".bss"].AsTyped<uint, ulong>();
        Assert.Equal(0ul, bss[0u]);
    }

    [LinuxFact]
    public void Counts_map_round_trips_through_the_typed_view()
    {
        using var obj = BpfObject.Load(ObjectFixture.Bytes);

        var counts = obj.Maps["counts"].AsTyped<uint, ulong>();
        counts.Update(1234u, 42ul);
        Assert.Equal(42ul, counts[1234u]);
    }

    [Fact]
    public void Typed_view_rejects_mismatched_sizes()
    {
        // Pure metadata check — the size validation happens before any syscall,
        // so this runs anywhere even though it exercises the same surface.
        var spec = new BpfMapSpec(
            "counts", BpfMapType.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 1024,
            BpfMapCreateFlags.None, InitialValue: null, Freeze: false);
        var map = new BpfObjectMap(spec, new BpfMapHandle());

        Assert.Throws<ArgumentException>(() => map.AsTyped<uint, uint>());   // value too small
        Assert.Throws<ArgumentException>(() => map.AsTyped<ulong, ulong>()); // key too big
    }
}
