using Nbpf.Core.Native;
using Nbpf.Core.ObjectFile;
using Xunit;

namespace Nbpf.Core.Tests;

/// <summary>
/// Planner tests against the real clang fixture. Expected map attributes come from
/// the fixture source (sample.bpf.c) and `llvm-readelf -S` for the section sizes:
/// .rodata holds `const volatile u32 min_uid` (4 bytes), .bss holds `u64 dropped`
/// (8 bytes). Pure — no bpf(2) syscalls, so these run on any host.
/// </summary>
public class MapPlanTests
{
    private static IReadOnlyList<BpfMapSpec> Plan()
        => BpfMapPlanner.Plan(ObjectFixture.Elf, ObjectFixture.Btf);

    [Fact]
    public void Fixture_plans_two_user_maps_and_two_data_sections()
    {
        Assert.Equal(
            new[] { "events", "counts", ".rodata", ".bss" },
            Plan().Select(s => s.Name));
    }

    [Fact]
    public void Ringbuf_map_keeps_its_btf_attributes()
    {
        var events = Plan().Single(s => s.Name == "events");

        Assert.Equal(BpfMapType.RingBuf, events.Type);
        Assert.Equal(0u, events.KeySize);   // ringbuf has neither key nor value
        Assert.Equal(0u, events.ValueSize);
        Assert.Equal(4096u, events.MaxEntries);
        Assert.Null(events.InitialValue);
        Assert.False(events.Freeze);
    }

    [Fact]
    public void Hash_map_sizes_come_from_the_key_and_value_pointees()
    {
        var counts = Plan().Single(s => s.Name == "counts");

        Assert.Equal(BpfMapType.Hash, counts.Type);
        Assert.Equal(4u, counts.KeySize);   // u32 *key
        Assert.Equal(8u, counts.ValueSize); // u64 *value
        Assert.Equal(1024u, counts.MaxEntries);
    }

    [Fact]
    public void Rodata_becomes_a_frozen_readonly_single_entry_array()
    {
        var rodata = Plan().Single(s => s.Name == ".rodata");

        Assert.Equal(BpfMapType.Array, rodata.Type);
        Assert.Equal(4u, rodata.KeySize);
        Assert.Equal(4u, rodata.ValueSize); // sizeof(min_uid) — from the ELF header,
                                            // since the BTF datasec size is 0 unlinked
        Assert.Equal(1u, rodata.MaxEntries);
        Assert.Equal(BpfMapCreateFlags.RdonlyProg, rodata.Flags);
        Assert.Equal(new byte[] { 0, 0, 0, 0 }, rodata.InitialValue); // min_uid = 0
        Assert.True(rodata.Freeze);
    }

    [Fact]
    public void Bss_is_sized_from_the_header_and_needs_no_initial_write()
    {
        var bss = Plan().Single(s => s.Name == ".bss");

        Assert.Equal(BpfMapType.Array, bss.Type);
        Assert.Equal(8u, bss.ValueSize);    // sizeof(dropped); SHT_NOBITS carries no bytes
        Assert.Null(bss.InitialValue);      // kernel zero-fills array values
        Assert.Equal(BpfMapCreateFlags.None, bss.Flags);
        Assert.False(bss.Freeze);
    }

    [Fact]
    public void Maps_section_without_btf_is_rejected()
    {
        var ex = Assert.Throws<NotSupportedException>(
            () => BpfMapPlanner.Plan(ObjectFixture.Elf, btf: null));
        Assert.Contains(".maps", ex.Message);
    }
}
