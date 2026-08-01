using Nbpf.Btf;
using Xunit;

namespace Nbpf.Btf.Tests;

/// <summary>
/// Tests for the ".maps" datasec decoder. The wire idiom under test is libbpf's
/// bpf_helpers.h encoding: __uint(name, v) becomes the member `int (*name)[v]`
/// (the value lives in the array length) and __type(name, t) becomes `t *name`.
/// The real-clang encoding of the same idiom is covered by the ELF fixture tests;
/// these build synthetic BTF so each rule is pinned in isolation.
/// </summary>
public class BtfMapDefTests
{
    private const uint RingBufType = 27, HashType = 1; // BPF_MAP_TYPE_* from linux/bpf.h

    /// <summary>Adds `int (*name)[length]` — the __uint(name, length) idiom.</summary>
    private static BtfBlobBuilder.Member UintMember(
        BtfBlobBuilder b, int intId, string name, uint length, uint bitOffset)
        => new(name, b.AddPtr(b.AddArray(intId, intId, length)), bitOffset);

    [Fact]
    public void Graph_without_a_maps_datasec_yields_no_defs()
    {
        var b = new BtfBlobBuilder();
        b.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);

        Assert.Empty(BtfMapDefReader.Read(BtfReader.Read(b.Build())));
    }

    [Fact]
    public void Ringbuf_def_has_type_and_max_entries_and_no_key_or_value()
    {
        var b = new BtfBlobBuilder();
        var intId = b.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var structId = b.AddStruct("", 16,
            UintMember(b, intId, "type", RingBufType, 0),
            UintMember(b, intId, "max_entries", 4096, 64));
        var varId = b.AddVar("events", structId, BtfLinkage.Global);
        b.AddDatasec(".maps", 0, (varId, 0, 16));

        var def = Assert.Single(BtfMapDefReader.Read(BtfReader.Read(b.Build())));

        Assert.Equal("events", def.Name);
        Assert.Equal(RingBufType, def.MapType);
        Assert.Equal(4096u, def.MaxEntries);
        // Ringbuf maps legitimately have neither key nor value; the loader passes 0.
        Assert.Equal(0u, def.KeySize);
        Assert.Equal(0u, def.ValueSize);
        Assert.Null(def.KeyType);
        Assert.Null(def.ValueType);
    }

    [Fact]
    public void Key_and_value_pointer_members_supply_types_and_sizes()
    {
        var b = new BtfBlobBuilder();
        var intId = b.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var u32Id = b.AddInt("unsigned int", 4);
        var u64Id = b.AddInt("unsigned long long", 8);
        var structId = b.AddStruct("", 32,
            UintMember(b, intId, "type", HashType, 0),
            UintMember(b, intId, "max_entries", 1024, 64),
            new BtfBlobBuilder.Member("key", b.AddPtr(u32Id), 128),
            new BtfBlobBuilder.Member("value", b.AddPtr(u64Id), 192));
        var varId = b.AddVar("counts", structId, BtfLinkage.Global);
        b.AddDatasec(".maps", 0, (varId, 0, 32));

        var def = Assert.Single(BtfMapDefReader.Read(BtfReader.Read(b.Build())));

        Assert.Equal(4u, def.KeySize);
        Assert.Equal(8u, def.ValueSize);
        Assert.Equal("unsigned int", def.KeyType!.Name);
        Assert.Equal("unsigned long long", def.ValueType!.Name);
    }

    [Fact]
    public void Explicit_key_size_and_value_size_are_read_and_win_over_pointees()
    {
        // Maps like perf event arrays are declared with __uint(key_size, 4) instead
        // of __type; and when both forms appear, the explicit size is authoritative.
        var b = new BtfBlobBuilder();
        var intId = b.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var u64Id = b.AddInt("unsigned long long", 8);
        var structId = b.AddStruct("", 32,
            UintMember(b, intId, "type", HashType, 0),
            UintMember(b, intId, "key_size", 16, 64),
            UintMember(b, intId, "value_size", 4, 128),
            new BtfBlobBuilder.Member("value", b.AddPtr(u64Id), 192));
        var varId = b.AddVar("m", structId, BtfLinkage.Global);
        b.AddDatasec(".maps", 0, (varId, 0, 32));

        var def = Assert.Single(BtfMapDefReader.Read(BtfReader.Read(b.Build())));

        Assert.Equal(16u, def.KeySize);
        Assert.Equal(4u, def.ValueSize); // explicit size, not the pointee's 8
        Assert.Equal("unsigned long long", def.ValueType!.Name);
    }

    [Fact]
    public void Typedefs_and_qualifiers_are_peeled_when_sizing_key_and_value()
    {
        // typedef const u32 key_t; key_t *key — sizeof must see through both.
        var b = new BtfBlobBuilder();
        var intId = b.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var u32Id = b.AddInt("unsigned int", 4);
        var keyTypedef = b.AddTypedef("key_t", b.AddConst(u32Id));
        var structId = b.AddStruct("", 24,
            UintMember(b, intId, "type", HashType, 0),
            new BtfBlobBuilder.Member("key", b.AddPtr(keyTypedef), 64),
            new BtfBlobBuilder.Member("value", b.AddPtr(u32Id), 128));
        var varId = b.AddVar("m", structId, BtfLinkage.Global);
        b.AddDatasec(".maps", 0, (varId, 0, 24));

        var def = Assert.Single(BtfMapDefReader.Read(BtfReader.Read(b.Build())));

        Assert.Equal(4u, def.KeySize);
        Assert.Equal("key_t", def.KeyType!.Name); // the declared type is preserved, not the peel
    }

    [Fact]
    public void Struct_values_are_sized_by_their_btf_size()
    {
        var b = new BtfBlobBuilder();
        var intId = b.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var u64Id = b.AddInt("unsigned long long", 8);
        var eventId = b.AddStruct("event", 24,
            new BtfBlobBuilder.Member("a", u64Id, 0),
            new BtfBlobBuilder.Member("b", u64Id, 64),
            new BtfBlobBuilder.Member("c", u64Id, 128));
        var structId = b.AddStruct("", 24,
            UintMember(b, intId, "type", HashType, 0),
            new BtfBlobBuilder.Member("key", b.AddPtr(intId), 64),
            new BtfBlobBuilder.Member("value", b.AddPtr(eventId), 128));
        var varId = b.AddVar("m", structId, BtfLinkage.Global);
        b.AddDatasec(".maps", 0, (varId, 0, 24));

        var def = Assert.Single(BtfMapDefReader.Read(BtfReader.Read(b.Build())));

        Assert.Equal(24u, def.ValueSize);
    }

    [Fact]
    public void Unknown_member_is_rejected_not_ignored()
    {
        // Silently skipping members would turn "values" (map-in-map, unsupported)
        // or a typo into a map with quietly wrong attributes.
        var b = new BtfBlobBuilder();
        var intId = b.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var structId = b.AddStruct("", 16,
            UintMember(b, intId, "type", HashType, 0),
            UintMember(b, intId, "pinning", 1, 64));
        var varId = b.AddVar("m", structId, BtfLinkage.Global);
        b.AddDatasec(".maps", 0, (varId, 0, 16));

        var ex = Assert.Throws<BtfFormatException>(
            () => BtfMapDefReader.Read(BtfReader.Read(b.Build())));
        Assert.Contains("pinning", ex.Message);
    }

    [Fact]
    public void Map_variable_that_is_not_a_struct_is_rejected()
    {
        var b = new BtfBlobBuilder();
        var intId = b.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var varId = b.AddVar("m", intId, BtfLinkage.Global);
        b.AddDatasec(".maps", 0, (varId, 0, 4));

        Assert.Throws<BtfFormatException>(() => BtfMapDefReader.Read(BtfReader.Read(b.Build())));
    }

    [Fact]
    public void Scalar_attribute_that_is_not_pointer_to_array_is_rejected()
    {
        // `int type;` instead of `int (*type)[N]` — a plain member carries no value
        // in its type, so the idiom is broken and must not decode as zero.
        var b = new BtfBlobBuilder();
        var intId = b.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var structId = b.AddStruct("", 8,
            new BtfBlobBuilder.Member("type", intId, 0));
        var varId = b.AddVar("m", structId, BtfLinkage.Global);
        b.AddDatasec(".maps", 0, (varId, 0, 8));

        var ex = Assert.Throws<BtfFormatException>(
            () => BtfMapDefReader.Read(BtfReader.Read(b.Build())));
        Assert.Contains("type", ex.Message);
    }
}
