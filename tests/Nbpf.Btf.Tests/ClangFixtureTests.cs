using Xunit;

namespace Nbpf.Btf.Tests;

/// <summary>
/// Parses a .BTF section produced by a real clang, rather than by this repo's own encoder.
/// Every expectation here is derived from Fixtures/sample.bpf.c and the C ABI, so a bug in
/// <see cref="BtfBlobBuilder"/> cannot mask a matching bug in the parser.
/// </summary>
public class ClangFixtureTests
{
    private static readonly Lazy<IBtfTypeGraph> Fixture = new(() =>
        BtfReader.Read(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "sample.btf"))));

    private static IBtfTypeGraph Graph => Fixture.Value;

    [Fact]
    public void Parses_the_whole_blob()
    {
        Assert.NotEmpty(Graph.Types);

        // Ids are dense and 1-based across the entire section.
        for (var i = 0; i < Graph.Types.Count; i++)
            Assert.Equal(i + 1, Graph.Types[i].Id);
    }

    [Fact]
    public void Struct_event_has_the_layout_the_c_abi_dictates()
    {
        var e = Assert.IsAssignableFrom<IBtfStruct>(Graph.Find("event", BtfKind.Struct));

        Assert.Equal(64, e.SizeBytes);
        Assert.Equal(
            ["ts", "pid", "comm", "nested", "kind", "flag_x", "flag_y", "ctx", "next"],
            e.Members.Select(m => m.Name));

        // Bit offsets computed from the declaration order and natural alignment.
        Assert.Equal(
            [0u, 64u, 96u, 224u, 288u, 320u, 321u, 384u, 448u],
            e.Members.Select(m => m.BitOffset));
    }

    [Fact]
    public void Bitfield_widths_come_through_the_kind_flag()
    {
        var e = Assert.IsAssignableFrom<IBtfStruct>(Graph.Find("event", BtfKind.Struct));

        var flagX = e.Members.Single(m => m.Name == "flag_x");
        var flagY = e.Members.Single(m => m.Name == "flag_y");

        Assert.Equal(1, flagX.BitfieldSize);
        Assert.Equal(3, flagY.BitfieldSize);

        // Every non-bitfield member must report a width of zero, not a garbage top byte.
        Assert.All(
            e.Members.Where(m => m.Name is not ("flag_x" or "flag_y")),
            m => Assert.Equal(0, m.BitfieldSize));
    }

    [Fact]
    public void Typedefs_resolve_to_their_underlying_ints()
    {
        var e = Assert.IsAssignableFrom<IBtfStruct>(Graph.Find("event", BtfKind.Struct));

        var ts = Assert.IsAssignableFrom<IBtfTypedef>(e.Members.Single(m => m.Name == "ts").Type);
        Assert.Equal("u64", ts.Name);
        var u64 = Assert.IsAssignableFrom<IBtfInt>(ts.Target);
        Assert.Equal(8, u64.SizeBytes);
        Assert.False(u64.IsSigned);

        var pid = Assert.IsAssignableFrom<IBtfTypedef>(e.Members.Single(m => m.Name == "pid").Type);
        Assert.Equal("u32", pid.Name);
        Assert.Equal(4, Assert.IsAssignableFrom<IBtfInt>(pid.Target).SizeBytes);
    }

    [Fact]
    public void Char_array_member_is_an_array_of_16()
    {
        var e = Assert.IsAssignableFrom<IBtfStruct>(Graph.Find("event", BtfKind.Struct));

        var comm = Assert.IsAssignableFrom<IBtfArray>(e.Members.Single(m => m.Name == "comm").Type);
        Assert.Equal(16u, comm.Length);
        Assert.Equal("char", comm.ElementType.Name);
        Assert.Equal(1, Assert.IsAssignableFrom<IBtfInt>(comm.ElementType).SizeBytes);
    }

    [Fact]
    public void Nested_struct_is_a_real_reference_not_a_copy()
    {
        var e = Assert.IsAssignableFrom<IBtfStruct>(Graph.Find("event", BtfKind.Struct));

        var nested = Assert.IsAssignableFrom<IBtfStruct>(e.Members.Single(m => m.Name == "nested").Type);
        Assert.Same(Graph.Find("inner", BtfKind.Struct), nested);
        Assert.Equal(8, nested.SizeBytes);
        Assert.Equal(["a", "b"], nested.Members.Select(m => m.Name));
        Assert.Equal([0u, 32u], nested.Members.Select(m => m.BitOffset));
    }

    [Fact]
    public void Enum_with_a_negative_value_is_signed()
    {
        var kind = Assert.IsAssignableFrom<IBtfEnum>(Graph.Find("kind", BtfKind.Enum));

        Assert.Equal(4, kind.SizeBytes);
        Assert.True(kind.IsSigned);
        Assert.Equal(
            [("KIND_A", 0), ("KIND_B", 1), ("KIND_C", -1)],
            kind.Values.Select(v => (v.Name, v.Value)));
    }

    [Fact]
    public void Const_void_pointer_member_terminates_at_void()
    {
        // `const void *ctx` — the qualifier sits directly on void, with no type behind it.
        var e = Assert.IsAssignableFrom<IBtfStruct>(Graph.Find("event", BtfKind.Struct));

        var ctx = Assert.IsAssignableFrom<IBtfPtr>(e.Members.Single(m => m.Name == "ctx").Type);
        var qualifier = Assert.IsAssignableFrom<IBtfConst>(ctx.Pointee);
        Assert.Null(qualifier.Target);
    }

    [Fact]
    public void Self_referential_pointer_links_back_to_its_own_struct()
    {
        var e = Assert.IsAssignableFrom<IBtfStruct>(Graph.Find("event", BtfKind.Struct));

        var next = Assert.IsAssignableFrom<IBtfPtr>(e.Members.Single(m => m.Name == "next").Type);
        Assert.Same(e, next.Pointee);
    }

    [Fact]
    public void Program_function_has_a_global_linkage_and_a_prototype()
    {
        var func = Assert.IsAssignableFrom<IBtfFunc>(Graph.Find("handle_exec", BtfKind.Func));

        Assert.Equal(BtfLinkage.Global, func.Linkage);
        Assert.Equal("int", func.Proto.ReturnType?.Name);

        var parameter = Assert.Single(func.Proto.Params);
        Assert.Equal("ctx", parameter.Name);
        Assert.Null(Assert.IsAssignableFrom<IBtfPtr>(parameter.Type).Pointee); // void *
    }

    [Fact]
    public void Rodata_datasec_carries_the_const_volatile_config_global()
    {
        var rodata = Assert.IsAssignableFrom<IBtfDatasec>(Graph.Find(".rodata", BtfKind.Datasec));

        var entry = Assert.Single(rodata.Variables);
        Assert.Equal("min_uid", entry.Variable.Name);
        Assert.Equal(0u, entry.Offset);
        Assert.Equal(4u, entry.Size);
        Assert.Equal(BtfLinkage.Global, entry.Variable.Linkage);

        // `const volatile u32` — both qualifiers survive, in that order, above the typedef.
        var qualified = Assert.IsAssignableFrom<IBtfConst>(entry.Variable.Type);
        var inner = Assert.IsAssignableFrom<IBtfVolatile>(qualified.Target);
        Assert.Equal("u32", Assert.IsAssignableFrom<IBtfTypedef>(inner.Target).Name);
    }

    [Fact]
    public void Bss_datasec_carries_the_uninitialized_global()
    {
        var bss = Assert.IsAssignableFrom<IBtfDatasec>(Graph.Find(".bss", BtfKind.Datasec));

        var entry = Assert.Single(bss.Variables);
        Assert.Equal("last_event", entry.Variable.Name);
        Assert.Equal(64u, entry.Size);
        Assert.Same(Graph.Find("event", BtfKind.Struct), entry.Variable.Type);
    }

    [Fact]
    public void Datasec_sizes_are_zero_in_an_unlinked_object()
    {
        // clang leaves btf_type.size zero for DATASECs in a .o; the real size lives in the ELF
        // section header and the loader is expected to patch it in. Pinning this so the
        // relocation work in phase 1 does not quietly start trusting the BTF value.
        foreach (var name in new[] { ".rodata", ".bss", "license" })
        {
            var section = Assert.IsAssignableFrom<IBtfDatasec>(Graph.Find(name, BtfKind.Datasec));
            Assert.Equal(0u, section.SizeBytes);
            Assert.NotEmpty(section.Variables);
        }
    }

    [Fact]
    public void License_string_is_a_four_byte_char_array()
    {
        var license = Assert.IsAssignableFrom<IBtfDatasec>(Graph.Find("license", BtfKind.Datasec));

        var entry = Assert.Single(license.Variables);
        Assert.Equal("_license", entry.Variable.Name);

        var array = Assert.IsAssignableFrom<IBtfArray>(entry.Variable.Type);
        Assert.Equal(4u, array.Length); // "GPL" plus the NUL
        Assert.Equal("char", array.ElementType.Name);
    }
}
