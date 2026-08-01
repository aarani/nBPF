using Xunit;

namespace Nbpf.Btf.Tests;

public class BtfReaderTests
{
    [Fact]
    public void Type_ids_are_one_based_and_index_by_id()
    {
        var builder = new BtfBlobBuilder();
        var i32 = builder.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var u64 = builder.AddInt("unsigned long long", 8);

        var graph = BtfReader.Read(builder.Build());

        Assert.Equal(1, i32);
        Assert.Equal(2, u64);
        Assert.Equal(2, graph.Types.Count);
        Assert.Equal(1, graph.Types[0].Id);
        Assert.Equal(2, graph.Types[1].Id);
        Assert.Same(graph.Types[0], graph[i32]);
        Assert.Same(graph.Types[1], graph[u64]);
    }

    [Fact]
    public void Void_is_not_a_type_entry()
    {
        var builder = new BtfBlobBuilder();
        builder.AddInt("int", 4);

        var graph = BtfReader.Read(builder.Build());

        Assert.False(graph.TryGetType(0, out _));
        Assert.Throws<ArgumentOutOfRangeException>(() => graph[0]);
        Assert.Throws<ArgumentOutOfRangeException>(() => graph[99]);
    }

    [Fact]
    public void Parses_int_encoding()
    {
        var builder = new BtfBlobBuilder();
        var signed = builder.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var unsignedChar = builder.AddInt("unsigned char", 1, BtfBlobBuilder.IntEncoding.Char);
        var boolean = builder.AddInt("_Bool", 1, BtfBlobBuilder.IntEncoding.Bool);

        var graph = BtfReader.Read(builder.Build());

        var i = Assert.IsAssignableFrom<IBtfInt>(graph[signed]);
        Assert.Equal("int", i.Name);
        Assert.Equal(4, i.SizeBytes);
        Assert.Equal(32, i.Bits);
        Assert.Equal(0, i.Offset);
        Assert.True(i.IsSigned);
        Assert.False(i.IsChar);

        var c = Assert.IsAssignableFrom<IBtfInt>(graph[unsignedChar]);
        Assert.True(c.IsChar);
        Assert.False(c.IsSigned);

        var b = Assert.IsAssignableFrom<IBtfInt>(graph[boolean]);
        Assert.True(b.IsBool);
    }

    [Fact]
    public void Pointer_to_void_has_a_null_pointee()
    {
        var builder = new BtfBlobBuilder();
        var voidPtr = builder.AddPtr(0);

        var graph = BtfReader.Read(builder.Build());

        var ptr = Assert.IsAssignableFrom<IBtfPtr>(graph[voidPtr]);
        Assert.Null(ptr.Pointee);
    }

    [Fact]
    public void Const_void_pointer_resolves_through_the_qualifier_to_void()
    {
        // `const void *p` encodes as PTR -> CONST -> void.
        var builder = new BtfBlobBuilder();
        var constVoid = builder.AddConst(0);
        var ptr = builder.AddPtr(constVoid);

        var graph = BtfReader.Read(builder.Build());

        var pointer = Assert.IsAssignableFrom<IBtfPtr>(graph[ptr]);
        var qualifier = Assert.IsAssignableFrom<IBtfConst>(pointer.Pointee);
        Assert.Null(qualifier.Target);
    }

    [Fact]
    public void Resolves_forward_references()
    {
        // A typedef whose target is defined after it — legal, and the reason linking is a second pass.
        var builder = new BtfBlobBuilder();
        var alias = builder.AddTypedef("point_t", targetId: 2);
        var record = builder.AddStruct("point", 4, new BtfBlobBuilder.Member("x", 3, 0));
        builder.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);

        var graph = BtfReader.Read(builder.Build());

        var typedef = Assert.IsAssignableFrom<IBtfTypedef>(graph[alias]);
        Assert.Same(graph[record], typedef.Target);
    }

    [Fact]
    public void Parses_struct_members_with_byte_offsets()
    {
        var builder = new BtfBlobBuilder();
        var i32 = builder.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var u64 = builder.AddInt("long", 8);
        var record = builder.AddStruct("event", 16,
            new BtfBlobBuilder.Member("pid", i32, 0),
            new BtfBlobBuilder.Member("ts", u64, 64));

        var graph = BtfReader.Read(builder.Build());

        var s = Assert.IsAssignableFrom<IBtfStruct>(graph[record]);
        Assert.Equal("event", s.Name);
        Assert.Equal(16, s.SizeBytes);
        Assert.Equal(2, s.Members.Count);

        Assert.Equal("pid", s.Members[0].Name);
        Assert.Equal(0u, s.Members[0].BitOffset);
        Assert.Equal(0, s.Members[0].BitfieldSize);
        Assert.Same(graph[i32], s.Members[0].Type);

        Assert.Equal("ts", s.Members[1].Name);
        Assert.Equal(64u, s.Members[1].BitOffset);
        Assert.Same(graph[u64], s.Members[1].Type);
    }

    [Fact]
    public void Kind_flag_splits_bitfield_size_from_bit_offset()
    {
        var builder = new BtfBlobBuilder();
        var u32 = builder.AddInt("unsigned int", 4);
        var record = builder.AddStruct("flags", 4,
            new BtfBlobBuilder.Member("a", u32, BitOffset: 0, BitfieldSize: 3),
            new BtfBlobBuilder.Member("b", u32, BitOffset: 3, BitfieldSize: 5));

        var graph = BtfReader.Read(builder.Build());

        var s = Assert.IsAssignableFrom<IBtfStruct>(graph[record]);
        Assert.Equal(0u, s.Members[0].BitOffset);
        Assert.Equal(3, s.Members[0].BitfieldSize);
        Assert.Equal(3u, s.Members[1].BitOffset);
        Assert.Equal(5, s.Members[1].BitfieldSize);
    }

    [Fact]
    public void Parses_unions()
    {
        var builder = new BtfBlobBuilder();
        var i32 = builder.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var f32 = builder.AddFloat("float", 4);
        var u = builder.AddUnion("value", 4,
            new BtfBlobBuilder.Member("i", i32, 0),
            new BtfBlobBuilder.Member("f", f32, 0));

        var graph = BtfReader.Read(builder.Build());

        var union = Assert.IsAssignableFrom<IBtfUnion>(graph[u]);
        Assert.Equal(4, union.SizeBytes);
        Assert.All(union.Members, m => Assert.Equal(0u, m.BitOffset));
        Assert.Equal(4, Assert.IsAssignableFrom<IBtfFloat>(graph[f32]).SizeBytes);
    }

    [Fact]
    public void Parses_arrays()
    {
        var builder = new BtfBlobBuilder();
        var ch = builder.AddInt("char", 1, BtfBlobBuilder.IntEncoding.Char | BtfBlobBuilder.IntEncoding.Signed);
        var u32 = builder.AddInt("__ARRAY_SIZE_TYPE__", 4);
        var array = builder.AddArray(ch, u32, length: 16);

        var graph = BtfReader.Read(builder.Build());

        var a = Assert.IsAssignableFrom<IBtfArray>(graph[array]);
        Assert.Equal(16u, a.Length);
        Assert.Same(graph[ch], a.ElementType);
        Assert.Same(graph[u32], a.IndexType);
    }

    [Fact]
    public void Parses_signed_and_unsigned_enums()
    {
        var builder = new BtfBlobBuilder();
        var unsignedEnum = builder.AddEnum("color", 4, signed: false, ("RED", 0), ("GREEN", 1));
        var signedEnum = builder.AddEnum("delta", 4, signed: true, ("BACK", -1), ("FORWARD", 1));

        var graph = BtfReader.Read(builder.Build());

        var e = Assert.IsAssignableFrom<IBtfEnum>(graph[unsignedEnum]);
        Assert.False(e.IsSigned);
        Assert.Equal(["RED", "GREEN"], e.Values.Select(v => v.Name));
        Assert.Equal([0, 1], e.Values.Select(v => v.Value));

        var s = Assert.IsAssignableFrom<IBtfEnum>(graph[signedEnum]);
        Assert.True(s.IsSigned);
        Assert.Equal(-1, s.Values[0].Value);
    }

    [Fact]
    public void Parses_enum64_values_across_both_halves()
    {
        var builder = new BtfBlobBuilder();
        var big = builder.AddEnum64("mask", 8, signed: false,
            ("LOW", 0x00000000FFFFFFFFUL),
            ("HIGH", 0xFFFFFFFF00000000UL),
            ("MIXED", 0x0123456789ABCDEFUL));

        var graph = BtfReader.Read(builder.Build());

        var e = Assert.IsAssignableFrom<IBtfEnum64>(graph[big]);
        Assert.Equal(8, e.SizeBytes);
        Assert.Equal(0x00000000FFFFFFFFUL, e.Values[0].Value);
        Assert.Equal(0xFFFFFFFF00000000UL, e.Values[1].Value);
        Assert.Equal(0x0123456789ABCDEFUL, e.Values[2].Value);
    }

    [Fact]
    public void Forward_declarations_distinguish_struct_from_union()
    {
        var builder = new BtfBlobBuilder();
        var structFwd = builder.AddFwd("task_struct", isUnion: false);
        var unionFwd = builder.AddFwd("sockaddr", isUnion: true);

        var graph = BtfReader.Read(builder.Build());

        Assert.False(Assert.IsAssignableFrom<IBtfFwd>(graph[structFwd]).IsUnion);
        Assert.True(Assert.IsAssignableFrom<IBtfFwd>(graph[unionFwd]).IsUnion);
    }

    [Fact]
    public void Parses_the_qualifier_chain()
    {
        var builder = new BtfBlobBuilder();
        var i32 = builder.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var c = builder.AddConst(i32);
        var v = builder.AddVolatile(c);
        var r = builder.AddRestrict(v);
        var tag = builder.AddTypeTag("user", r);

        var graph = BtfReader.Read(builder.Build());

        var typeTag = Assert.IsAssignableFrom<IBtfTypeTag>(graph[tag]);
        Assert.Equal("user", typeTag.Name);

        var restrict = Assert.IsAssignableFrom<IBtfRestrict>(typeTag.Target);
        var volatileType = Assert.IsAssignableFrom<IBtfVolatile>(restrict.Target);
        var constType = Assert.IsAssignableFrom<IBtfConst>(volatileType.Target);
        Assert.Same(graph[i32], constType.Target);
    }

    [Fact]
    public void Parses_func_proto_with_a_vararg_and_void_return()
    {
        var builder = new BtfBlobBuilder();
        var i32 = builder.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var charPtr = builder.AddPtr(i32);
        var proto = builder.AddFuncProto(returnTypeId: 0, ("fmt", charPtr), ("", 0));
        var func = builder.AddFunc("trace_printk", proto, BtfLinkage.Static);

        var graph = BtfReader.Read(builder.Build());

        var f = Assert.IsAssignableFrom<IBtfFunc>(graph[func]);
        Assert.Equal("trace_printk", f.Name);
        Assert.Equal(BtfLinkage.Static, f.Linkage);

        Assert.Null(f.Proto.ReturnType);
        Assert.Equal(2, f.Proto.Params.Count);
        Assert.Equal("fmt", f.Proto.Params[0].Name);
        Assert.Same(graph[charPtr], f.Proto.Params[0].Type);

        // The trailing nameless, typeless parameter is the ellipsis.
        Assert.Equal("", f.Proto.Params[1].Name);
        Assert.Null(f.Proto.Params[1].Type);
    }

    [Theory]
    [InlineData(BtfLinkage.Static)]
    [InlineData(BtfLinkage.Global)]
    [InlineData(BtfLinkage.Extern)]
    public void Parses_func_linkage(BtfLinkage linkage)
    {
        var builder = new BtfBlobBuilder();
        var proto = builder.AddFuncProto(returnTypeId: 0);
        var func = builder.AddFunc("handler", proto, linkage);

        var graph = BtfReader.Read(builder.Build());

        Assert.Equal(linkage, Assert.IsAssignableFrom<IBtfFunc>(graph[func]).Linkage);
    }

    [Fact]
    public void Parses_vars_and_datasecs()
    {
        // The shape of a .rodata section carrying one config global.
        var builder = new BtfBlobBuilder();
        var u32 = builder.AddInt("unsigned int", 4);
        var min = builder.AddVar("min_uid", u32, BtfLinkage.Global);
        var rodata = builder.AddDatasec(".rodata", 4, (min, 0, 4));

        var graph = BtfReader.Read(builder.Build());

        var section = Assert.IsAssignableFrom<IBtfDatasec>(graph[rodata]);
        Assert.Equal(".rodata", section.Name);
        Assert.Equal(4u, section.SizeBytes);

        var entry = Assert.Single(section.Variables);
        Assert.Equal(0u, entry.Offset);
        Assert.Equal(4u, entry.Size);
        Assert.Equal("min_uid", entry.Variable.Name);
        Assert.Equal(BtfLinkage.Global, entry.Variable.Linkage);
        Assert.Same(graph[u32], entry.Variable.Type);
    }

    [Fact]
    public void Parses_decl_tags()
    {
        var builder = new BtfBlobBuilder();
        var u32 = builder.AddInt("unsigned int", 4);
        var record = builder.AddStruct("cfg", 4, new BtfBlobBuilder.Member("a", u32, 0));
        var wholeType = builder.AddDeclTag("tag_a", record, componentIndex: -1);
        var member = builder.AddDeclTag("tag_b", record, componentIndex: 0);

        var graph = BtfReader.Read(builder.Build());

        var onType = Assert.IsAssignableFrom<IBtfDeclTag>(graph[wholeType]);
        Assert.Equal("tag_a", onType.Value);
        Assert.Equal(-1, onType.ComponentIndex);
        Assert.Same(graph[record], onType.Target);

        Assert.Equal(0, Assert.IsAssignableFrom<IBtfDeclTag>(graph[member]).ComponentIndex);
    }

    [Fact]
    public void Find_matches_on_name_and_kind()
    {
        var builder = new BtfBlobBuilder();
        var i32 = builder.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var record = builder.AddStruct("thing", 4, new BtfBlobBuilder.Member("a", i32, 0));
        var alias = builder.AddTypedef("thing", record);

        var graph = BtfReader.Read(builder.Build());

        Assert.Same(graph[record], graph.Find("thing", BtfKind.Struct));
        Assert.Same(graph[alias], graph.Find("thing", BtfKind.Typedef));
        Assert.Null(graph.Find("thing", BtfKind.Union));
        Assert.Null(graph.Find("nope", BtfKind.Struct));
        Assert.Null(graph.Find("", BtfKind.Struct));
    }

    [Fact]
    public void Rejects_a_type_id_that_is_out_of_range()
    {
        var builder = new BtfBlobBuilder();
        builder.AddPtr(pointeeId: 999);

        var ex = Assert.Throws<BtfFormatException>(() => BtfReader.Read(builder.Build()));
        Assert.Contains("999", ex.Message);
    }

    [Fact]
    public void Rejects_void_where_a_real_type_is_required()
    {
        var builder = new BtfBlobBuilder();
        builder.AddStruct("bad", 4, new BtfBlobBuilder.Member("a", 0, 0));

        var ex = Assert.Throws<BtfFormatException>(() => BtfReader.Read(builder.Build()));
        Assert.Contains("void", ex.Message);
    }

    [Fact]
    public void Rejects_a_datasec_entry_that_is_not_a_var()
    {
        var builder = new BtfBlobBuilder();
        var u32 = builder.AddInt("unsigned int", 4);
        builder.AddDatasec(".rodata", 4, (u32, 0, 4)); // points at the INT, not at a VAR

        var ex = Assert.Throws<BtfFormatException>(() => BtfReader.Read(builder.Build()));
        Assert.Contains("Int", ex.Message);
    }

    [Fact]
    public void Rejects_an_unknown_kind()
    {
        var builder = new BtfBlobBuilder();
        builder.AddRaw("mystery", (BtfKind)30, 0, false, 0);

        var ex = Assert.Throws<BtfFormatException>(() => BtfReader.Read(builder.Build()));
        Assert.Contains("unsupported kind 30", ex.Message);
    }
}
