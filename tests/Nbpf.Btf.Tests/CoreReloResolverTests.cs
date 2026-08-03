using Xunit;
using Member = Nbpf.Btf.Tests.BtfBlobBuilder.Member;

namespace Nbpf.Btf.Tests;

/// <summary>
/// Pins the CO-RE resolution semantics to libbpf's relo_core.c, case by case. Local and
/// target graphs are built independently, the way a compiled object and a running
/// kernel's vmlinux BTF are unrelated blobs that only agree on names.
/// </summary>
public class CoreReloResolverTests
{
    private static CoreReloResult Resolve(
        BtfBlobBuilder local, int typeId, string access, BtfCoreReloKind kind,
        BtfBlobBuilder target)
        => new CoreReloResolver().Resolve(
            new BtfCoreRelo(0, (uint)typeId, access, kind),
            BtfReader.Read(local.Build()),
            BtfReader.Read(target.Build()));

    // ---- field byte offset -------------------------------------------------------

    [Fact]
    public void Identical_layouts_resolve_to_the_local_offset()
    {
        var local = new BtfBlobBuilder();
        var lint = local.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var ls = local.AddStruct("task", 8, new Member("pid", lint, 0), new Member("tgid", lint, 32));

        var target = new BtfBlobBuilder();
        var tint = target.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        target.AddStruct("task", 8, new Member("pid", tint, 0), new Member("tgid", tint, 32));

        var result = Resolve(local, ls, "0:1", BtfCoreReloKind.FieldByteOffset, target);

        Assert.Equal(new CoreReloResult(4, 4, Poison: false, Validate: true), result);
    }

    [Fact]
    public void Members_are_matched_by_name_not_by_position()
    {
        var local = new BtfBlobBuilder();
        var lint = local.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var ls = local.AddStruct("task", 8, new Member("pid", lint, 0), new Member("tgid", lint, 32));

        // tgid moved from member 1 at byte 4 to member 2 at byte 12.
        var target = new BtfBlobBuilder();
        var tint = target.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var tlong = target.AddInt("long", 8, BtfBlobBuilder.IntEncoding.Signed);
        target.AddStruct("task", 16,
            new Member("pad", tlong, 0), new Member("pid", tint, 64), new Member("tgid", tint, 96));

        var result = Resolve(local, ls, "0:1", BtfCoreReloKind.FieldByteOffset, target);

        Assert.Equal(new CoreReloResult(4, 12, Poison: false, Validate: true), result);
    }

    [Fact]
    public void Nested_members_resolve_through_every_level()
    {
        var local = new BtfBlobBuilder();
        var lu32 = local.AddInt("u32", 4);
        var linner = local.AddStruct("inner", 8, new Member("a", lu32, 0), new Member("b", lu32, 32));
        var louter = local.AddStruct("outer", 12, new Member("in", linner, 0), new Member("c", lu32, 64));

        // inner.b moved to byte 8 within inner, and outer.in moved to byte 8: total 16.
        var target = new BtfBlobBuilder();
        var tu32 = target.AddInt("u32", 4);
        var tu64 = target.AddInt("u64", 8);
        var tinner = target.AddStruct("inner", 12,
            new Member("a", tu32, 0), new Member("pad", tu32, 32), new Member("b", tu32, 64));
        target.AddStruct("outer", 24, new Member("pad2", tu64, 0), new Member("in", tinner, 64));

        var result = Resolve(local, louter, "0:0:1", BtfCoreReloKind.FieldByteOffset, target);

        Assert.Equal(new CoreReloResult(4, 16, Poison: false, Validate: true), result);
    }

    [Fact]
    public void Anonymous_members_on_the_target_side_are_searched_transparently()
    {
        var local = new BtfBlobBuilder();
        var lint = local.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var ls = local.AddStruct("s", 4, new Member("a", lint, 0));

        // The target buries `a` inside an anonymous struct, one int deep.
        var target = new BtfBlobBuilder();
        var tint = target.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var anon = target.AddStruct("", 8, new Member("x", tint, 0), new Member("a", tint, 32));
        target.AddStruct("s", 8, new Member("", anon, 0));

        var result = Resolve(local, ls, "0:0", BtfCoreReloKind.FieldByteOffset, target);

        Assert.Equal(new CoreReloResult(0, 4, Poison: false, Validate: true), result);
    }

    [Fact]
    public void Anonymous_members_on_the_local_side_collapse_out_of_the_spec()
    {
        // Local `a` sits inside an anonymous struct, so clang's raw spec has an extra
        // index ("0:0:0") — the anonymous step contributes no named accessor and the
        // target is matched on `a` alone.
        var local = new BtfBlobBuilder();
        var lint = local.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var anon = local.AddStruct("", 4, new Member("a", lint, 0));
        var ls = local.AddStruct("s", 4, new Member("", anon, 0));

        var target = new BtfBlobBuilder();
        var tint = target.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        target.AddStruct("s", 8, new Member("pad", tint, 0), new Member("a", tint, 32));

        var result = Resolve(local, ls, "0:0:0", BtfCoreReloKind.FieldByteOffset, target);

        Assert.Equal(new CoreReloResult(0, 4, Poison: false, Validate: true), result);
    }

    [Fact]
    public void Typedefs_and_qualifiers_on_the_target_member_are_skipped()
    {
        var local = new BtfBlobBuilder();
        var lu32 = local.AddInt("u32", 4);
        var lu64 = local.AddInt("u64", 8);
        var ls = local.AddStruct("s", 12, new Member("pad", lu64, 0), new Member("a", lu32, 64));

        // Target `a` is const my_u32 — the wrappers must not defeat int-vs-int compat.
        var target = new BtfBlobBuilder();
        var tu32 = target.AddInt("u32", 4);
        var tu64 = target.AddInt("u64", 8);
        var tdef = target.AddTypedef("my_u32", tu32);
        var tconst = target.AddConst(tdef);
        target.AddStruct("s", 20,
            new Member("pad", tu64, 0), new Member("pad2", tu64, 64), new Member("a", tconst, 128));

        var result = Resolve(local, ls, "0:1", BtfCoreReloKind.FieldByteOffset, target);

        Assert.Equal(new CoreReloResult(8, 16, Poison: false, Validate: true), result);
    }

    [Fact]
    public void Array_elements_scale_by_the_target_element_size()
    {
        var local = new BtfBlobBuilder();
        var lu32 = local.AddInt("u32", 4);
        var larr = local.AddArray(lu32, lu32, 8);
        var ls = local.AddStruct("s", 32, new Member("vals", larr, 0));

        // Same field, but the target widened the elements to u64.
        var target = new BtfBlobBuilder();
        var tu32 = target.AddInt("u32", 4);
        var tu64 = target.AddInt("u64", 8);
        var tarr = target.AddArray(tu64, tu32, 8);
        target.AddStruct("s", 64, new Member("vals", tarr, 0));

        var result = Resolve(local, ls, "0:0:3", BtfCoreReloKind.FieldByteOffset, target);

        Assert.Equal(new CoreReloResult(12, 24, Poison: false, Validate: true), result);
    }

    [Fact]
    public void The_root_index_scales_by_the_target_struct_size()
    {
        // "2:1" is `&ptr[2].b` — the leading index is pointer arithmetic on the root.
        var local = new BtfBlobBuilder();
        var lu32 = local.AddInt("u32", 4);
        var ls = local.AddStruct("s", 8, new Member("a", lu32, 0), new Member("b", lu32, 32));

        var target = new BtfBlobBuilder();
        var tu32 = target.AddInt("u32", 4);
        target.AddStruct("s", 12,
            new Member("a", tu32, 0), new Member("pad", tu32, 32), new Member("b", tu32, 64));

        var result = Resolve(local, ls, "2:1", BtfCoreReloKind.FieldByteOffset, target);

        Assert.Equal(new CoreReloResult(2 * 8 + 4, 2 * 12 + 8, Poison: false, Validate: true), result);
    }

    [Fact]
    public void A_bitfield_byte_offset_is_the_aligned_load_offset_and_skips_validation()
    {
        // y spans bits [33, 36): loaded as the aligned u32 at byte 4.
        var local = BitfieldStruct();
        var target = BitfieldStruct();

        var result = Resolve(local.Builder, local.StructId, "0:2",
            BtfCoreReloKind.FieldByteOffset, target.Builder);

        Assert.Equal(new CoreReloResult(4, 4, Poison: false, Validate: false), result);
    }

    [Fact]
    public void A_missing_field_poisons_instead_of_throwing()
    {
        var local = new BtfBlobBuilder();
        var lint = local.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var ls = local.AddStruct("task", 8, new Member("pid", lint, 0), new Member("tgid", lint, 32));

        var target = new BtfBlobBuilder();
        var tint = target.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        target.AddStruct("task", 4, new Member("pid", tint, 0));

        var result = Resolve(local, ls, "0:1", BtfCoreReloKind.FieldByteOffset, target);

        Assert.True(result.Poison);
    }

    [Fact]
    public void An_out_of_bounds_target_array_index_poisons()
    {
        var local = new BtfBlobBuilder();
        var lu32 = local.AddInt("u32", 4);
        var larr = local.AddArray(lu32, lu32, 8);
        var ls = local.AddStruct("s", 32, new Member("vals", larr, 0));

        var target = new BtfBlobBuilder();
        var tu32 = target.AddInt("u32", 4);
        var tarr = target.AddArray(tu32, tu32, 2);
        target.AddStruct("s", 8, new Member("vals", tarr, 0));

        var result = Resolve(local, ls, "0:0:3", BtfCoreReloKind.FieldByteOffset, target);

        Assert.True(result.Poison);
    }

    // ---- field exists ------------------------------------------------------------

    [Fact]
    public void An_existing_field_resolves_exists_to_one()
    {
        var local = new BtfBlobBuilder();
        var lint = local.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var ls = local.AddStruct("task", 8, new Member("pid", lint, 0), new Member("tgid", lint, 32));

        var target = new BtfBlobBuilder();
        var tint = target.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        target.AddStruct("task", 8, new Member("pid", tint, 0), new Member("tgid", tint, 32));

        var result = Resolve(local, ls, "0:1", BtfCoreReloKind.FieldExists, target);

        Assert.Equal(new CoreReloResult(1, 1, Poison: false, Validate: true), result);
    }

    [Fact]
    public void A_missing_field_resolves_exists_to_zero_without_poison()
    {
        var local = new BtfBlobBuilder();
        var lint = local.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var ls = local.AddStruct("task", 8, new Member("pid", lint, 0), new Member("tgid", lint, 32));

        var target = new BtfBlobBuilder();
        var tint = target.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        target.AddStruct("task", 4, new Member("pid", tint, 0));

        var result = Resolve(local, ls, "0:1", BtfCoreReloKind.FieldExists, target);

        Assert.Equal(new CoreReloResult(1, 0, Poison: false, Validate: true), result);
    }

    [Fact]
    public void A_missing_root_type_still_resolves_exists_to_zero()
    {
        var local = new BtfBlobBuilder();
        var lint = local.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var ls = local.AddStruct("task", 4, new Member("pid", lint, 0));

        var target = new BtfBlobBuilder();
        target.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed); // no task at all

        var result = Resolve(local, ls, "0:0", BtfCoreReloKind.FieldExists, target);

        Assert.False(result.Poison);
        Assert.Equal(0ul, result.NewValue);
    }

    // ---- field size and signedness -----------------------------------------------

    [Fact]
    public void Field_byte_size_takes_the_target_width()
    {
        var local = new BtfBlobBuilder();
        var lu32 = local.AddInt("u32", 4);
        var ls = local.AddStruct("s", 4, new Member("a", lu32, 0));

        var target = new BtfBlobBuilder();
        var tu64 = target.AddInt("u64", 8);
        target.AddStruct("s", 8, new Member("a", tu64, 0));

        var result = Resolve(local, ls, "0:0", BtfCoreReloKind.FieldByteSize, target);

        Assert.Equal(new CoreReloResult(4, 8, Poison: false, Validate: true), result);
    }

    [Fact]
    public void Field_byte_size_of_a_bitfield_is_the_covering_load_and_skips_validation()
    {
        var local = BitfieldStruct();
        var target = BitfieldStruct();

        var result = Resolve(local.Builder, local.StructId, "0:2",
            BtfCoreReloKind.FieldByteSize, target.Builder);

        Assert.Equal(new CoreReloResult(4, 4, Poison: false, Validate: false), result);
    }

    [Fact]
    public void Field_signedness_comes_from_the_target_type()
    {
        var local = new BtfBlobBuilder();
        var lu32 = local.AddInt("u32", 4);
        var ls = local.AddStruct("s", 4, new Member("a", lu32, 0));

        var target = new BtfBlobBuilder();
        var tint = target.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        target.AddStruct("s", 4, new Member("a", tint, 0));

        var result = Resolve(local, ls, "0:0", BtfCoreReloKind.FieldSigned, target);

        Assert.Equal(new CoreReloResult(0, 1, Poison: false, Validate: true), result);
    }

    // ---- bitfield shifts ---------------------------------------------------------
    //
    // y spans bits [33, 36) and is loaded as the aligned u32 at byte 4, so on a
    // little-endian target: lshift = 64 - (33 + 3 - 4*8) = 60, rshift = 64 - 3 = 61.

    [Fact]
    public void Left_shift_positions_the_bitfield_at_the_top_of_the_loaded_word()
    {
        var local = BitfieldStruct();
        var target = BitfieldStruct();

        var result = Resolve(local.Builder, local.StructId, "0:2",
            BtfCoreReloKind.FieldLShiftU64, target.Builder);

        Assert.Equal(new CoreReloResult(60, 60, Poison: false, Validate: false), result);
    }

    [Fact]
    public void Right_shift_is_sixty_four_minus_the_bit_width_and_validates()
    {
        var local = BitfieldStruct();
        var target = BitfieldStruct();

        var result = Resolve(local.Builder, local.StructId, "0:2",
            BtfCoreReloKind.FieldRShiftU64, target.Builder);

        Assert.Equal(new CoreReloResult(61, 61, Poison: false, Validate: true), result);
    }

    [Fact]
    public void A_moved_bitfield_recomputes_the_shifts_against_the_target()
    {
        var local = BitfieldStruct();

        // In the target, x:5 starts at bit 64 and y:3 at bit 69, loaded at byte 8:
        // lshift = 64 - (69 + 3 - 8*8) = 56.
        var target = new BtfBlobBuilder();
        var tu32 = target.AddInt("u32", 4);
        target.AddStruct("s", 12,
            new Member("a", tu32, 0), new Member("pad", tu32, 32),
            new Member("x", tu32, 64, 5), new Member("y", tu32, 69, 3));

        var result = Resolve(local.Builder, local.StructId, "0:2",
            BtfCoreReloKind.FieldLShiftU64, target);

        Assert.Equal(new CoreReloResult(60, 56, Poison: false, Validate: false), result);
    }

    // ---- enum values -------------------------------------------------------------

    [Fact]
    public void Enum_values_are_matched_by_name_and_take_the_target_value()
    {
        var local = new BtfBlobBuilder();
        var le = local.AddEnum("kind", 4, false, ("A", 0), ("B", 1));

        var target = new BtfBlobBuilder();
        target.AddEnum("kind", 4, false, ("A", 5), ("B", 7));

        var result = Resolve(local, le, "1", BtfCoreReloKind.EnumValValue, target);

        Assert.Equal(new CoreReloResult(1, 7, Poison: false, Validate: true), result);
    }

    [Fact]
    public void Enum_value_existence_is_a_zero_or_one_probe()
    {
        var local = new BtfBlobBuilder();
        var le = local.AddEnum("kind", 4, false, ("A", 0), ("B", 1));

        var target = new BtfBlobBuilder();
        target.AddEnum("kind", 4, false, ("A", 5)); // no B

        var missing = Resolve(local, le, "1", BtfCoreReloKind.EnumValExists, target);
        var present = Resolve(local, le, "0", BtfCoreReloKind.EnumValExists, target);

        Assert.Equal(new CoreReloResult(1, 0, Poison: false, Validate: true), missing);
        Assert.Equal(new CoreReloResult(1, 1, Poison: false, Validate: true), present);
    }

    [Fact]
    public void A_missing_enum_value_poisons_the_value_relocation()
    {
        var local = new BtfBlobBuilder();
        var le = local.AddEnum("kind", 4, false, ("A", 0), ("B", 1));

        var target = new BtfBlobBuilder();
        target.AddEnum("kind", 4, false, ("A", 5)); // no B

        var result = Resolve(local, le, "1", BtfCoreReloKind.EnumValValue, target);

        Assert.True(result.Poison);
    }

    [Fact]
    public void Enum64_values_span_the_full_width()
    {
        var local = new BtfBlobBuilder();
        var le = local.AddEnum64("big", 8, false, ("BIG", 1ul));

        var target = new BtfBlobBuilder();
        target.AddEnum64("big", 8, false, ("BIG", 1ul << 40));

        var result = Resolve(local, le, "0", BtfCoreReloKind.EnumValValue, target);

        Assert.Equal(new CoreReloResult(1, 1ul << 40, Poison: false, Validate: true), result);
    }

    // ---- type-based relocations --------------------------------------------------

    [Fact]
    public void Type_exists_matches_kind_as_well_as_name()
    {
        var local = new BtfBlobBuilder();
        var lint = local.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var ls = local.AddStruct("s", 4, new Member("a", lint, 0));

        var asStruct = new BtfBlobBuilder();
        var tint = asStruct.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        asStruct.AddStruct("s", 4, new Member("a", tint, 0));

        // A typedef named "s" is not a struct named "s".
        var asTypedef = new BtfBlobBuilder();
        var t2int = asTypedef.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        asTypedef.AddTypedef("s", t2int);

        Assert.Equal(1ul, Resolve(local, ls, "0", BtfCoreReloKind.TypeExists, asStruct).NewValue);
        Assert.Equal(0ul, Resolve(local, ls, "0", BtfCoreReloKind.TypeExists, asTypedef).NewValue);
    }

    [Fact]
    public void Type_size_takes_the_target_size()
    {
        var local = new BtfBlobBuilder();
        var lint = local.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var ls = local.AddStruct("s", 8, new Member("a", lint, 0), new Member("b", lint, 32));

        var target = new BtfBlobBuilder();
        var tint = target.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var tlong = target.AddInt("long", 8, BtfBlobBuilder.IntEncoding.Signed);
        target.AddStruct("s", 24,
            new Member("a", tint, 0), new Member("pad", tlong, 64), new Member("b", tint, 128));

        var result = Resolve(local, ls, "0", BtfCoreReloKind.TypeSize, target);

        Assert.Equal(new CoreReloResult(8, 24, Poison: false, Validate: true), result);
    }

    [Fact]
    public void Type_id_local_echoes_the_local_id_without_validation()
    {
        var local = new BtfBlobBuilder();
        var lint = local.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var ls = local.AddStruct("s", 4, new Member("a", lint, 0));

        var target = new BtfBlobBuilder();
        target.AddInt("int", 4); // target is irrelevant to this kind

        var result = Resolve(local, ls, "0", BtfCoreReloKind.TypeIdLocal, target);

        Assert.Equal(new CoreReloResult((ulong)ls, (ulong)ls, Poison: false, Validate: false), result);
    }

    [Fact]
    public void Type_id_target_returns_the_matched_id_without_validation()
    {
        var local = new BtfBlobBuilder();
        var lint = local.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var ls = local.AddStruct("s", 4, new Member("a", lint, 0));

        var target = new BtfBlobBuilder();
        var tint = target.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        target.AddInt("long", 8, BtfBlobBuilder.IntEncoding.Signed);
        var ts = target.AddStruct("s", 4, new Member("a", tint, 0));

        var result = Resolve(local, ls, "0", BtfCoreReloKind.TypeIdTarget, target);

        Assert.Equal(new CoreReloResult((ulong)ls, (ulong)ts, Poison: false, Validate: false), result);
    }

    [Fact]
    public void A_missing_type_resolves_type_relos_to_zero_without_poison()
    {
        var local = new BtfBlobBuilder();
        var lint = local.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var ls = local.AddStruct("s", 4, new Member("a", lint, 0));

        var target = new BtfBlobBuilder();
        target.AddInt("int", 4);

        var exists = Resolve(local, ls, "0", BtfCoreReloKind.TypeExists, target);
        var size = Resolve(local, ls, "0", BtfCoreReloKind.TypeSize, target);

        Assert.Equal((0ul, false), (exists.NewValue, exists.Poison));
        Assert.Equal((0ul, false), (size.NewValue, size.Poison));
    }

    [Fact]
    public void Type_matches_requires_the_same_shape()
    {
        var local = new BtfBlobBuilder();
        var lint = local.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var ls = local.AddStruct("s", 4, new Member("a", lint, 0));

        var same = new BtfBlobBuilder();
        var sint = same.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        same.AddStruct("s", 4, new Member("a", sint, 0));

        // Same member name, but an int is not a pointer.
        var different = new BtfBlobBuilder();
        var dint = different.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var dptr = different.AddPtr(dint);
        different.AddStruct("s", 8, new Member("a", dptr, 0));

        Assert.Equal(1ul, Resolve(local, ls, "0", BtfCoreReloKind.TypeMatches, same).NewValue);
        Assert.Equal(0ul, Resolve(local, ls, "0", BtfCoreReloKind.TypeMatches, different).NewValue);
    }

    // ---- flavors and candidates --------------------------------------------------

    [Fact]
    public void Flavor_suffixes_are_stripped_on_both_sides()
    {
        // A "___older" local flavor targets the plain kernel name, and a target
        // flavor is just as much a candidate for a plain local name.
        var local = new BtfBlobBuilder();
        var lint = local.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        var flavored = local.AddStruct("task___older", 4, new Member("pid", lint, 0));

        var target = new BtfBlobBuilder();
        var tint = target.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
        target.AddStruct("task", 8, new Member("pad", tint, 0), new Member("pid", tint, 32));

        var result = Resolve(local, flavored, "0:0", BtfCoreReloKind.FieldByteOffset, target);

        Assert.Equal(new CoreReloResult(0, 4, Poison: false, Validate: true), result);
    }

    [Fact]
    public void Agreeing_candidates_resolve()
    {
        var local = new BtfBlobBuilder();
        var lu32 = local.AddInt("u32", 4);
        var ls = local.AddStruct("s", 4, new Member("a", lu32, 0));

        // Two candidates ("s" and its flavor), both placing a at byte 4.
        var target = new BtfBlobBuilder();
        var tu32 = target.AddInt("u32", 4);
        target.AddStruct("s", 8, new Member("pad", tu32, 0), new Member("a", tu32, 32));
        target.AddStruct("s___v2", 8, new Member("padx", tu32, 0), new Member("a", tu32, 32));

        var result = Resolve(local, ls, "0:0", BtfCoreReloKind.FieldByteOffset, target);

        Assert.Equal(new CoreReloResult(0, 4, Poison: false, Validate: true), result);
    }

    [Fact]
    public void Conflicting_candidates_throw()
    {
        var local = new BtfBlobBuilder();
        var lu32 = local.AddInt("u32", 4);
        var ls = local.AddStruct("s", 4, new Member("a", lu32, 0));

        // Both match, but disagree: a at byte 4 vs byte 0.
        var target = new BtfBlobBuilder();
        var tu32 = target.AddInt("u32", 4);
        target.AddStruct("s", 8, new Member("pad", tu32, 0), new Member("a", tu32, 32));
        target.AddStruct("s___v2", 4, new Member("a", tu32, 0));

        Assert.Throws<CoreReloException>(
            () => Resolve(local, ls, "0:0", BtfCoreReloKind.FieldByteOffset, target));
    }

    // ---- malformed relocations ---------------------------------------------------

    [Fact]
    public void A_malformed_access_string_throws()
    {
        var local = new BtfBlobBuilder();
        var lu32 = local.AddInt("u32", 4);
        var ls = local.AddStruct("s", 4, new Member("a", lu32, 0));

        var target = new BtfBlobBuilder();
        target.AddInt("u32", 4);

        Assert.Throws<CoreReloException>(
            () => Resolve(local, ls, "0:x", BtfCoreReloKind.FieldByteOffset, target));
        Assert.Throws<CoreReloException>(
            () => Resolve(local, ls, "", BtfCoreReloKind.FieldByteOffset, target));
    }

    [Fact]
    public void An_access_index_past_the_local_members_throws()
    {
        var local = new BtfBlobBuilder();
        var lu32 = local.AddInt("u32", 4);
        var ls = local.AddStruct("s", 8, new Member("a", lu32, 0), new Member("b", lu32, 32));

        var target = new BtfBlobBuilder();
        target.AddInt("u32", 4);

        Assert.Throws<CoreReloException>(
            () => Resolve(local, ls, "0:9", BtfCoreReloKind.FieldByteOffset, target));
    }

    [Fact]
    public void A_field_access_through_a_non_composite_local_type_throws()
    {
        var local = new BtfBlobBuilder();
        var lu32 = local.AddInt("u32", 4);

        var target = new BtfBlobBuilder();
        target.AddInt("u32", 4);

        Assert.Throws<CoreReloException>(
            () => Resolve(local, lu32, "0:1", BtfCoreReloKind.FieldByteOffset, target));
    }

    [Fact]
    public void An_unknown_local_type_id_throws()
    {
        var local = new BtfBlobBuilder();
        local.AddInt("u32", 4);

        var target = new BtfBlobBuilder();
        target.AddInt("u32", 4);

        Assert.Throws<CoreReloException>(
            () => Resolve(local, 99, "0:0", BtfCoreReloKind.FieldByteOffset, target));
    }

    // ---- shared fixtures ---------------------------------------------------------

    /// <summary>struct s { u32 a; u32 x:1; u32 y:3; } — y at bits [33, 36).</summary>
    private static (BtfBlobBuilder Builder, int StructId) BitfieldStruct()
    {
        var builder = new BtfBlobBuilder();
        var u32 = builder.AddInt("u32", 4);
        var s = builder.AddStruct("s", 8,
            new Member("a", u32, 0), new Member("x", u32, 32, 1), new Member("y", u32, 33, 3));
        return (builder, s);
    }
}
