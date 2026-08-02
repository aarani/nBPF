using Xunit;

namespace Nbpf.Btf.Tests;

public class BtfExtReaderTests
{
    [Fact]
    public void An_empty_blob_has_no_sections_at_all()
    {
        var btf = new BtfBlobBuilder();
        var info = BtfExtReader.Read(new BtfExtBlobBuilder(btf).Build(), btf.Build());

        Assert.Empty(info.FuncInfo);
        Assert.Empty(info.LineInfo);
        Assert.Empty(info.CoreRelos);
    }

    [Fact]
    public void Func_info_records_carry_instruction_offsets_and_type_ids()
    {
        var btf = new BtfBlobBuilder();
        var ext = new BtfExtBlobBuilder(btf);
        ext.AddFuncSection("tracepoint/syscalls/sys_enter_execve", (0, 5));
        ext.AddFuncSection(".text", (0, 7), (64, 9));

        var info = BtfExtReader.Read(ext.Build(), btf.Build());

        Assert.Collection(info.FuncInfo,
            section =>
            {
                Assert.Equal("tracepoint/syscalls/sys_enter_execve", section.SectionName);
                Assert.Equal([new BtfFuncInfo(0, 5)], section.Records);
            },
            section =>
            {
                Assert.Equal(".text", section.SectionName);
                Assert.Equal([new BtfFuncInfo(0, 7), new BtfFuncInfo(64, 9)], section.Records);
            });
    }

    [Fact]
    public void Line_info_unpacks_the_packed_line_and_column()
    {
        var btf = new BtfBlobBuilder();
        var ext = new BtfExtBlobBuilder(btf);
        ext.AddLineSection("prog",
            (0, "probe.bpf.c", "int handle(void *ctx)", 42, 0),
            (8, "probe.bpf.c", "    return 0;", 43, 5));

        var info = BtfExtReader.Read(ext.Build(), btf.Build());

        var section = Assert.Single(info.LineInfo);
        Assert.Equal("prog", section.SectionName);
        Assert.Equal(
            [
                new BtfLineInfo(0, "probe.bpf.c", "int handle(void *ctx)", 42, 0),
                new BtfLineInfo(8, "probe.bpf.c", "    return 0;", 43, 5),
            ],
            section.Records);
    }

    [Fact]
    public void Core_relos_resolve_access_strings_and_kinds()
    {
        var btf = new BtfBlobBuilder();
        var ext = new BtfExtBlobBuilder(btf);
        ext.AddCoreReloSection("prog",
            (0, 12, "0:1:2", (uint)BtfCoreReloKind.FieldByteOffset),
            (24, 12, "0:3", (uint)BtfCoreReloKind.FieldExists),
            (40, 15, "9", (uint)BtfCoreReloKind.EnumValValue));

        var info = BtfExtReader.Read(ext.Build(), btf.Build());

        var section = Assert.Single(info.CoreRelos);
        Assert.Equal(
            [
                new BtfCoreRelo(0, 12, "0:1:2", BtfCoreReloKind.FieldByteOffset),
                new BtfCoreRelo(24, 12, "0:3", BtfCoreReloKind.FieldExists),
                new BtfCoreRelo(40, 15, "9", BtfCoreReloKind.EnumValValue),
            ],
            section.Records);
    }

    [Fact]
    public void An_unrecognized_core_relo_kind_is_rejected()
    {
        // A relocation we cannot interpret is a program we cannot correctly load —
        // skipping it would mean silently corrupted field reads later.
        var btf = new BtfBlobBuilder();
        var ext = new BtfExtBlobBuilder(btf);
        ext.AddCoreReloSection("prog", (8, 3, "0:0", 99));

        var ex = Assert.Throws<BtfFormatException>(() => BtfExtReader.Read(ext.Build(), btf.Build()));
        Assert.Contains("kind 99", ex.Message);
    }

    [Fact]
    public void A_larger_record_size_from_a_newer_producer_is_skipped_over()
    {
        // The format grows by appending fields; a parser must honor the declared record
        // size rather than assume the fields it knows are all there is.
        var btf = new BtfBlobBuilder();
        var ext = new BtfExtBlobBuilder(btf) { FuncRecordSize = 16 };
        ext.AddFuncSection("prog", (0, 5), (32, 6));

        var info = BtfExtReader.Read(ext.Build(), btf.Build());

        var section = Assert.Single(info.FuncInfo);
        Assert.Equal([new BtfFuncInfo(0, 5), new BtfFuncInfo(32, 6)], section.Records);
    }

    [Fact]
    public void A_record_size_below_the_minimum_is_rejected()
    {
        var btf = new BtfBlobBuilder();
        var ext = new BtfExtBlobBuilder(btf) { LineRecordSize = 8 };
        ext.AddLineSection("prog", (0, "f.c", "x;", 1, 0));

        var ex = Assert.Throws<BtfFormatException>(() => BtfExtReader.Read(ext.Build(), btf.Build()));
        Assert.Contains("smaller than the 16-byte minimum", ex.Message);
    }

    [Fact]
    public void A_record_size_that_is_not_word_aligned_is_rejected()
    {
        var btf = new BtfBlobBuilder();
        var ext = new BtfExtBlobBuilder(btf) { FuncRecordSize = 10 };
        ext.AddFuncSection("prog", (0, 1));

        var ex = Assert.Throws<BtfFormatException>(() => BtfExtReader.Read(ext.Build(), btf.Build()));
        Assert.Contains("multiple of 4", ex.Message);
    }

    [Fact]
    public void A_section_declaring_zero_records_is_rejected()
    {
        var btf = new BtfBlobBuilder();
        var ext = new BtfExtBlobBuilder(btf);
        ext.AddFuncSection("prog");

        var ex = Assert.Throws<BtfFormatException>(() => BtfExtReader.Read(ext.Build(), btf.Build()));
        Assert.Contains("zero records", ex.Message);
    }

    [Fact]
    public void A_section_with_fewer_records_than_declared_is_rejected()
    {
        var btf = new BtfBlobBuilder();
        var ext = new BtfExtBlobBuilder(btf);
        ext.AddCoreReloSection("prog",
            (0, 1, "0:0", 0),
            (8, 1, "0:1", 0));

        // Chop one whole record off the end of the blob, then fix up the header's
        // core_relo_len so the block bound (not the blob bound) is what the last
        // record runs into.
        var blob = ext.Build(truncateBytes: 16);
        blob[28] -= 16; // core_relo_len, little-endian low byte

        var ex = Assert.Throws<BtfFormatException>(() => BtfExtReader.Read(blob, btf.Build()));
        Assert.Contains("truncated", ex.Message);
    }

    [Fact]
    public void A_section_name_outside_the_companion_string_table_is_rejected()
    {
        var btf = new BtfBlobBuilder();
        var ext = new BtfExtBlobBuilder(btf);
        ext.AddFuncSection("prog", (0, 1));

        var blob = ext.Build();
        blob[36] = 0xF0; // the block's first sec_name_off, low byte

        var ex = Assert.Throws<BtfFormatException>(() => BtfExtReader.Read(blob, btf.Build()));
        Assert.Contains("string offset", ex.Message);
    }

    [Fact]
    public void Strings_come_from_the_companion_btf_not_from_the_ext_blob()
    {
        // The same .BTF.ext bytes paired with a different string table must resolve
        // differently — proof the parser is not carrying its own string section.
        var btf = new BtfBlobBuilder();
        var ext = new BtfExtBlobBuilder(btf);
        ext.AddFuncSection("prog", (0, 1));

        var extBlob = ext.Build();
        var wrongCompanion = new BtfBlobBuilder();
        wrongCompanion.AddString("gorp"); // lands at the same offset "prog" has in the real one

        Assert.Equal("prog", Assert.Single(BtfExtReader.Read(extBlob, btf.Build()).FuncInfo).SectionName);
        Assert.Equal("gorp", Assert.Single(BtfExtReader.Read(extBlob, wrongCompanion.Build()).FuncInfo).SectionName);
    }
}
