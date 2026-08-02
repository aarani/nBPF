using Xunit;

namespace Nbpf.Btf.Tests;

/// <summary>
/// Parses the .BTF.ext section produced by a real clang, paired with the .BTF section
/// from the same object (its string offsets are meaningless against any other blob).
/// Both fixtures are dumped from the ELF test object, so the expectations here — line
/// numbers, source text, function names — are all derived from
/// tests/Nbpf.Elf.Tests/Fixtures/sample.bpf.c.
/// </summary>
public class BtfExtClangFixtureTests
{
    private static readonly Lazy<(IBtfExtInfo Ext, IBtfTypeGraph Graph)> Fixture = new(() =>
    {
        var btf = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "elf-sample.btf"));
        var ext = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "elf-sample.btf.ext"));
        return (BtfExtReader.Read(ext, btf), BtfReader.Read(btf));
    });

    private static IBtfExtInfo Ext => Fixture.Value.Ext;
    private static IBtfTypeGraph Graph => Fixture.Value.Graph;

    [Fact]
    public void Func_info_covers_every_code_section()
    {
        // Two tracepoint programs plus .text, which holds the noinline subprogram.
        Assert.Equal(
            ["tracepoint/syscalls/sys_enter_execve", "tracepoint/syscalls/sys_enter_openat", ".text"],
            Ext.FuncInfo.Select(s => s.SectionName));

        // Each section holds exactly one function, starting at its first instruction.
        Assert.All(Ext.FuncInfo, s => Assert.Equal(0u, Assert.Single(s.Records).InsnByteOffset));
    }

    [Fact]
    public void Func_info_type_ids_resolve_to_the_right_functions_in_the_companion_btf()
    {
        static IBtfFunc FuncOf(BtfExtSection<BtfFuncInfo> section) =>
            Assert.IsAssignableFrom<IBtfFunc>(Graph.Types[(int)section.Records[0].TypeId - 1]);

        Assert.Equal(["handle_exec", "handle_open", "bump"], Ext.FuncInfo.Select(s => FuncOf(s).Name));

        // The subprogram is static; the entry points are global.
        Assert.Equal(BtfLinkage.Static, FuncOf(Ext.FuncInfo[2]).Linkage);
        Assert.Equal(BtfLinkage.Global, FuncOf(Ext.FuncInfo[0]).Linkage);
    }

    [Fact]
    public void Line_info_groups_by_the_same_sections_as_func_info()
    {
        Assert.Equal(Ext.FuncInfo.Select(s => s.SectionName), Ext.LineInfo.Select(s => s.SectionName));
    }

    [Fact]
    public void Every_line_record_points_into_the_fixture_source()
    {
        Assert.All(
            Ext.LineInfo.SelectMany(s => s.Records),
            record => Assert.EndsWith("sample.bpf.c", record.FileName));
    }

    [Fact]
    public void Instruction_offsets_are_byte_offsets_in_ascending_order()
    {
        Assert.All(Ext.LineInfo, section =>
        {
            var offsets = section.Records.Select(r => r.InsnByteOffset).ToArray();
            Assert.All(offsets, o => Assert.Equal(0u, o % 8));
            Assert.Equal(offsets.OrderBy(o => o), offsets);
        });
    }

    [Fact]
    public void Handle_exec_line_records_walk_the_function_body()
    {
        var records = Ext.LineInfo[0].Records;

        // The first instruction maps to the signature; col 0 marks a whole-line position.
        Assert.Equal(new BtfLineInfo(0, records[0].FileName, "int handle_exec(void *ctx)", 56, 0), records[0]);

        // `u32 pid = min_uid;` — the embedded source text is verbatim, indentation included.
        Assert.Equal("    u32 pid = min_uid;", records[1].SourceLine);
        Assert.Equal(58u, records[1].LineNumber);

        // record() is always_inline, so lines 45-51 from its body land in this section.
        Assert.Contains(records, r => r.LineNumber == 45 && r.SourceLine.Contains("bpf_map_lookup_elem"));

        // The closing brace of the function is the last mapped source position.
        Assert.Equal(63u, records[^1].LineNumber);
    }

    [Fact]
    public void The_noinline_subprogram_has_its_own_line_records_under_text()
    {
        var records = Ext.LineInfo[2].Records;

        Assert.Equal(38u, records[0].LineNumber); // the bump() signature
        Assert.StartsWith("static __attribute__((noinline)) u64 bump", records[0].SourceLine);
        Assert.All(records.Skip(1), r =>
        {
            Assert.Equal(40u, r.LineNumber); // both remaining insns map to `return previous + 1;`
            Assert.Equal("    return previous + 1;", r.SourceLine);
        });
    }

    [Fact]
    public void An_object_built_without_core_accessors_has_no_relocations()
    {
        // The fixture never uses __builtin_preserve_access_index, so the modern 32-byte
        // header is present but its core_relo block is empty. Pinning this keeps the
        // parser honest about "absent" versus "present but zero-length".
        Assert.Empty(Ext.CoreRelos);
    }
}
