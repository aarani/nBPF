using System.Text;
using Xunit;

namespace Ebpf.Elf.Tests;

public class ElfSectionTests
{
    [Theory]
    [InlineData(".text")]
    [InlineData(ElfFixture.ExecveProgram)]
    [InlineData(ElfFixture.OpenatProgram)]
    [InlineData(".rodata")]
    [InlineData(".bss")]
    [InlineData("license")]
    [InlineData(".maps")]
    [InlineData(".BTF")]
    [InlineData(".BTF.ext")]
    [InlineData(".symtab")]
    [InlineData(".strtab")]
    public void Finds_every_section_the_loader_cares_about(string name)
    {
        Assert.NotNull(ElfFixture.Object.FindSection(name));
    }

    [Fact]
    public void Find_section_returns_null_for_an_absent_name()
    {
        Assert.Null(ElfFixture.Object.FindSection(".no_such_section"));
    }

    [Fact]
    public void Section_names_come_from_the_section_header_string_table()
    {
        // A slash in the name is the normal case for BPF program sections and a classic
        // place to get the shstrtab lookup subtly wrong.
        var program = ElfFixture.Section(ElfFixture.ExecveProgram);

        Assert.Equal(ElfFixture.ExecveProgram, program.Name);
        Assert.Equal(ElfSectionType.ProgBits, program.Type);
    }

    [Fact]
    public void Program_sections_are_allocatable_and_executable()
    {
        foreach (var name in new[] { ".text", ElfFixture.ExecveProgram, ElfFixture.OpenatProgram })
        {
            var section = ElfFixture.Section(name);
            Assert.Equal(ElfSectionFlags.Alloc | ElfSectionFlags.Execute, section.Flags);
        }
    }

    [Fact]
    public void Program_section_data_is_a_whole_number_of_8_byte_instructions()
    {
        foreach (var name in new[] { ".text", ElfFixture.ExecveProgram, ElfFixture.OpenatProgram })
        {
            var section = ElfFixture.Section(name);
            Assert.Equal((int)section.Size, section.Data.Length);
            Assert.Equal(0, section.Data.Length % 8);
            Assert.NotEmpty(section.Data);
        }
    }

    [Fact]
    public void Text_holds_only_the_out_of_line_subprogram()
    {
        // `bump` is the single noinline static; three instructions at -O2.
        var text = ElfFixture.Section(".text");

        Assert.Equal(24ul, text.Size);
        Assert.Equal(24, text.Data.Length);
    }

    [Fact]
    public void Bss_has_a_size_but_no_file_contents()
    {
        // NOBITS occupies no file space. Sizing the .bss array map from Data instead of
        // Size would silently produce a zero-length map.
        var bss = ElfFixture.Section(".bss");

        Assert.Equal(ElfSectionType.NoBits, bss.Type);
        Assert.Equal(8ul, bss.Size); // u64 dropped
        Assert.Empty(bss.Data);
        Assert.Equal(ElfSectionFlags.Write | ElfSectionFlags.Alloc, bss.Flags);
    }

    [Fact]
    public void Rodata_contains_the_initial_value_of_the_config_global()
    {
        var rodata = ElfFixture.Section(".rodata");

        Assert.Equal(ElfSectionType.ProgBits, rodata.Type);
        Assert.Equal(4ul, rodata.Size); // const volatile u32 min_uid
        Assert.Equal([0, 0, 0, 0], rodata.Data);

        // Read-only in the BPF sense (the verifier is told via BPF_MAP_FREEZE), but the ELF
        // section itself is not marked write.
        Assert.False(rodata.Flags.HasFlag(ElfSectionFlags.Write));
    }

    [Fact]
    public void License_section_holds_a_nul_terminated_string()
    {
        var license = ElfFixture.Section("license");

        Assert.Equal(4ul, license.Size);
        Assert.Equal("GPL", Encoding.ASCII.GetString(license.Data).TrimEnd('\0'));
    }

    [Fact]
    public void Maps_section_is_sized_for_both_map_definitions()
    {
        // events is 2 pointers, counts is 4 — the .maps contents are placeholders; the real
        // definitions live in BTF. Only the size and the symbol offsets matter here.
        var maps = ElfFixture.Section(".maps");

        Assert.Equal(48ul, maps.Size);
        Assert.Equal(ElfSectionFlags.Write | ElfSectionFlags.Alloc, maps.Flags);
    }

    [Fact]
    public void Btf_sections_are_present_and_non_empty()
    {
        Assert.NotEmpty(ElfFixture.Section(".BTF").Data);
        Assert.NotEmpty(ElfFixture.Section(".BTF.ext").Data);
    }

    [Fact]
    public void Relocation_sections_are_not_surfaced_as_ordinary_sections_to_relocate()
    {
        // The .rel* sections exist in the section list, but nothing relocates against them.
        foreach (var section in ElfFixture.Object.Sections.Where(s => s.Type == ElfSectionType.Rel))
            Assert.Empty(section.Relocations);
    }
}
