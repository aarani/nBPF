using Xunit;

namespace Ebpf.Elf.Tests;

public class ElfHeaderTests
{
    [Fact]
    public void Identifies_the_fixture_as_a_little_endian_elf64_bpf_object()
    {
        var elf = ElfFixture.Object;

        Assert.Equal(ElfClass.Elf64, elf.Class);
        Assert.Equal(ElfEndianness.Little, elf.Endianness);
        Assert.Equal(ElfFileType.Relocatable, elf.FileType);
        Assert.Equal(ElfMachine.Bpf, elf.Machine);
    }

    [Fact]
    public void Rejects_a_file_that_is_not_elf()
    {
        var notElf = new byte[256];
        notElf[0] = 0x9F;
        notElf[1] = 0xEB; // a bare BTF blob, say

        var ex = Assert.Throws<ElfFormatException>(() => ElfReader.Read(notElf));
        Assert.Contains("magic", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_a_file_shorter_than_the_header()
    {
        var ex = Assert.Throws<ElfFormatException>(() => ElfReader.Read([0x7F, (byte)'E', (byte)'L', (byte)'F']));
        Assert.Contains("truncated", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_a_32_bit_object()
    {
        var elf = (byte[])ElfFixture.Bytes.Clone();
        elf[4] = (byte)ElfClass.Elf32; // e_ident[EI_CLASS]

        var ex = Assert.Throws<ElfFormatException>(() => ElfReader.Read(elf));
        Assert.Contains("64", ex.Message);
    }

    [Fact]
    public void Rejects_a_section_header_table_that_runs_past_the_end_of_the_file()
    {
        var elf = (byte[])ElfFixture.Bytes.Clone();

        // e_shoff lives at offset 0x28 and is 8 bytes; point it far beyond the file.
        for (var i = 0; i < 4; i++)
            elf[0x28 + i] = 0xFF;

        Assert.Throws<ElfFormatException>(() => ElfReader.Read(elf));
    }

    [Fact]
    public void Section_zero_is_the_reserved_null_entry()
    {
        var first = ElfFixture.Object.Sections[0];

        Assert.Equal(0, first.Index);
        Assert.Equal(ElfSectionType.Null, first.Type);
        Assert.Equal("", first.Name);
    }

    [Fact]
    public void Section_indices_match_their_position_in_the_list()
    {
        var sections = ElfFixture.Object.Sections;

        for (var i = 0; i < sections.Count; i++)
            Assert.Equal(i, sections[i].Index);
    }
}
