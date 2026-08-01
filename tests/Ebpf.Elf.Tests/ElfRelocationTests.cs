using Xunit;

namespace Ebpf.Elf.Tests;

public class ElfRelocationTests
{
    /// <summary>Resolves a relocation's symbol name, which is how the loader identifies its target.</summary>
    private static string SymbolName(ElfRelocation relocation) =>
        ElfFixture.Object.Symbols[(int)relocation.SymbolIndex].Name;

    [Fact]
    public void Relocations_are_attached_to_the_section_they_apply_to()
    {
        // They live in a separate `.rel<name>` section whose sh_info points back here; the
        // reader is expected to have already followed that link.
        var execve = ElfFixture.Section(ElfFixture.ExecveProgram);

        Assert.Equal(4, execve.Relocations.Count);
    }

    [Fact]
    public void Execve_program_relocations_match_the_object()
    {
        var relocations = ElfFixture.Section(ElfFixture.ExecveProgram).Relocations;

        Assert.Equal(
            [
                (0x08ul, "min_uid", BpfRelocationType.Bpf64_64),
                (0x40ul, "counts", BpfRelocationType.Bpf64_64),
                (0x90ul, "counts", BpfRelocationType.Bpf64_64),
                (0xC8ul, ".text", BpfRelocationType.Bpf64_32),
            ],
            relocations.Select(r => (r.Offset, SymbolName(r), r.Type)));
    }

    [Fact]
    public void Openat_program_relocations_match_the_object()
    {
        var relocations = ElfFixture.Section(ElfFixture.OpenatProgram).Relocations;

        Assert.Equal(
            [
                (0x08ul, "dropped", BpfRelocationType.Bpf64_64),
                (0x20ul, ".text", BpfRelocationType.Bpf64_32),
            ],
            relocations.Select(r => (r.Offset, SymbolName(r), r.Type)));
    }

    [Fact]
    public void Map_references_are_ld_imm64_relocations()
    {
        // BPF_PSEUDO_MAP_FD patching keys off these: a 64-bit immediate against a .maps symbol.
        var mapRelocations = ElfFixture.Section(ElfFixture.ExecveProgram).Relocations
            .Where(r => SymbolName(r) == "counts")
            .ToList();

        Assert.Equal(2, mapRelocations.Count);
        Assert.All(mapRelocations, r => Assert.Equal(BpfRelocationType.Bpf64_64, r.Type));
    }

    [Fact]
    public void Subprogram_calls_are_32_bit_relocations_against_text()
    {
        // Both programs call `bump`, and both reference it through the .text section symbol
        // rather than through the function symbol.
        foreach (var name in new[] { ElfFixture.ExecveProgram, ElfFixture.OpenatProgram })
        {
            var call = Assert.Single(
                ElfFixture.Section(name).Relocations, r => r.Type == BpfRelocationType.Bpf64_32);

            Assert.Equal(".text", SymbolName(call));
        }
    }

    [Fact]
    public void Relocation_offsets_land_on_instruction_boundaries()
    {
        foreach (var name in new[] { ElfFixture.ExecveProgram, ElfFixture.OpenatProgram })
        {
            var section = ElfFixture.Section(name);

            foreach (var relocation in section.Relocations)
            {
                Assert.Equal(0ul, relocation.Offset % 8);
                Assert.True(relocation.Offset < section.Size,
                    $"relocation at {relocation.Offset:X} is outside {name} ({section.Size} bytes)");
            }
        }
    }

    [Fact]
    public void Every_relocation_names_a_symbol_that_exists()
    {
        foreach (var section in ElfFixture.Object.Sections)
        {
            foreach (var relocation in section.Relocations)
            {
                Assert.InRange((int)relocation.SymbolIndex, 0, ElfFixture.Object.Symbols.Count - 1);
                Assert.NotEqual("", SymbolName(relocation));
            }
        }
    }

    [Fact]
    public void Sections_with_nothing_to_relocate_report_an_empty_list()
    {
        // Not null — callers should be able to foreach without a guard.
        Assert.Empty(ElfFixture.Section(".rodata").Relocations);
        Assert.Empty(ElfFixture.Section("license").Relocations);
    }
}
