using Xunit;

namespace Nbpf.Elf.Tests;

public class ElfSymbolTests
{
    [Fact]
    public void Symbol_zero_is_the_reserved_undefined_entry()
    {
        var first = ElfFixture.Object.Symbols[0];

        Assert.Equal(0, first.Index);
        Assert.Equal("", first.Name);
        Assert.Equal(0ul, first.Value);
    }

    [Fact]
    public void Symbol_indices_match_their_position_in_the_list()
    {
        // Relocations address symbols by index, so a shifted table corrupts every relocation.
        var symbols = ElfFixture.Object.Symbols;

        for (var i = 0; i < symbols.Count; i++)
            Assert.Equal(i, symbols[i].Index);
    }

    [Fact]
    public void Program_entry_points_are_global_functions_in_their_program_section()
    {
        var execve = ElfFixture.Symbol("handle_exec");
        Assert.Equal(ElfSymbolType.Func, execve.Type);
        Assert.Equal(ElfSymbolBinding.Global, execve.Binding);
        Assert.Equal(0ul, execve.Value);
        Assert.Equal(ElfFixture.Section(ElfFixture.ExecveProgram).Index, execve.SectionIndex);

        var openat = ElfFixture.Symbol("handle_open");
        Assert.Equal(ElfSymbolType.Func, openat.Type);
        Assert.Equal(ElfSymbolBinding.Global, openat.Binding);
        Assert.Equal(ElfFixture.Section(ElfFixture.OpenatProgram).Index, openat.SectionIndex);
    }

    [Fact]
    public void Subprogram_is_a_local_function_in_text()
    {
        // Static + noinline: the loader has to find this by symbol to append it to callers.
        var bump = ElfFixture.Symbol("bump");

        Assert.Equal(ElfSymbolType.Func, bump.Type);
        Assert.Equal(ElfSymbolBinding.Local, bump.Binding);
        Assert.Equal(ElfFixture.Section(".text").Index, bump.SectionIndex);
        Assert.Equal(0ul, bump.Value);
        Assert.Equal(24ul, bump.Size);
    }

    [Fact]
    public void Map_symbols_carry_their_offset_within_the_maps_section()
    {
        // Two maps share .maps, so the offset is what distinguishes them. Getting `counts`
        // wrong here means relocating the wrong map fd into the instruction stream.
        var maps = ElfFixture.Section(".maps").Index;

        var events = ElfFixture.Symbol("events");
        Assert.Equal(ElfSymbolType.Object, events.Type);
        Assert.Equal(maps, events.SectionIndex);
        Assert.Equal(0ul, events.Value);
        Assert.Equal(16ul, events.Size);

        var counts = ElfFixture.Symbol("counts");
        Assert.Equal(maps, counts.SectionIndex);
        Assert.Equal(0x10ul, counts.Value);
        Assert.Equal(32ul, counts.Size);
    }

    [Fact]
    public void Global_data_symbols_point_at_rodata_and_bss()
    {
        var minUid = ElfFixture.Symbol("min_uid");
        Assert.Equal(ElfSymbolType.Object, minUid.Type);
        Assert.Equal(ElfFixture.Section(".rodata").Index, minUid.SectionIndex);
        Assert.Equal(4ul, minUid.Size);

        var dropped = ElfFixture.Symbol("dropped");
        Assert.Equal(ElfFixture.Section(".bss").Index, dropped.SectionIndex);
        Assert.Equal(8ul, dropped.Size);
    }

    [Fact]
    public void Section_symbols_are_present_and_typed_as_sections()
    {
        // Subprogram-call relocations reference .text through a SECTION symbol rather than
        // through `bump` directly, so these must survive parsing.
        var text = ElfFixture.Object.Symbols.Single(s =>
            s.Type == ElfSymbolType.Section && s.SectionIndex == ElfFixture.Section(".text").Index);

        Assert.Equal(ElfSymbolBinding.Local, text.Binding);
    }
}
