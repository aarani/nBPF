using Nbpf.Core.Insns;
using Nbpf.Core.Native;
using Nbpf.Core.ObjectFile;
using Nbpf.Elf;
using Xunit;

namespace Nbpf.Core.Tests;

/// <summary>
/// Instruction-level relocation tests against the real clang fixture. Every index
/// and immediate below is pinned from `llvm-objdump -dr sample.bpf.o`: handle_exec
/// is 29 instructions with ld_imm64 relocations at 1 (min_uid), 8 and 18 (counts)
/// and a call at 25; handle_open is 8 instructions with ld_imm64 at 1 (dropped)
/// and a call at 4; .text holds the 3-instruction `bump`. Pure — no syscalls, so
/// fds are arbitrary made-up numbers.
/// </summary>
public class LinkerTests
{
    private static readonly Dictionary<string, int> Fds = new()
    {
        ["events"] = 102, ["counts"] = 101, [".rodata"] = 103, [".bss"] = 104,
    };

    private static IReadOnlyList<LinkedProgram> Linked { get; } =
        BpfLinker.Link(ObjectFixture.Elf, Fds);

    private static LinkedProgram Program(string name) => Linked.Single(p => p.Name == name);

    [Fact]
    public void Both_programs_are_discovered_with_their_section_types()
    {
        Assert.Equal(2, Linked.Count);

        var exec = Program("handle_exec");
        Assert.Equal("tracepoint/syscalls/sys_enter_execve", exec.SectionName);
        Assert.Equal(BpfProgType.Tracepoint, exec.Type);

        var open = Program("handle_open");
        Assert.Equal("tracepoint/syscalls/sys_enter_openat", open.SectionName);
        Assert.Equal(BpfProgType.Tracepoint, open.Type);
    }

    [Fact]
    public void Map_references_get_the_fd_and_the_pseudo_map_fd_marker()
    {
        var insns = Program("handle_exec").Insns;

        foreach (var index in new[] { 8, 18 }) // the two `counts` lookups
        {
            Assert.Equal(Asm.LdImm64OpCode, insns[index].OpCode);
            Assert.Equal(Asm.PseudoMapFd, (byte)insns[index].Src);
            Assert.Equal(Fds["counts"], insns[index].Imm);
            Assert.Equal(0, insns[index + 1].Imm); // high slot of a plain map fd stays 0
        }
    }

    [Fact]
    public void Rodata_reference_becomes_a_pseudo_map_value_with_the_variable_offset()
    {
        var insns = Program("handle_exec").Insns;

        // insn 1: r2 = &min_uid — fd of the .rodata array map in the low slot,
        // min_uid's byte offset within the value (0) in the high slot.
        Assert.Equal(Asm.LdImm64OpCode, insns[1].OpCode);
        Assert.Equal(Reg.R2, insns[1].Dst);           // untouched by the patch
        Assert.Equal(Asm.PseudoMapValue, (byte)insns[1].Src);
        Assert.Equal(Fds[".rodata"], insns[1].Imm);
        Assert.Equal(0, insns[2].Imm);
    }

    [Fact]
    public void Bss_reference_becomes_a_pseudo_map_value_on_the_bss_map()
    {
        var insns = Program("handle_open").Insns;

        Assert.Equal(Asm.PseudoMapValue, (byte)insns[1].Src);
        Assert.Equal(Reg.R6, insns[1].Dst);
        Assert.Equal(Fds[".bss"], insns[1].Imm);
        Assert.Equal(0, insns[2].Imm); // `dropped` sits at offset 0 of .bss
    }

    [Fact]
    public void Subprogram_is_appended_and_calls_become_pc_relative()
    {
        var textInsns = System.Runtime.InteropServices.MemoryMarshal
            .Cast<byte, BpfInsn>(ObjectFixture.Elf.FindSection(".text")!.Data).ToArray();

        // handle_exec: 29 own instructions + the 3 of `bump` appended at 29.
        var exec = Program("handle_exec").Insns;
        Assert.Equal(32, exec.Length);
        Assert.Equal(Asm.CallOpCode, exec[25].OpCode);
        Assert.Equal(Asm.PseudoCall, (byte)exec[25].Src);
        Assert.Equal(3, exec[25].Imm); // 29 - 25 - 1
        Assert.Equal(textInsns, exec[29..]);

        // handle_open: 8 own instructions + `bump` at 8. Same pc-relative distance
        // by coincidence of the layout, which makes for a nice cross-check.
        var open = Program("handle_open").Insns;
        Assert.Equal(11, open.Length);
        Assert.Equal(3, open[4].Imm); // 8 - 4 - 1
        Assert.Equal(textInsns, open[8..]);
    }

    [Fact]
    public void Instructions_without_relocations_are_untouched()
    {
        var section = ObjectFixture.Elf.FindSection("tracepoint/syscalls/sys_enter_openat")!;
        var original = System.Runtime.InteropServices.MemoryMarshal
            .Cast<byte, BpfInsn>(section.Data).ToArray();
        var linked = Program("handle_open").Insns;

        // Everything except the patched ld_imm64 pair (1, 2) and the call (4).
        foreach (var index in new[] { 0, 3, 5, 6, 7 })
            Assert.Equal(original[index], linked[index]);
    }

    [Fact]
    public void Missing_map_fd_is_reported_by_name()
    {
        var withoutCounts = new Dictionary<string, int>(Fds);
        withoutCounts.Remove("counts");

        var ex = Assert.Throws<InvalidDataException>(
            () => BpfLinker.Link(ObjectFixture.Elf, withoutCounts));
        Assert.Contains("counts", ex.Message);
    }

    [Fact]
    public void Unknown_program_section_prefix_is_rejected()
    {
        // Rewrite "tracepoint/" to "xracepoint/" everywhere in the object (section
        // names live in .shstrtab) — the loader must refuse to guess a program type.
        var mutated = ReplaceBytes(ObjectFixture.Bytes, "tracepoint/"u8, "xracepoint/"u8);

        var ex = Assert.Throws<NotSupportedException>(
            () => BpfLinker.Link(ElfReader.Read(mutated), Fds));
        Assert.Contains("xracepoint/", ex.Message);
        // The message lists what *would* have worked, both prefixes and exact names.
        Assert.Contains(ProgSections.SupportedPrefixes, ex.Message);
        Assert.Contains(ProgSections.SupportedFixedNames, ex.Message);
    }

    [Fact]
    public void Relocation_that_does_not_land_on_ld_imm64_is_rejected()
    {
        // Corrupt the opcode under the min_uid relocation (execve insn 1). A reloc
        // pointing at a non-ld_imm64 must be refused, never mispatched.
        var mutated = (byte[])ObjectFixture.Bytes.Clone();
        var section = ObjectFixture.Elf.FindSection("tracepoint/syscalls/sys_enter_execve")!;
        mutated[(int)section.Offset + 8] = 0xb7; // ld_imm64 → mov64_imm

        Assert.Throws<InvalidDataException>(
            () => BpfLinker.Link(ElfReader.Read(mutated), Fds));
    }

    [Fact]
    public void Undefined_symbol_is_reported_as_an_unsupported_extern()
    {
        // Point the min_uid relocation's symbol at SHN_UNDEF, the shape an extern
        // (e.g. a kconfig or kfunc reference) arrives in.
        var mutated = (byte[])ObjectFixture.Bytes.Clone();
        var elf = ObjectFixture.Elf;
        var section = elf.FindSection("tracepoint/syscalls/sys_enter_execve")!;
        var symbolIndex = section.Relocations[0].SymbolIndex;
        var symtab = elf.Sections.Single(s => s.Type == ElfSectionType.SymTab);
        // Elf64_Sym is 24 bytes; st_shndx is the u16 at offset 6.
        long shndxAt = (long)symtab.Offset + symbolIndex * 24 + 6;
        mutated[shndxAt] = 0;
        mutated[shndxAt + 1] = 0;

        var ex = Assert.Throws<NotSupportedException>(
            () => BpfLinker.Link(ElfReader.Read(mutated), Fds));
        Assert.Contains("extern", ex.Message);
    }
 

    private static byte[] ReplaceBytes(byte[] source, ReadOnlySpan<byte> find, ReadOnlySpan<byte> replace)
    {
        var result = (byte[])source.Clone();
        for (int i = 0; i <= result.Length - find.Length; i++)
        {
            if (result.AsSpan(i, find.Length).SequenceEqual(find))
                replace.CopyTo(result.AsSpan(i));
        }
        return result;
    }
}
