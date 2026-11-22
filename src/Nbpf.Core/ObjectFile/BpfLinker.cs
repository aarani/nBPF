using System.Runtime.InteropServices;
using Nbpf.Core.Insns;
using Nbpf.Core.Native;
using Nbpf.Elf;

namespace Nbpf.Core.ObjectFile;

/// <summary>One program after relocation: a self-contained instruction stream the
/// kernel can verify, with any called subprograms appended.</summary>
internal sealed record LinkedProgram(
    string Name,          // ELF function symbol, e.g. "handle_exec"
    string SectionName,   // e.g. "tracepoint/syscalls/sys_enter_execve"
    BpfProgType Type,
    BpfInsn[] Insns);

/// <summary>
/// The relocation engine (DESIGN §4.4, steps 1–3): patches map fds and global-data
/// references into ld_imm64 instructions and statically links subprogram calls.
/// Pure — takes fds as data, performs no syscalls, so it is testable anywhere.
/// </summary>
internal static class BpfLinker
{
    /// <summary>
    /// Relocates every program in the object. <paramref name="mapFds"/> is keyed by
    /// <see cref="BpfMapSpec.Name"/>: user maps by symbol name ("counts"), global
    /// data by section name (".rodata"). CO-RE and externs are not handled yet.
    /// </summary>
    internal static IReadOnlyList<LinkedProgram> Link(
        IElfObject elf, IReadOnlyDictionary<string, int> mapFds)
    {
        if (elf.Class != ElfClass.Elf64 || elf.Endianness != ElfEndianness.Little)
            throw new NotSupportedException(
                "Only little-endian ELF64 BPF objects are supported (bpfeb is not).");
        if (!BitConverter.IsLittleEndian)
            throw new NotSupportedException(
                "Relocation assumes a little-endian host to reinterpret instruction bytes.");

        var programs = new List<LinkedProgram>();
        foreach (var section in elf.Sections)
        {
            if (section.Type != ElfSectionType.ProgBits ||
                (section.Flags & ElfSectionFlags.Execute) == 0 ||
                section.Name == ".text")
                continue;

            if (!ProgSections.TryResolve(section.Name, out var progType))
                throw new NotSupportedException(
                    $"Program section '{section.Name}' has no known type; " +
                    $"supported prefixes: {ProgSections.SupportedPrefixes};" +
                    $" or exact names: {ProgSections.SupportedFixedNames}.");

            foreach (var symbol in elf.Symbols)
            {
                if (symbol.Type == ElfSymbolType.Func && symbol.SectionIndex == section.Index)
                    programs.Add(LinkProgram(elf, mapFds, section, symbol, progType));
            }
        }

        return programs;
    }

    private static LinkedProgram LinkProgram(
        IElfObject elf, IReadOnlyDictionary<string, int> mapFds,
        IElfSection section, in ElfSymbol program, BpfProgType progType)
    {
        var insns = new List<BpfInsn>();
        insns.AddRange(SliceInsns(section, program));

        // Relocations to apply, keyed by instruction index in the combined stream.
        // Appending a subprogram enqueues that subprogram's own relocations too, so
        // .text-internal map/data/call references keep working.
        var pending = new Queue<(int Insn, ElfRelocation Rel)>();
        EnqueueRelocations(pending, section, program, combinedBase: 0);

        // .text functions already appended, by symbol index → combined start insn.
        var appended = new Dictionary<int, int>();

        while (pending.Count > 0)
        {
            var (index, relocation) = pending.Dequeue();
            var symbol = ResolveSymbol(elf, relocation);
            var target = ResolveSection(elf, program.Name, symbol);

            switch (relocation.Type)
            {
                case BpfRelocationType.Bpf64_64:
                    PatchLdImm64(program.Name, insns, index, symbol, target, mapFds);
                    break;

                case BpfRelocationType.Bpf64_32:
                    PatchCall(elf, program.Name, insns, index, symbol, target, pending, appended);
                    break;

                default:
                    throw new NotSupportedException(
                        $"Program '{program.Name}': relocation type {relocation.Type} " +
                        $"against '{symbol.Name}' is not supported.");
            }
        }

        return new LinkedProgram(program.Name, section.Name, progType, insns.ToArray());
    }

    /// <summary>Map and global-data references: a two-slot ld_imm64 whose imm gets
    /// the map fd — and, for data, whose high slot gets the offset into the value.</summary>
    private static void PatchLdImm64(
        string programName, List<BpfInsn> insns, int index, in ElfSymbol symbol,
        IElfSection target, IReadOnlyDictionary<string, int> mapFds)
    {
        if (index + 1 >= insns.Count || insns[index].OpCode != Asm.LdImm64OpCode)
            throw new InvalidDataException(
                $"Program '{programName}': Bpf64_64 relocation against '{symbol.Name}' does " +
                "not land on a two-slot ld_imm64 instruction.");

        if (target.Name == ".maps")
        {
            if (!mapFds.TryGetValue(symbol.Name, out int fd))
                throw new InvalidDataException(
                    $"Program '{programName}' references map '{symbol.Name}', " +
                    "which has no created map.");
            insns[index] = insns[index].WithSrcImm(Asm.PseudoMapFd, fd);
            return;
        }

        if (target.Name is ".rodata" or ".data" or ".bss")
        {
            if (!mapFds.TryGetValue(target.Name, out int sectionFd))
                throw new InvalidDataException(
                    $"Program '{programName}' references '{symbol.Name}' in '{target.Name}', " +
                    "but no map was created for that section.");
            // Global variable: fd of the section's array map in the low slot, byte
            // offset of the variable within the value in the high slot. The offset
            // is the symbol's position plus whatever addend clang left in the
            // instruction (SHT_REL puts the addend in the patched field itself).
            long offset = (long)symbol.Value + insns[index].Imm;
            insns[index] = insns[index].WithSrcImm(Asm.PseudoMapValue, sectionFd);
            insns[index + 1] = insns[index + 1].WithImm(checked((int)offset));
            return;
        }

        throw new NotSupportedException(
            $"Program '{programName}': cannot relocate '{symbol.Name}' in section " +
            $"'{target.Name}' — only .maps and global-data references are supported.");
    }

    /// <summary>Subprogram calls: append the callee (once) and point the call's imm
    /// at it, pc-relative. This is static linking, DESIGN §4.4 step 3.</summary>
    private static void PatchCall(
        IElfObject elf, string programName, List<BpfInsn> insns, int index,
        in ElfSymbol symbol, IElfSection text,
        Queue<(int, ElfRelocation)> pending, Dictionary<int, int> appended)
    {
        if (insns[index].OpCode != Asm.CallOpCode ||
            (byte)insns[index].Src != Asm.PseudoCall)
            throw new InvalidDataException(
                $"Program '{programName}': Bpf64_32 relocation against '{symbol.Name}' does " +
                "not land on a BPF_PSEUDO_CALL instruction.");

        if (text.Name != ".text")
            throw new NotSupportedException(
                $"Program '{programName}': call relocation targets section '{text.Name}'; " +
                "only .text subprogram calls are supported.");

        // libbpf's rule: the callee's insn index within .text is the symbol's offset
        // plus the call's existing imm plus one (clang leaves imm = -1, so a section
        // symbol resolves to index st_value/8 and a func symbol to its own start).
        long targetInsn = (long)(symbol.Value / 8) + insns[index].Imm + 1;

        var callee = FindTextFunction(elf, programName, text, targetInsn);
        if (!appended.TryGetValue(callee.Index, out int calleeBase))
        {
            calleeBase = insns.Count;
            appended[callee.Index] = calleeBase;
            insns.AddRange(SliceInsns(text, callee));
            EnqueueRelocations(pending, text, callee, calleeBase);
        }

        int combinedTarget = calleeBase + (int)(targetInsn - (long)(callee.Value / 8));
        insns[index] = insns[index].WithImm(combinedTarget - index - 1);
    }

    /// <summary>The FUNC symbol in .text whose byte range contains the given insn.</summary>
    private static ElfSymbol FindTextFunction(
        IElfObject elf, string programName, IElfSection text, long targetInsn)
    {
        long byteOffset = targetInsn * 8;
        foreach (var symbol in elf.Symbols)
        {
            if (symbol.Type == ElfSymbolType.Func && symbol.SectionIndex == text.Index &&
                (long)symbol.Value <= byteOffset && byteOffset < (long)(symbol.Value + symbol.Size))
                return symbol;
        }

        throw new InvalidDataException(
            $"Program '{programName}': call target at .text instruction {targetInsn} " +
            "is not inside any function symbol.");
    }

    /// <summary>The function's slice of its section, reinterpreted as instructions.</summary>
    private static ReadOnlySpan<BpfInsn> SliceInsns(IElfSection section, in ElfSymbol symbol)
    {
        if (symbol.Size == 0 || symbol.Size % 8 != 0 ||
            symbol.Value + symbol.Size > (ulong)section.Data.Length)
            throw new InvalidDataException(
                $"Function '{symbol.Name}' spans [{symbol.Value}, {symbol.Value + symbol.Size}) " +
                $"of '{section.Name}', which is not a whole number of instructions inside it.");

        return MemoryMarshal.Cast<byte, BpfInsn>(
            section.Data.AsSpan((int)symbol.Value, (int)symbol.Size));
    }

    /// <summary>Queues the section relocations that fall inside the function, rebased
    /// to the function's position in the combined stream.</summary>
    private static void EnqueueRelocations(
        Queue<(int, ElfRelocation)> pending, IElfSection section, in ElfSymbol function,
        int combinedBase)
    {
        foreach (var relocation in section.Relocations)
        {
            if (relocation.Offset < function.Value ||
                relocation.Offset >= function.Value + function.Size)
                continue;

            if (relocation.Offset % 8 != 0)
                throw new InvalidDataException(
                    $"Relocation at 0x{relocation.Offset:X} in '{section.Name}' is not on " +
                    "an instruction boundary.");

            pending.Enqueue((combinedBase + (int)((relocation.Offset - function.Value) / 8),
                             relocation));
        }
    }

    private static ElfSymbol ResolveSymbol(IElfObject elf, in ElfRelocation relocation)
    {
        if (relocation.SymbolIndex >= elf.Symbols.Count)
            throw new InvalidDataException(
                $"Relocation names symbol {relocation.SymbolIndex}, " +
                "which is outside the symbol table.");
        return elf.Symbols[(int)relocation.SymbolIndex];
    }

    /// <summary>The section a relocated symbol lives in. Undefined symbols are the
    /// extern case, which Phase 1 does not handle.</summary>
    private static IElfSection ResolveSection(IElfObject elf, string programName, in ElfSymbol symbol)
    {
        if (symbol.SectionIndex == 0 || symbol.SectionIndex >= elf.Sections.Count)
            throw new NotSupportedException(
                $"Program '{programName}': symbol '{symbol.Name}' is undefined or in a " +
                "special section — externs are not supported yet.");
        return elf.Sections[symbol.SectionIndex];
    }
}
