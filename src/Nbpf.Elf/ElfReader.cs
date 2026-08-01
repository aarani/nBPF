namespace Nbpf.Elf;

/// <summary>
/// Reads an ELF64 BPF relocatable object. Scoped to what the loader needs (DESIGN.md §4.2):
/// no program headers, no dynamic linking, no 32-bit support.
/// </summary>
public sealed class ElfReader : IElfReader
{
    private const int EiClass = 4;
    private const int EiData = 5;
    private const int EiVersion = 6;

    private const int HeaderSize = 64;
    private const int SectionHeaderSize = 64;
    private const int SymbolSize = 24;
    private const int RelSize = 16;

    /// <summary>Section index values at or above this are reserved markers, not real sections.</summary>
    private const ushort ShnLoReserve = 0xFF00;

    /// <summary>Convenience entry point for callers that do not need the interface.</summary>
    public static IElfObject Read(byte[] elf) => new ElfReader().Parse(elf);

    public IElfObject Parse(byte[] elf)
    {
        if (elf is null)
            throw new ArgumentNullException(nameof(elf));

        var endianness = ReadIdent(elf);
        var c = new ElfCursor(elf, endianness == ElfEndianness.Big);

        var fileType = (ElfFileType)c.ReadU16(16);
        var machine = (ElfMachine)c.ReadU16(18);

        if (machine != ElfMachine.Bpf)
            throw new ElfFormatException($"not a BPF object: e_machine is {(ushort)machine}, expected {(ushort)ElfMachine.Bpf}");

        var sectionHeaderOffset = (long)c.ReadU64(0x28);
        var sectionHeaderEntrySize = c.ReadU16(0x3A);
        var sectionCount = (int)c.ReadU16(0x3C);
        var sectionNameTableIndex = (int)c.ReadU16(0x3E);

        if (sectionHeaderEntrySize != SectionHeaderSize)
            throw new ElfFormatException(
                $"unexpected e_shentsize {sectionHeaderEntrySize}, expected {SectionHeaderSize}");

        if (sectionCount == 0)
            throw new ElfFormatException("ELF has no section headers; nothing to load");

        // Validate the whole table up front so a bogus e_shoff fails here rather than
        // partway through with a confusing per-section message.
        c.Require(sectionHeaderOffset, (long)sectionCount * SectionHeaderSize);

        if (sectionNameTableIndex <= 0 || sectionNameTableIndex >= sectionCount)
            throw new ElfFormatException(
                $"e_shstrndx {sectionNameTableIndex} does not name a section (there are {sectionCount})");

        var headers = ReadSectionHeaders(c, sectionHeaderOffset, sectionCount);
        var sections = BuildSections(c, headers, headers[sectionNameTableIndex].Offset);
        var symbols = ReadSymbols(c, sections);

        AttachRelocations(c, sections, headers);

        return new ElfObject(ElfClass.Elf64, endianness, fileType, machine, sections, symbols);
    }

    private static ElfEndianness ReadIdent(byte[] elf)
    {
        if (elf.Length < 4)
            throw new ElfFormatException($"truncated ELF: {elf.Length} byte(s), too short to identify");

        if (elf[0] != 0x7F || elf[1] != (byte)'E' || elf[2] != (byte)'L' || elf[3] != (byte)'F')
            throw new ElfFormatException(
                $"not an ELF file: expected magic 7F 45 4C 46, found " +
                $"{elf[0]:X2} {elf[1]:X2} {elf[2]:X2} {elf[3]:X2}");

        if (elf.Length < HeaderSize)
            throw new ElfFormatException(
                $"truncated ELF: {elf.Length} byte(s), need at least {HeaderSize} for the header");

        var elfClass = (ElfClass)elf[EiClass];
        if (elfClass != ElfClass.Elf64)
            throw new ElfFormatException(
                $"only 64-bit ELF is supported; this object is {(elfClass == ElfClass.Elf32 ? "32-bit" : $"class {(byte)elfClass}")}");

        var endianness = (ElfEndianness)elf[EiData];
        if (endianness != ElfEndianness.Little && endianness != ElfEndianness.Big)
            throw new ElfFormatException($"unrecognized ELF data encoding {(byte)endianness}");

        if (elf[EiVersion] != 1)
            throw new ElfFormatException($"unsupported ELF ident version {elf[EiVersion]}");

        return endianness;
    }

    /// <summary>The raw section header fields, before names and contents are attached.</summary>
    private readonly struct SectionHeader
    {
        internal SectionHeader(uint nameOffset, ElfSectionType type, ElfSectionFlags flags, ulong address,
            long offset, long size, uint link, uint info, ulong addressAlign, ulong entrySize)
        {
            NameOffset = nameOffset;
            Type = type;
            Flags = flags;
            Address = address;
            Offset = offset;
            Size = size;
            Link = link;
            Info = info;
            AddressAlign = addressAlign;
            EntrySize = entrySize;
        }

        internal uint NameOffset { get; }
        internal ElfSectionType Type { get; }
        internal ElfSectionFlags Flags { get; }
        internal ulong Address { get; }
        internal long Offset { get; }
        internal long Size { get; }
        internal uint Link { get; }
        internal uint Info { get; }
        internal ulong AddressAlign { get; }
        internal ulong EntrySize { get; }
    }

    private static SectionHeader[] ReadSectionHeaders(ElfCursor c, long tableOffset, int count)
    {
        var headers = new SectionHeader[count];

        for (var i = 0; i < count; i++)
        {
            var o = tableOffset + ((long)i * SectionHeaderSize);
            headers[i] = new SectionHeader(
                nameOffset: c.ReadU32(o),
                type: (ElfSectionType)c.ReadU32(o + 4),
                flags: (ElfSectionFlags)c.ReadU64(o + 8),
                address: c.ReadU64(o + 16),
                offset: (long)c.ReadU64(o + 24),
                size: (long)c.ReadU64(o + 32),
                link: c.ReadU32(o + 40),
                info: c.ReadU32(o + 44),
                addressAlign: c.ReadU64(o + 48),
                entrySize: c.ReadU64(o + 56));
        }

        return headers;
    }

    private static ElfSection[] BuildSections(ElfCursor c, SectionHeader[] headers, long nameTableOffset)
    {
        var sections = new ElfSection[headers.Length];

        for (var i = 0; i < headers.Length; i++)
        {
            var h = headers[i];
            var name = i == 0 ? string.Empty : c.ReadString(nameTableOffset + h.NameOffset, $"section {i} name");

            // NOBITS (.bss) declares a size but occupies no file space, so there is nothing to
            // copy and nothing to bounds-check. Callers must size it from Size, not Data.
            var data = h.Type is ElfSectionType.NoBits or ElfSectionType.Null || h.Size == 0
                ? Array.Empty<byte>()
                : c.ReadBytes(h.Offset, h.Size);

            sections[i] = new ElfSection(i, name, h.Type, h.Flags, h.Address, (ulong)h.Offset,
                (ulong)h.Size, h.Link, h.Info, h.AddressAlign, h.EntrySize, data);
        }

        return sections;
    }

    private static ElfSymbol[] ReadSymbols(ElfCursor c, ElfSection[] sections)
    {
        var symtab = Array.Find(sections, s => s.Type == ElfSectionType.SymTab);
        if (symtab is null)
            return Array.Empty<ElfSymbol>();

        if (symtab.Link >= sections.Length)
            throw new ElfFormatException($"{symtab.Name} sh_link {symtab.Link} does not name a string table");

        var strtab = sections[symtab.Link];
        var entrySize = symtab.EntrySize == 0 ? SymbolSize : (long)symtab.EntrySize;
        if (entrySize != SymbolSize)
            throw new ElfFormatException($"unexpected symbol entry size {entrySize}, expected {SymbolSize}");

        var count = (long)symtab.Size / entrySize;
        var symbols = new ElfSymbol[count];

        for (var i = 0L; i < count; i++)
        {
            var o = (long)symtab.Offset + (i * entrySize);
            var nameOffset = c.ReadU32(o);
            var info = c.ReadU8(o + 4);
            var sectionIndex = c.ReadU16(o + 6);
            var value = c.ReadU64(o + 8);
            var size = c.ReadU64(o + 16);

            var type = (ElfSymbolType)(info & 0x0F);
            var binding = (ElfSymbolBinding)(info >> 4);

            symbols[i] = new ElfSymbol(
                (int)i,
                ResolveSymbolName(c, nameOffset, type, sectionIndex, sections, strtab),
                value,
                size,
                type,
                binding,
                sectionIndex);
        }

        return symbols;
    }

    /// <summary>
    /// Section symbols are emitted with <c>st_name == 0</c>, so their name has to come from the
    /// section they refer to. This matters: subprogram-call relocations reference <c>.text</c>
    /// through its section symbol, and without this they would resolve to an empty name.
    /// </summary>
    private static string ResolveSymbolName(ElfCursor c, uint nameOffset, ElfSymbolType type,
        ushort sectionIndex, ElfSection[] sections, ElfSection strtab)
    {
        if (nameOffset != 0)
            return c.ReadString((long)strtab.Offset + nameOffset, "symbol name");

        if (type == ElfSymbolType.Section && sectionIndex < ShnLoReserve && sectionIndex < sections.Length)
            return sections[sectionIndex].Name;

        return string.Empty;
    }

    private static void AttachRelocations(ElfCursor c, ElfSection[] sections, SectionHeader[] headers)
    {
        for (var i = 0; i < sections.Length; i++)
        {
            var relSection = sections[i];
            if (relSection.Type != ElfSectionType.Rel)
                continue;

            // sh_info names the section these relocations apply to.
            var targetIndex = relSection.Info;
            if (targetIndex == 0 || targetIndex >= sections.Length)
                throw new ElfFormatException(
                    $"{relSection.Name} sh_info {targetIndex} does not name a section to relocate");

            var entrySize = relSection.EntrySize == 0 ? RelSize : (long)relSection.EntrySize;
            if (entrySize != RelSize)
                throw new ElfFormatException(
                    $"{relSection.Name} has entry size {entrySize}, expected {RelSize} (SHT_RELA is not used by BPF)");

            var count = (long)relSection.Size / entrySize;
            var relocations = new ElfRelocation[count];

            for (var k = 0L; k < count; k++)
            {
                var o = (long)relSection.Offset + (k * entrySize);
                var offset = c.ReadU64(o);
                var info = c.ReadU64(o + 8);

                relocations[k] = new ElfRelocation(
                    offset,
                    SymbolIndex: (uint)(info >> 32),
                    Type: (BpfRelocationType)(uint)(info & 0xFFFFFFFF));
            }

            sections[targetIndex].AttachRelocations(relocations);
        }
    }
}
