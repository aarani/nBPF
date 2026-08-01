namespace Nbpf.Elf;

internal sealed class ElfSection : IElfSection
{
    internal ElfSection(int index, string name, ElfSectionType type, ElfSectionFlags flags,
        ulong address, ulong offset, ulong size, uint link, uint info, ulong addressAlign,
        ulong entrySize, byte[] data)
    {
        Index = index;
        Name = name;
        Type = type;
        Flags = flags;
        Address = address;
        Offset = offset;
        Size = size;
        Link = link;
        Info = info;
        AddressAlign = addressAlign;
        EntrySize = entrySize;
        Data = data;
    }

    public int Index { get; }
    public string Name { get; }
    public ElfSectionType Type { get; }
    public ElfSectionFlags Flags { get; }
    public ulong Address { get; }
    public ulong Offset { get; }
    public ulong Size { get; }
    public uint Link { get; }
    public uint Info { get; }
    public ulong AddressAlign { get; }
    public ulong EntrySize { get; }
    public byte[] Data { get; }

    public IReadOnlyList<ElfRelocation> Relocations { get; private set; } = Array.Empty<ElfRelocation>();

    internal void AttachRelocations(ElfRelocation[] relocations) =>
        Relocations = Array.AsReadOnly(relocations);

    public override string ToString() => $"[{Index}] {Name} ({Type}, {Size} bytes)";
}

internal sealed class ElfObject : IElfObject
{
    private readonly ElfSection[] _sections;

    internal ElfObject(ElfClass elfClass, ElfEndianness endianness, ElfFileType fileType,
        ElfMachine machine, ElfSection[] sections, ElfSymbol[] symbols)
    {
        Class = elfClass;
        Endianness = endianness;
        FileType = fileType;
        Machine = machine;
        _sections = sections;
        Sections = Array.AsReadOnly(sections);
        Symbols = Array.AsReadOnly(symbols);
    }

    public ElfClass Class { get; }
    public ElfEndianness Endianness { get; }
    public ElfFileType FileType { get; }
    public ElfMachine Machine { get; }
    public IReadOnlyList<IElfSection> Sections { get; }
    public IReadOnlyList<ElfSymbol> Symbols { get; }

    public IElfSection? FindSection(string name)
    {
        foreach (var section in _sections)
        {
            // Skip index 0: its name is empty, and so is the caller's mistake if they ask for "".
            if (section.Index != 0 && section.Name == name)
                return section;
        }

        return null;
    }
}
