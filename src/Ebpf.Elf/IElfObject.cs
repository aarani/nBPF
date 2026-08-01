namespace Ebpf.Elf;

/// <summary>Thrown when an ELF object is malformed, truncated, or is not a BPF object.</summary>
public sealed class ElfFormatException : Exception
{
    public ElfFormatException(string message) : base(message) { }

    public ElfFormatException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>One entry of a <c>SHT_REL</c> section, already split out of <c>r_info</c>.</summary>
public readonly record struct ElfRelocation(ulong Offset, uint SymbolIndex, BpfRelocationType Type);

/// <summary>An entry of <c>.symtab</c>.</summary>
public readonly record struct ElfSymbol(
    int Index,
    string Name,
    ulong Value,
    ulong Size,
    ElfSymbolType Type,
    ElfSymbolBinding Binding,
    ushort SectionIndex);

/// <summary>One section header plus its contents.</summary>
public interface IElfSection
{
    /// <summary>Index into <see cref="IElfObject.Sections"/>, which is also the ELF section index.</summary>
    int Index { get; }

    string Name { get; }
    ElfSectionType Type { get; }
    ElfSectionFlags Flags { get; }
    ulong Address { get; }

    /// <summary>Byte offset of the contents within the file. Meaningless for <see cref="ElfSectionType.NoBits"/>.</summary>
    ulong Offset { get; }

    /// <summary>Declared size in bytes. For <c>.bss</c> this is non-zero even though <see cref="Data"/> is empty.</summary>
    ulong Size { get; }

    uint Link { get; }
    uint Info { get; }
    ulong AddressAlign { get; }
    ulong EntrySize { get; }

    /// <summary>
    /// The section contents. Always empty for <see cref="ElfSectionType.NoBits"/> — <c>.bss</c> occupies no
    /// file space — so size the corresponding array map from <see cref="Size"/>, never from this.
    /// </summary>
    byte[] Data { get; }

    /// <summary>
    /// Relocations that apply *to* this section, gathered from the matching <c>.rel</c> section.
    /// Empty when nothing relocates against it.
    /// </summary>
    IReadOnlyList<ElfRelocation> Relocations { get; }
}

/// <summary>
/// A parsed ELF64 relocatable object, scoped to what a BPF loader needs — see DESIGN.md §4.2.
/// Not a general-purpose ELF library.
/// </summary>
public interface IElfObject
{
    ElfClass Class { get; }
    ElfEndianness Endianness { get; }
    ElfFileType FileType { get; }
    ElfMachine Machine { get; }

    /// <summary>All sections in ELF section-index order, including the empty section at index 0.</summary>
    IReadOnlyList<IElfSection> Sections { get; }

    /// <summary>All <c>.symtab</c> entries in symbol-index order, as referenced by <see cref="ElfRelocation.SymbolIndex"/>.</summary>
    IReadOnlyList<ElfSymbol> Symbols { get; }

    /// <summary>The named section, or null. Section names are not unique in general, so this returns the first match.</summary>
    IElfSection? FindSection(string name);
}

/// <summary>Parses an ELF64 BPF object.</summary>
public interface IElfReader
{
    IElfObject Parse(byte[] elf);
}
