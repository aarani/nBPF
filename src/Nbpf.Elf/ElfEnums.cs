namespace Nbpf.Elf;

public enum ElfClass : byte
{
    None = 0,
    Elf32 = 1,
    Elf64 = 2,
}

public enum ElfEndianness : byte
{
    None = 0,
    Little = 1,
    Big = 2,
}

/// <summary><c>e_type</c>. A compiled BPF object is always <see cref="Relocatable"/>.</summary>
public enum ElfFileType : ushort
{
    None = 0,
    Relocatable = 1,
    Executable = 2,
    Shared = 3,
    Core = 4,
}

/// <summary><c>e_machine</c>, restricted to the values this loader has any reason to see.</summary>
public enum ElfMachine : ushort
{
    None = 0,
    Bpf = 247,
}

public enum ElfSectionType : uint
{
    Null = 0,
    ProgBits = 1,
    SymTab = 2,
    StrTab = 3,
    Rela = 4,
    Hash = 5,
    Dynamic = 6,
    Note = 7,

    /// <summary>Occupies no file space but does have a size — this is how <c>.bss</c> is encoded.</summary>
    NoBits = 8,

    Rel = 9,
    DynSym = 11,
}

[Flags]
public enum ElfSectionFlags : ulong
{
    None = 0,
    Write = 0x1,
    Alloc = 0x2,
    Execute = 0x4,
    Merge = 0x10,
    Strings = 0x20,
    InfoLink = 0x40,
}

public enum ElfSymbolType : byte
{
    NoType = 0,
    Object = 1,
    Func = 2,
    Section = 3,
    File = 4,
}

public enum ElfSymbolBinding : byte
{
    Local = 0,
    Global = 1,
    Weak = 2,
}

/// <summary>
/// BPF relocation types, from the psABI. The loader only acts on a couple of these; the
/// rest exist so a diagnostic can name what it saw rather than printing a bare number.
/// </summary>
public enum BpfRelocationType : uint
{
    None = 0,

    /// <summary>64-bit immediate on an <c>ld_imm64</c> — how map fds and global data references arrive.</summary>
    Bpf64_64 = 1,

    Bpf64_Abs64 = 2,
    Bpf64_Abs32 = 3,
    Bpf64_NoDyld32 = 4,

    /// <summary>32-bit immediate on a <c>call</c> — how <c>BPF_PSEUDO_CALL</c> subprogram references arrive.</summary>
    Bpf64_32 = 10,
}
