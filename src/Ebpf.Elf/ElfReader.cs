namespace Ebpf.Elf;

/// <summary>
/// Reads an ELF64 BPF object. Not implemented yet — the tests in Ebpf.Elf.Tests are the
/// specification, and they are red until this is filled in.
/// </summary>
public sealed class ElfReader : IElfReader
{
    /// <summary>Convenience entry point for callers that do not need the interface.</summary>
    public static IElfObject Read(byte[] elf) => new ElfReader().Parse(elf);

    public IElfObject Parse(byte[] elf) => throw new NotImplementedException("ELF reader: see DESIGN.md §4.2");
}
