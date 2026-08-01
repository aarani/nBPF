using Ebpf.Elf;

namespace Ebpf.Elf.Tests;

/// <summary>
/// The shared fixture object. Parsed once; every expectation in these tests was taken from
/// <c>llvm-readelf</c> run against the same file, so the oracle is independent of this reader.
/// </summary>
internal static class ElfFixture
{
    internal const string ExecveProgram = "tracepoint/syscalls/sys_enter_execve";
    internal const string OpenatProgram = "tracepoint/syscalls/sys_enter_openat";

    private static readonly Lazy<byte[]> RawBytes = new(() =>
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "sample.bpf.o")));

    private static readonly Lazy<IElfObject> Parsed = new(() => ElfReader.Read(RawBytes.Value));

    internal static byte[] Bytes => RawBytes.Value;

    internal static IElfObject Object => Parsed.Value;

    internal static IElfSection Section(string name) =>
        Object.FindSection(name) ?? throw new InvalidOperationException($"fixture has no section '{name}'");

    internal static ElfSymbol Symbol(string name) =>
        Object.Symbols.SingleOrDefault(s => s.Name == name) is { Name.Length: > 0 } symbol
            ? symbol
            : throw new InvalidOperationException($"fixture has no symbol '{name}'");
}
