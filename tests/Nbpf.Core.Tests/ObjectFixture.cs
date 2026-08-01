using Nbpf.Btf;
using Nbpf.Elf;

namespace Nbpf.Core.Tests;

/// <summary>
/// The clang-compiled relocatable object shared with Nbpf.Elf.Tests (linked into
/// this project's Fixtures/ at build time). See that project's Fixtures/sample.bpf.c
/// for the source; regenerate with eng/gen-fixtures.sh.
/// </summary>
internal static class ObjectFixture
{
    internal static byte[] Bytes { get; } =
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "sample.bpf.o"));

    private static readonly Lazy<IElfObject> _elf = new(() => ElfReader.Read(Bytes));
    internal static IElfObject Elf => _elf.Value;

    private static readonly Lazy<IBtfTypeGraph> _btf =
        new(() => BtfReader.Read(Elf.FindSection(".BTF")!.Data));
    internal static IBtfTypeGraph Btf => _btf.Value;
}
