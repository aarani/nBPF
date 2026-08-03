using Xunit;

namespace Nbpf.Btf.Tests;

/// <summary>
/// Resolves the CO-RE relocations a real clang emitted (the core-sample object's
/// .BTF.ext, see eng/gen-fixtures.sh) against that object's own .BTF. With local and
/// target being the same graph, every relocation must resolve to its baked-in value —
/// the identity relocation libbpf performs when the kernel matches the headers.
/// </summary>
public class CoreReloClangFixtureTests
{
    private static readonly byte[] Btf =
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "core-sample.btf"));

    private static readonly byte[] BtfExt =
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "core-sample.btf.ext"));

    private static IBtfTypeGraph Graph => BtfReader.Read(Btf);

    private static IReadOnlyList<BtfCoreRelo> Relos =>
        BtfExtReader.Read(BtfExt, Btf).CoreRelos.SelectMany(s => s.Records).ToList();

    [Fact]
    public void Every_fixture_relocation_resolves_to_its_baked_in_value()
    {
        var graph = Graph;
        var resolver = new CoreReloResolver();

        Assert.NotEmpty(Relos);
        Assert.All(Relos, relo =>
        {
            var result = resolver.Resolve(relo, graph, graph);
            Assert.False(result.Poison);
            Assert.Equal(result.OldValue, result.NewValue);
        });
    }

    [Fact]
    public void The_pid_access_is_field_offset_zero()
    {
        // core-sample.bpf.c declares pid as task_struct's first member, so clang's
        // relo for &task->pid is spec "0:0" with a baked-in offset of 0.
        var pidRelos = Relos.Where(r =>
            r.Kind == BtfCoreReloKind.FieldByteOffset && r.AccessString == "0:0").ToList();

        Assert.NotEmpty(pidRelos);
        var resolver = new CoreReloResolver();
        Assert.All(pidRelos, relo =>
            Assert.Equal(0ul, resolver.Resolve(relo, Graph, Graph).NewValue));
    }

    [Fact]
    public void The_guarded_tgid_access_emits_an_exists_probe_that_resolves_to_one()
    {
        var existsRelos = Relos.Where(r => r.Kind == BtfCoreReloKind.FieldExists).ToList();

        Assert.NotEmpty(existsRelos);
        var resolver = new CoreReloResolver();
        Assert.All(existsRelos, relo =>
            Assert.Equal(1ul, resolver.Resolve(relo, Graph, Graph).NewValue));
    }
}
