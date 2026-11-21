using Xunit;

namespace Nbpf.Btf.Tests;

/// <summary>
/// The offline half of phase 2's exit criterion ("same binary runs on 5.4 and 6.8"):
/// one object's CO-RE relocations (tests/Nbpf.Elf.Tests/Fixtures/core-kernels.bpf.c)
/// resolved against the real vmlinux BTF of Ubuntu's 5.4.0-26 and 6.8.0-31 kernels,
/// minimized to the types the object touches (eng/gen-kernel-btf.sh).
///
/// <para>Expected values come from <c>bpftool btf dump</c> of the <em>full</em> kernel BTF,
/// not from this parser, so they're an independent check on both the minimized
/// fixtures and the resolver. Byte offsets are bpftool's bits_offset / 8.</para>
/// </summary>
public class CoreReloCrossKernelTests
{
    public const string Ubuntu54 = "5.4.0-26-generic";
    public const string Ubuntu68 = "6.8.0-31-generic";

    private static readonly byte[] LocalBtfBytes = Fixture("core-kernels.btf");
    private static readonly IBtfTypeGraph Local = BtfReader.Read(LocalBtfBytes);

    private static readonly IReadOnlyList<BtfCoreRelo> Relos =
        BtfExtReader.Read(Fixture("core-kernels.btf.ext"), LocalBtfBytes)
            .CoreRelos.SelectMany(s => s.Records).ToList();

    private static readonly Dictionary<string, IBtfTypeGraph> Kernels = new()
    {
        [Ubuntu54] = BtfReader.Read(Fixture($"vmlinux-{Ubuntu54}.min.btf")),
        [Ubuntu68] = BtfReader.Read(Fixture($"vmlinux-{Ubuntu68}.min.btf")),
    };

    [Theory]
    [InlineData(Ubuntu54, 2264ul, 2268ul)]
    [InlineData(Ubuntu68, 2464ul, 2468ul)]
    public void Task_struct_pid_and_tgid_land_on_each_kernels_real_offsets(
        string kernel, ulong pid, ulong tgid)
    {
        Assert.Equal(pid, Resolve(kernel, BtfCoreReloKind.FieldByteOffset, "task_struct", "0:0"));
        Assert.Equal(tgid, Resolve(kernel, BtfCoreReloKind.FieldByteOffset, "task_struct", "0:1"));
    }

    [Fact]
    public void On_5_4_only_the_old_state_flavor_exists()
    {
        Assert.Equal(0ul, Resolve(Ubuntu54, BtfCoreReloKind.FieldExists, "task_struct", "0:2"));
        Assert.Equal(1ul, Resolve(Ubuntu54, BtfCoreReloKind.FieldExists, "task_struct___old", "0:0"));

        // volatile long state, 16 bytes in.
        Assert.Equal(16ul, Resolve(Ubuntu54, BtfCoreReloKind.FieldByteOffset, "task_struct___old", "0:0"));
        Assert.Equal(8ul, Resolve(Ubuntu54, BtfCoreReloKind.FieldByteSize, "task_struct___old", "0:0"));

        // The __state read sits behind the exists check, so poisoning it is harmless.
        Assert.True(Poisoned(Ubuntu54, BtfCoreReloKind.FieldByteOffset, "task_struct", "0:2"));
    }

    [Fact]
    public void On_6_8_only_the_renamed_state_exists()
    {
        Assert.Equal(1ul, Resolve(Ubuntu68, BtfCoreReloKind.FieldExists, "task_struct", "0:2"));
        Assert.Equal(0ul, Resolve(Ubuntu68, BtfCoreReloKind.FieldExists, "task_struct___old", "0:0"));

        // unsigned int __state, 24 bytes in.
        Assert.Equal(24ul, Resolve(Ubuntu68, BtfCoreReloKind.FieldByteOffset, "task_struct", "0:2"));

        Assert.True(Poisoned(Ubuntu68, BtfCoreReloKind.FieldByteOffset, "task_struct___old", "0:0"));
        Assert.True(Poisoned(Ubuntu68, BtfCoreReloKind.FieldByteSize, "task_struct___old", "0:0"));
    }

    [Theory]
    [InlineData(Ubuntu54, 9280ul)]
    [InlineData(Ubuntu68, 13696ul)]
    public void Task_struct_size_is_the_kernels(string kernel, ulong size)
    {
        Assert.Equal(size, Resolve(kernel, BtfCoreReloKind.TypeSize, "task_struct", "0"));
    }

    [Theory]
    [InlineData(Ubuntu54, 0ul)]
    [InlineData(Ubuntu68, 1ul)]
    public void Ring_buffer_support_is_detected_by_type_and_by_enum_value(string kernel, ulong exists)
    {
        // Both arrived in 5.8: struct bpf_ringbuf, and BPF_MAP_TYPE_RINGBUF (local
        // enumerator index 1 in core-kernels.bpf.c's stand-in enum).
        Assert.Equal(exists, Resolve(kernel, BtfCoreReloKind.TypeExists, "bpf_ringbuf", "0"));
        Assert.Equal(exists, Resolve(kernel, BtfCoreReloKind.EnumValExists, "bpf_map_type", "1"));
    }

    [Theory]
    [InlineData(Ubuntu54)]
    [InlineData(Ubuntu68)]
    public void Sk_buff_pkt_type_bitfield_reads_the_same_byte_on_both_kernels(string kernel)
    {
        // A __u8 pkt_type:3 at bit 1024 on both kernels — but 6.8 reaches it through an
        // anonymous union and struct, which the matcher has to descend into. One-byte
        // load at byte 128; lshift = 64 - (1024 + 3 - 8*128) = 61; rshift = 64 - 3.
        Assert.Equal(128ul, Resolve(kernel, BtfCoreReloKind.FieldByteOffset, "sk_buff", "0:0"));
        Assert.Equal(1ul, Resolve(kernel, BtfCoreReloKind.FieldByteSize, "sk_buff", "0:0"));
        Assert.Equal(0ul, Resolve(kernel, BtfCoreReloKind.FieldSigned, "sk_buff", "0:0"));
        Assert.Equal(61ul, Resolve(kernel, BtfCoreReloKind.FieldLShiftU64, "sk_buff", "0:0"));
        Assert.Equal(61ul, Resolve(kernel, BtfCoreReloKind.FieldRShiftU64, "sk_buff", "0:0"));
    }

    [Fact]
    public void Every_relocation_in_the_object_is_covered_above()
    {
        // Keeps the fixture and these tests in step: a relo added to core-kernels.bpf.c
        // without an expectation here fails this test rather than going unchecked.
        var covered = new HashSet<(BtfCoreReloKind, string, string)>
        {
            (BtfCoreReloKind.FieldByteOffset, "task_struct", "0:0"),
            (BtfCoreReloKind.FieldByteOffset, "task_struct", "0:1"),
            (BtfCoreReloKind.FieldByteOffset, "task_struct", "0:2"),
            (BtfCoreReloKind.FieldExists, "task_struct", "0:2"),
            (BtfCoreReloKind.FieldExists, "task_struct___old", "0:0"),
            (BtfCoreReloKind.FieldByteOffset, "task_struct___old", "0:0"),
            (BtfCoreReloKind.FieldByteSize, "task_struct___old", "0:0"),
            (BtfCoreReloKind.TypeSize, "task_struct", "0"),
            (BtfCoreReloKind.TypeExists, "bpf_ringbuf", "0"),
            (BtfCoreReloKind.EnumValExists, "bpf_map_type", "1"),
            (BtfCoreReloKind.FieldByteOffset, "sk_buff", "0:0"),
            (BtfCoreReloKind.FieldByteSize, "sk_buff", "0:0"),
            (BtfCoreReloKind.FieldSigned, "sk_buff", "0:0"),
            (BtfCoreReloKind.FieldLShiftU64, "sk_buff", "0:0"),
            (BtfCoreReloKind.FieldRShiftU64, "sk_buff", "0:0"),
        };

        Assert.Equal(covered, Relos.Select(r => (r.Kind, RootName(r), r.AccessString)).ToHashSet());
    }

    private static ulong Resolve(string kernel, BtfCoreReloKind kind, string root, string access)
    {
        var results = Matching(kernel, kind, root, access);
        Assert.All(results, r => Assert.False(r.Poison, $"{kind} {root} {access} poisoned on {kernel}"));
        return Assert.Single(results.Select(r => r.NewValue).Distinct());
    }

    private static bool Poisoned(string kernel, BtfCoreReloKind kind, string root, string access) =>
        Matching(kernel, kind, root, access).All(r => r.Poison);

    /// <summary>Every relo for (kind, root, access) — clang may emit one per use site.</summary>
    private static List<CoreReloResult> Matching(string kernel, BtfCoreReloKind kind, string root, string access)
    {
        var resolver = new CoreReloResolver();
        var results = Relos
            .Where(r => r.Kind == kind && r.AccessString == access && RootName(r) == root)
            .Select(r => resolver.Resolve(r, Local, Kernels[kernel]))
            .ToList();
        Assert.NotEmpty(results);
        return results;
    }

    private static string RootName(BtfCoreRelo relo) =>
        Local.TryGetType((int)relo.TypeId, out var type) ? type.Name : "";

    private static byte[] Fixture(string name) =>
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));
}
