using Nbpf.Core.Maps;
using Nbpf.Core.Native;
using Xunit;

namespace Nbpf.Core.Tests;

public class MapTests
{
    [LinuxFact]
    public void Create_hash_map_yields_valid_fd()
    {
        using var map = BpfMap<uint, ulong>.Create(BpfMapType.Hash, maxEntries: 16, name: "t_create");
        Assert.False(map.Handle.IsInvalid);
    }

    [LinuxFact]
    public void Update_then_lookup_roundtrips()
    {
        using var map = BpfMap<uint, ulong>.Create(BpfMapType.Hash, maxEntries: 16);
        map[42u] = 0xDEADBEEFUL;

        Assert.True(map.TryGetValue(42u, out var value));
        Assert.Equal(0xDEADBEEFUL, value);
    }

    [LinuxFact]
    public void Lookup_of_absent_key_returns_false()
    {
        using var map = BpfMap<uint, ulong>.Create(BpfMapType.Hash, maxEntries: 16);
        Assert.False(map.TryGetValue(7u, out _));
    }

    [LinuxFact]
    public void Delete_removes_the_key()
    {
        using var map = BpfMap<uint, ulong>.Create(BpfMapType.Hash, maxEntries: 16);
        map[1u] = 100;

        Assert.True(map.Delete(1u));
        Assert.False(map.TryGetValue(1u, out _));
        Assert.False(map.Delete(1u)); // second delete: key gone
    }

    [LinuxFact]
    public void NoExist_flag_rejects_existing_key()
    {
        using var map = BpfMap<uint, ulong>.Create(BpfMapType.Hash, maxEntries: 16);
        map.Update(5u, 1, MapUpdateFlags.NoExist);

        var ex = Assert.Throws<BpfException>(() => map.Update(5u, 2, MapUpdateFlags.NoExist));
        Assert.Equal(17, ex.Errno); // EEXIST
    }

    [LinuxFact]
    public void Enumerate_visits_every_entry()
    {
        using var map = BpfMap<uint, ulong>.Create(BpfMapType.Hash, maxEntries: 64);
        for (uint i = 0; i < 10; i++)
            map[i] = i * 100;

        var entries = map.Enumerate().OrderBy(kv => kv.Key).ToList();

        Assert.Equal(10, entries.Count);
        Assert.All(entries, kv => Assert.Equal(kv.Key * 100, kv.Value));
    }

    [LinuxFact]
    public void Array_map_is_prepopulated_with_zeroes()
    {
        using var map = BpfMap<uint, long>.Create(BpfMapType.Array, maxEntries: 4);
        Assert.True(map.TryGetValue(3u, out var value));
        Assert.Equal(0, value);
    }
}
