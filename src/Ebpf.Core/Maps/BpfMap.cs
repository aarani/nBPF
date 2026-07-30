using Ebpf.Core.Native;

namespace Ebpf.Core.Maps;

/// <summary>
/// A typed BPF map. Phase 0 cut: create + element CRUD + key enumeration.
/// Batch ops and per-CPU maps come later (per-CPU intentionally gets its own type).
/// </summary>
public sealed unsafe class BpfMap<TKey, TValue> : IDisposable
    where TKey : unmanaged
    where TValue : unmanaged
{
    public BpfMapHandle Handle { get; }
    public BpfMapType Type { get; }
    public uint MaxEntries { get; }

    private BpfMap(BpfMapHandle handle, BpfMapType type, uint maxEntries)
    {
        Handle = handle;
        Type = type;
        MaxEntries = maxEntries;
    }

    public static BpfMap<TKey, TValue> Create(BpfMapType type, uint maxEntries, string? name = null)
    {
        var handle = BpfSyscall.CreateMap(
            type, (uint)sizeof(TKey), (uint)sizeof(TValue), maxEntries, flags: 0, name);
        return new BpfMap<TKey, TValue>(handle, type, maxEntries);
    }

    public bool TryGetValue(in TKey key, out TValue value)
    {
        fixed (TKey* k = &key)
        fixed (TValue* v = &value)
        {
            return BpfSyscall.LookupElem(Handle, k, v);
        }
    }

    public TValue this[in TKey key]
    {
        get => TryGetValue(in key, out var value)
            ? value
            : throw new KeyNotFoundException($"Key not present in BPF map.");
        set => Update(in key, in value, MapUpdateFlags.Any);
    }

    public void Update(in TKey key, in TValue value, MapUpdateFlags flags = MapUpdateFlags.Any)
    {
        fixed (TKey* k = &key)
        fixed (TValue* v = &value)
        {
            BpfSyscall.UpdateElem(Handle, k, v, flags);
        }
    }

    public bool Delete(in TKey key)
    {
        fixed (TKey* k = &key)
        {
            return BpfSyscall.DeleteElem(Handle, k);
        }
    }

    /// <summary>
    /// Walks the map with GET_NEXT_KEY. Two syscalls per entry — fine for small
    /// maps; batch lookup will replace this for bulk reads.
    /// </summary>
    public IEnumerable<KeyValuePair<TKey, TValue>> Enumerate()
    {
        TKey current = default;
        bool hasCurrent = TryGetFirstKey(out current);
        while (hasCurrent)
        {
            if (TryGetValue(in current, out var value))
                yield return new KeyValuePair<TKey, TValue>(current, value);
            hasCurrent = TryGetNextKey(in current, out current);
        }
    }

    private bool TryGetFirstKey(out TKey first)
    {
        fixed (TKey* next = &first)
        {
            return BpfSyscall.GetNextKey(Handle, null, next);
        }
    }

    private bool TryGetNextKey(in TKey prev, out TKey next)
    {
        TKey prevCopy = prev; // kernel writes next before we stop reading prev; keep them distinct
        fixed (TKey* n = &next)
        {
            return BpfSyscall.GetNextKey(Handle, &prevCopy, n);
        }
    }

    public void Dispose() => Handle.Dispose();
}
