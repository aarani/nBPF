using Nbpf.Core.Maps;
using Nbpf.Core.Native;

namespace Nbpf.Core.ObjectFile;

/// <summary>
/// One map created while loading a <see cref="BpfObject"/>. Untyped, because the
/// key/value shapes only exist in the object's BTF at this point; the generated
/// skeleton (or <see cref="AsTyped{TKey,TValue}"/>) supplies the C# view.
/// The owning <see cref="BpfObject"/> controls the fd's lifetime.
/// </summary>
public sealed class BpfObjectMap
{
    public string Name { get; }
    public BpfMapType Type { get; }
    public uint KeySize { get; }
    public uint ValueSize { get; }
    public uint MaxEntries { get; }
    public BpfMapHandle Handle { get; }

    internal BpfObjectMap(in BpfMapSpec spec, BpfMapHandle handle)
    {
        Name = spec.Name;
        Type = spec.Type;
        KeySize = spec.KeySize;
        ValueSize = spec.ValueSize;
        MaxEntries = spec.MaxEntries;
        Handle = handle;
    }

    /// <summary>
    /// A typed view over this map. The sizes of <typeparamref name="TKey"/> and
    /// <typeparamref name="TValue"/> must match the map's BTF-declared sizes —
    /// a mismatch would silently corrupt keys or values, so it throws instead.
    /// The view shares this map's fd; disposing the view is a no-op as long as
    /// the owning <see cref="BpfObject"/> is alive.
    /// </summary>
    public unsafe BpfMap<TKey, TValue> AsTyped<TKey, TValue>()
        where TKey : unmanaged where TValue : unmanaged
    {
        if (sizeof(TKey) != KeySize)
            throw new ArgumentException(
                $"Map '{Name}' has {KeySize}-byte keys, but {typeof(TKey).Name} is {sizeof(TKey)} bytes.");
        if (sizeof(TValue) != ValueSize)
            throw new ArgumentException(
                $"Map '{Name}' has {ValueSize}-byte values, but {typeof(TValue).Name} is {sizeof(TValue)} bytes.");

        return new BpfMap<TKey, TValue>(Handle, Type, MaxEntries);
    }
}
