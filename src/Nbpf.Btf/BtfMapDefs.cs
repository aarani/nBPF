namespace Nbpf.Btf;

/// <summary>
/// One BTF-defined map decoded from a ".maps" datasec. Numeric fields carry the raw
/// linux/bpf.h values (BPF_MAP_TYPE_*, BPF_F_*); this library deliberately has no
/// syscall-layer enums to hand out — the loader owns that mapping.
/// <see cref="KeySize"/>/<see cref="ValueSize"/> are 0 when the definition supplies
/// neither a size nor a type (legitimate for e.g. ringbuf maps).
/// </summary>
public readonly record struct BtfMapDef(
    string Name,
    uint MapType,
    uint MaxEntries,
    uint KeySize,
    uint ValueSize,
    IBtfType? KeyType,
    IBtfType? ValueType,
    uint MapFlags);

/// <summary>
/// Decodes the libbpf map-definition idiom from a ".maps" datasec: each map is a
/// struct variable whose members encode attributes *in their types* — scalar
/// attributes (<c>__uint</c>) as pointer-to-array where the array length is the
/// value, and key/value (<c>__type</c>) as plain pointers whose pointee is the
/// key/value type.
/// </summary>
public static class BtfMapDefReader
{
    /// <summary>
    /// Decodes every variable of the ".maps" datasec, in datasec order.
    /// Returns an empty list when the graph has no ".maps" datasec.
    /// </summary>
    public static IReadOnlyList<BtfMapDef> Read(IBtfTypeGraph graph)
    {
        if (graph == null) throw new ArgumentNullException(nameof(graph));

        if (graph.Find(".maps", BtfKind.Datasec) is not IBtfDatasec datasec)
            return Array.Empty<BtfMapDef>();

        var defs = new List<BtfMapDef>(datasec.Variables.Count);
        foreach (var entry in datasec.Variables)
            defs.Add(ReadOne(entry.Variable));
        return defs;
    }

    private static BtfMapDef ReadOne(IBtfVar variable)
    {
        if (Peel(variable.Type) is not IBtfStruct definition)
            throw new BtfFormatException(
                $"Map '{variable.Name}' in .maps is a {variable.Type.Kind}, not a struct definition.");

        uint mapType = 0, maxEntries = 0, keySize = 0, valueSize = 0, mapFlags = 0;
        IBtfType? keyType = null, valueType = null;

        foreach (var member in definition.Members)
        {
            switch (member.Name)
            {
                case "type": mapType = ScalarAttribute(variable.Name, member); break;
                case "max_entries": maxEntries = ScalarAttribute(variable.Name, member); break;
                case "map_flags": mapFlags = ScalarAttribute(variable.Name, member); break;
                case "key_size": keySize = ScalarAttribute(variable.Name, member); break;
                case "value_size": valueSize = ScalarAttribute(variable.Name, member); break;
                case "key": keyType = TypeAttribute(variable.Name, member, ref keySize); break;
                case "value": valueType = TypeAttribute(variable.Name, member, ref valueSize); break;
                default:
                    // Silently ignoring a member would turn a typo (or an idiom we
                    // don't handle yet, e.g. "values" for map-in-map) into a map
                    // with quietly wrong attributes. Refuse instead, like libbpf.
                    throw new BtfFormatException(
                        $"Map '{variable.Name}' in .maps has unsupported member '{member.Name}'.");
            }
        }

        return new BtfMapDef(
            variable.Name, mapType, maxEntries, keySize, valueSize, keyType, valueType, mapFlags);
    }

    /// <summary>The __uint idiom: <c>int (*name)[N]</c>, where N is the value.</summary>
    private static uint ScalarAttribute(string mapName, in BtfMember member)
    {
        if (Peel(member.Type) is IBtfPtr ptr && Peel(ptr.Pointee) is IBtfArray array)
            return array.Length;

        throw new BtfFormatException(
            $"Map '{mapName}' member '{member.Name}' is not the pointer-to-array __uint idiom.");
    }

    /// <summary>The __type idiom: a plain pointer whose pointee is the key/value type.
    /// Also fills in the size from the pointee unless an explicit *_size already did.</summary>
    private static IBtfType? TypeAttribute(string mapName, in BtfMember member, ref uint size)
    {
        if (Peel(member.Type) is not IBtfPtr ptr)
            throw new BtfFormatException(
                $"Map '{mapName}' member '{member.Name}' is not a pointer (__type idiom).");

        if (ptr.Pointee is null) // void* — size must come from key_size/value_size
            return null;

        if (size == 0)
            size = SizeOf(ptr.Pointee, mapName, member.Name);
        return ptr.Pointee;
    }

    /// <summary>Byte size of a BTF type, following the C sizeof rules for the kinds
    /// that can appear in a map key/value.</summary>
    private static uint SizeOf(IBtfType type, string mapName, string memberName)
    {
        var peeled = Peel(type) ?? throw new BtfFormatException(
            $"Map '{mapName}' member '{memberName}' resolves to void, which has no size.");

        return peeled switch
        {
            IBtfInt i => (uint)i.SizeBytes,
            IBtfStruct s => (uint)s.SizeBytes,
            IBtfUnion u => (uint)u.SizeBytes,
            IBtfEnum e => (uint)e.SizeBytes,
            IBtfEnum64 e => (uint)e.SizeBytes,
            IBtfFloat f => (uint)f.SizeBytes,
            IBtfPtr => 8, // BPF is a 64-bit target
            IBtfArray a => a.Length * SizeOf(a.ElementType, mapName, memberName),
            _ => throw new BtfFormatException(
                $"Map '{mapName}' member '{memberName}' has a {peeled.Kind}, which has no size."),
        };
    }

    /// <summary>Follows typedefs, qualifiers, and type tags to the underlying type.
    /// Null in, null out (void stays void).</summary>
    private static IBtfType? Peel(IBtfType? type)
    {
        while (true)
        {
            switch (type)
            {
                case IBtfTypedef t: type = t.Target; break;
                case IBtfQualifier q: type = q.Target; break;
                case IBtfTypeTag t: type = t.Target; break;
                default: return type;
            }
        }
    }
}
