using Nbpf.Btf;
using Nbpf.Core.Native;
using Nbpf.Elf;

namespace Nbpf.Core.ObjectFile;

/// <summary>Everything needed to create one map for an object: a decoded user map
/// definition or a synthesized global-data section map. Pure data — no fds yet.</summary>
internal readonly record struct BpfMapSpec(
    string Name,            // "counts", or the section name ".rodata"/".data"/".bss"
    BpfMapType Type,
    uint KeySize,
    uint ValueSize,
    uint MaxEntries,
    BpfMapCreateFlags Flags,
    byte[]? InitialValue,   // written at key 0 before load; null = nothing to write
    bool Freeze);           // BPF_MAP_FREEZE after populating (only .rodata)

/// <summary>
/// Decides which maps an object needs: the BTF-defined user maps from ".maps",
/// plus one single-entry array per global-data section. Pure — no syscalls.
/// </summary>
internal static class BpfMapPlanner
{
    internal static IReadOnlyList<BpfMapSpec> Plan(IElfObject elf, IBtfTypeGraph? btf)
    {
        var specs = new List<BpfMapSpec>();

        if (elf.FindSection(".maps") is not null)
        {
            if (btf is null)
                throw new NotSupportedException(
                    "The object has a .maps section but no .BTF section; " +
                    "BTF-defined maps cannot be decoded without it.");

            foreach (var def in BtfMapDefReader.Read(btf))
                specs.Add(UserMap(def));
        }

        // DESIGN §4.4: clang emits DATASEC sizes of zero in an unlinked .o, so the
        // value size must come from the ELF section header, never from BTF.
        foreach (var name in new[] { ".rodata", ".data", ".bss" })
        {
            if (elf.FindSection(name) is { Size: > 0 } section)
                specs.Add(GlobalDataMap(section));
        }

        return specs;
    }

    private static BpfMapSpec UserMap(in BtfMapDef def)
    {
        var type = (BpfMapType)def.MapType;
        if (!Enum.IsDefined(type))
            throw new NotSupportedException(
                $"Map '{def.Name}' has BPF_MAP_TYPE {def.MapType}, which is not supported yet.");

        return new BpfMapSpec(
            def.Name, type, def.KeySize, def.ValueSize, def.MaxEntries,
            (BpfMapCreateFlags)def.MapFlags, InitialValue: null, Freeze: false);
    }

    private static BpfMapSpec GlobalDataMap(IElfSection section)
    {
        bool isRodata = section.Name == ".rodata";
        // .bss is SHT_NOBITS — no bytes in the file, and none needed: the kernel
        // zero-initializes array map values.
        byte[]? initial = section.Type == ElfSectionType.NoBits ? null : section.Data;

        return new BpfMapSpec(
            section.Name,
            BpfMapType.Array,
            KeySize: 4,
            ValueSize: (uint)section.Size,
            MaxEntries: 1,
            isRodata ? BpfMapCreateFlags.RdonlyProg : BpfMapCreateFlags.None,
            initial,
            Freeze: isRodata);
    }
}
