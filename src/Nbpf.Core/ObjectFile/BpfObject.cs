using System.Text;
using Nbpf.Btf;
using Nbpf.Core.Native;
using Nbpf.Elf;

namespace Nbpf.Core.ObjectFile;

/// <summary>
/// A relocated and loaded compiled BPF object (a clang `.bpf.o`): every map
/// created, every global-data section materialized, every program accepted by
/// the verifier. Owns all the resulting fds. CO-RE relocations, externs, and
/// attachment are not handled yet — programs load but must be attached by the
/// caller once attachment exists.
/// </summary>
public sealed class BpfObject : IDisposable
{
    /// <summary>User maps by BTF name ("events", "counts") plus the global-data
    /// array maps by section name (".rodata", ".data", ".bss").</summary>
    public IReadOnlyDictionary<string, BpfObjectMap> Maps { get; }

    /// <summary>Loaded programs keyed by C function name ("handle_exec").</summary>
    public IReadOnlyDictionary<string, BpfProgram> Programs { get; }

    private BpfObject(
        Dictionary<string, BpfObjectMap> maps, Dictionary<string, BpfProgram> programs)
    {
        Maps = maps;
        Programs = programs;
    }

    public static BpfObject Load(byte[] objectFile)
    {
        var elf = ElfReader.Read(objectFile);
        var btf = elf.FindSection(".BTF") is { } btfSection
            ? BtfReader.Read(btfSection.Data)
            : null;

        var maps = new Dictionary<string, BpfObjectMap>();
        var programs = new Dictionary<string, BpfProgram>();
        try
        {
            foreach (var spec in BpfMapPlanner.Plan(elf, btf))
                maps.Add(spec.Name, CreateMap(spec));

            var mapFds = maps.ToDictionary(m => m.Key, m => m.Value.Handle.Fd);
            string license = License(elf);
            foreach (var linked in BpfLinker.Link(elf, mapFds))
            {
                var handle = BpfSyscall.LoadProgram(
                    linked.Type, linked.Insns, license, KernelName(linked.Name));
                programs.Add(linked.Name, new BpfProgram(handle, linked.Type));
            }
        }
        catch
        {
            foreach (var program in programs.Values) program.Dispose();
            foreach (var map in maps.Values) map.Handle.Dispose();
            throw;
        }

        return new BpfObject(maps, programs);
    }

    private static BpfObjectMap CreateMap(in BpfMapSpec spec)
    {
        var handle = BpfSyscall.CreateMap(
            spec.Type, spec.KeySize, spec.ValueSize, spec.MaxEntries,
            (uint)spec.Flags, KernelName(spec.Name));

        // Populate before freezing, freeze before any program loads: the verifier
        // reads frozen .rodata at load time and treats it as constant, which is
        // what lets it prune branches on config values (DESIGN §4.4).
        if (spec.InitialValue is { } initial)
        {
            ReadOnlySpan<byte> key = stackalloc byte[4]; // index 0 of the array map
            BpfSyscall.UpdateElem(handle, key, initial, MapUpdateFlags.Any);
        }
        if (spec.Freeze)
            BpfSyscall.FreezeMap(handle);

        return new BpfObjectMap(spec, handle);
    }

    /// <summary>Contents of the object's license section; the kernel gates some
    /// helpers on it being GPL-compatible.</summary>
    private static string License(IElfObject elf)
    {
        if (elf.FindSection("license") is not { } section || section.Data.Length == 0)
            return "GPL";

        int nul = Array.IndexOf<byte>(section.Data, 0);
        return Encoding.ASCII.GetString(
            section.Data, 0, nul < 0 ? section.Data.Length : nul);
    }

    /// <summary>Kernel object names cap at 15 bytes; longer ELF names are truncated
    /// rather than rejected because the ELF name stays the real identifier.</summary>
    private static string KernelName(string name)
        => name.Length > 15 ? name[..15] : name;

    public void Dispose()
    {
        foreach (var program in Programs.Values) program.Dispose();
        foreach (var map in Maps.Values) map.Handle.Dispose();
    }
}
