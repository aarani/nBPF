using Ebpf.Btf;
using Xunit;

namespace Ebpf.Elf.Tests;

/// <summary>
/// The two readers composed the way the loader will use them: pull <c>.BTF</c> out of the
/// object, hand the bytes to the BTF parser. This is also the path the source generator takes,
/// which is why both assemblies target netstandard2.0.
/// </summary>
public class ElfBtfIntegrationTests
{
    private static IBtfTypeGraph ParseEmbeddedBtf() =>
        BtfReader.Read(ElfFixture.Section(".BTF").Data);

    [Fact]
    public void Btf_section_of_the_object_parses()
    {
        Assert.NotEmpty(ParseEmbeddedBtf().Types);
    }

    [Fact]
    public void Both_maps_appear_as_vars_in_the_maps_datasec()
    {
        var graph = ParseEmbeddedBtf();

        // Sorted: the order within the datasec is the linker's business, not something to pin.
        var maps = Assert.IsAssignableFrom<IBtfDatasec>(graph.Find(".maps", BtfKind.Datasec));
        Assert.Equal(["counts", "events"], maps.Variables.Select(v => v.Variable.Name).Order());
    }

    [Fact]
    public void Map_definition_encodes_its_type_as_a_pointer_to_array()
    {
        // `int (*type)[27]` is how the map type reaches BTF: the array length is the value.
        var graph = ParseEmbeddedBtf();

        var maps = Assert.IsAssignableFrom<IBtfDatasec>(graph.Find(".maps", BtfKind.Datasec));
        var events = maps.Variables.Single(v => v.Variable.Name == "events").Variable;

        var definition = Assert.IsAssignableFrom<IBtfStruct>(events.Type);
        var typeMember = definition.Members.Single(m => m.Name == "type");

        var pointer = Assert.IsAssignableFrom<IBtfPtr>(typeMember.Type);
        var array = Assert.IsAssignableFrom<IBtfArray>(pointer.Pointee);
        Assert.Equal(27u, array.Length); // BPF_MAP_TYPE_RINGBUF
    }

    [Fact]
    public void Each_program_has_a_matching_btf_func()
    {
        var graph = ParseEmbeddedBtf();

        foreach (var name in new[] { "handle_exec", "handle_open" })
        {
            var func = Assert.IsAssignableFrom<IBtfFunc>(graph.Find(name, BtfKind.Func));
            Assert.Equal(BtfLinkage.Global, func.Linkage);
        }

        // The noinline subprogram is static, and BTF records that.
        Assert.Equal(BtfLinkage.Static,
            Assert.IsAssignableFrom<IBtfFunc>(graph.Find("bump", BtfKind.Func)).Linkage);
    }

    [Fact]
    public void Datasec_sizes_still_have_to_come_from_the_elf()
    {
        // Pinned in the BTF tests too, but this is the pairing that matters: BTF says zero,
        // the section header says the truth. Size the array maps from the ELF.
        var graph = ParseEmbeddedBtf();

        foreach (var name in new[] { ".rodata", ".bss" })
        {
            var datasec = Assert.IsAssignableFrom<IBtfDatasec>(graph.Find(name, BtfKind.Datasec));
            Assert.Equal(0u, datasec.SizeBytes);
            Assert.NotEqual(0ul, ElfFixture.Section(name).Size);
        }
    }
}
