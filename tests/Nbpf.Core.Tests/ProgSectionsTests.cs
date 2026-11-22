using Nbpf.Core.Native;
using Nbpf.Core.ObjectFile;
using Xunit;

namespace Nbpf.Core.Tests;

/// <summary>
/// Section-name → program-type resolution. Pure string matching, so these run anywhere.
/// The rejected cases matter as much as the accepted ones: a name the loader doesn't
/// recognize must fail the link, never be guessed into the nearest program type.
/// </summary>
public class ProgSectionsTests
{
    [Theory]
    [InlineData("tracepoint/syscalls/sys_enter_execve", BpfProgType.Tracepoint)]
    [InlineData("tp/sched/sched_switch", BpfProgType.Tracepoint)]
    // A bare SEC("xdp") is an exact name; "xdp/<anything>" is the prefix form.
    [InlineData("xdp", BpfProgType.Xdp)]
    [InlineData("xdp/", BpfProgType.Xdp)]
    [InlineData("xdp/drop_udp", BpfProgType.Xdp)]
    public void Known_section_names_resolve_to_their_program_type(string section, BpfProgType expected)
    {
        Assert.True(ProgSections.TryResolve(section, out var type));
        Assert.Equal(expected, type);
    }

    [Theory]
    // Multi-buffer XDP: loading it as plain XDP would drop the BPF_F_XDP_HAS_FRAGS
    // flag it needs, so until frags are supported it must be refused, not matched by
    // the "xdp" name.
    [InlineData("xdp.frags")]
    [InlineData("xdp.frags/drop_udp")]
    // Look-alikes of the exact name and of the prefixes.
    [InlineData("xdpfoo")]
    [InlineData("xdp_drop")]
    [InlineData("tracepoint")]
    [InlineData("tp")]
    // Matching is ordinal: libbpf section names are case-sensitive.
    [InlineData("XDP")]
    [InlineData("Tracepoint/syscalls/sys_enter_execve")]
    // Families nBPF doesn't load yet.
    [InlineData("kprobe/do_sys_open")]
    [InlineData("tc")]
    [InlineData("")]
    public void Unknown_section_names_are_rejected(string section)
    {
        Assert.False(ProgSections.TryResolve(section, out _));
    }

    [Fact]
    public void Supported_name_lists_name_every_entry_once()
    {
        Assert.Equal("'tracepoint/', 'tp/', 'xdp/'", ProgSections.SupportedPrefixes);
        Assert.Equal("'xdp'", ProgSections.SupportedFixedNames);
    }
}
