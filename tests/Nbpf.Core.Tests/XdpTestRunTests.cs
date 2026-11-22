using System.Buffers.Binary;
using Nbpf.Core.Native;
using Nbpf.Core.ObjectFile;
using Xunit;

namespace Nbpf.Core.Tests;

/// <summary>
/// The XDP fixture's packet logic, checked with BPF_PROG_TEST_RUN: hand-built frames go
/// in, the program's XDP action comes out, and nothing is attached to any interface.
/// This is the safety net under the attach work: if these fail, a live-interface test
/// can't tell a parser bug from an attach bug. See
/// Nbpf.Elf.Tests/Fixtures/xdp-drop.bpf.c for the program.
/// </summary>
public class XdpTestRunTests
{
    // Mirrors PORT_TO_BLOCK in xdp-drop.bpf.c.
    private const ushort BlockedPort = 13131;
    private const ushort OtherPort = 13132;

    private const uint XdpDrop = 1;
    private const uint XdpPass = 2;

    private const ushort EthPIp = 0x0800;
    private const ushort EthPIpv6 = 0x86DD;
    private const ushort EthP8021Q = 0x8100;
    private const ushort EthP8021AD = 0x88A8;
    private const byte IpProtoTcp = 6;
    private const byte IpProtoUdp = 17;

    private const int EthHeaderLength = 14;
    private const int VlanHeaderLength = 4;
    private const int UdpHeaderLength = 8;
    private const int PayloadLength = 4;

    private static readonly byte[] XdpObject =
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "xdp-drop.bpf.o"));

    public static TheoryData<string, byte[], uint> Cases => new()
    {
        { "UDP to the blocked port", Packet(), XdpDrop },
        { "UDP to another port", Packet(destPort: OtherPort), XdpPass },
        { "TCP to the blocked port", Packet(protocol: IpProtoTcp), XdpPass },
        { "IPv6 EtherType", Packet(etherType: EthPIpv6), XdpPass },

        // VLANs: up to two tags are walked (VLAN_MAX_DEPTH); a third leaves the
        // EtherType still a VLAN one, which isn't IPv4, so the frame passes.
        { "one 802.1Q tag", Packet(vlans: [EthP8021Q]), XdpDrop },
        { "QinQ (802.1ad outer, 802.1Q inner)", Packet(vlans: [EthP8021AD, EthP8021Q]), XdpDrop },
        { "three tags, deeper than VLAN_MAX_DEPTH", Packet(vlans: [EthP8021AD, EthP8021Q, EthP8021Q]), XdpPass },

        // IHL: the UDP header starts at ihl * 4, not at a fixed 20. With 4 bytes of
        // options, the blocked port is only found if that offset is honoured (at
        // offset 20 the program would read option bytes instead).
        { "IPv4 options (ihl = 6)", Packet(ihl: 6), XdpDrop },
        { "IPv4 options (ihl = 15, the maximum)", Packet(ihl: 15), XdpDrop },
        { "invalid ihl < 5", Packet(ihl: 4), XdpPass },

        // Fragments: frag_off is network byte order. The first fragment (offset 0) still
        // carries the UDP header and is dropped even with More Fragments (0x2000) set,
        // which only works if the 0x1FFF offset mask is byte-swapped too. Later
        // fragments carry no UDP header and pass.
        { "first fragment, More Fragments set", Packet(fragOff: 0x2000), XdpDrop },
        { "Don't Fragment set", Packet(fragOff: 0x4000), XdpDrop },
        { "non-first fragment", Packet(fragOff: 0x0001), XdpPass },
        { "last fragment of a train", Packet(fragOff: 0x00B9), XdpPass },

        // Truncation: every header must be bounds-checked before it is read. The kernel
        // refuses test-run input shorter than an Ethernet header, so 14 is the floor.
        { "Ethernet header only", Truncated(Packet(), EthHeaderLength), XdpPass },
        { "IPv4 header cut short", Truncated(Packet(), EthHeaderLength + 19), XdpPass },
        { "UDP header cut short", Truncated(Packet(), EthHeaderLength + 20 + UdpHeaderLength - 1), XdpPass },
        { "UDP header complete, no payload", Truncated(Packet(), EthHeaderLength + 20 + UdpHeaderLength), XdpDrop },
        { "VLAN tag cut short", Truncated(Packet(vlans: [EthP8021Q]), EthHeaderLength + VlanHeaderLength - 1), XdpPass },
    };

    [KernelFeatureTheory(ProgType = BpfProgType.Xdp)]
    [MemberData(nameof(Cases))]
    public void Packet_gets_the_expected_action_and_only_drops_are_counted(
        string description, byte[] packet, uint expected)
    {
        using var obj = BpfObject.Load(XdpObject);
        var program = obj.Programs["xdp_bad_udp"];
        Assert.Equal(BpfProgType.Xdp, program.Type);

        // Compared by name so a failure reads "XDP_PASS" rather than "2". The case's
        // description is already in the test's display name.
        _ = description;
        Assert.Equal(ActionName(expected), ActionName(program.TestRun(packet)));

        // A fresh object per case, so the counter started at zero.
        Assert.Equal(expected == XdpDrop ? 1ul : 0ul, Drops(obj));
    }

    [KernelFeatureFact(ProgType = BpfProgType.Xdp)]
    public void Drop_counter_accumulates_across_runs()
    {
        using var obj = BpfObject.Load(XdpObject);
        var program = obj.Programs["xdp_bad_udp"];

        Assert.Equal(XdpDrop, program.TestRun(Packet(), repeat: 5));
        Assert.Equal(5ul, Drops(obj));

        // Passed traffic leaves the count alone.
        Assert.Equal(XdpPass, program.TestRun(Packet(destPort: OtherPort), repeat: 3));
        Assert.Equal(5ul, Drops(obj));

        Assert.Equal(XdpDrop, program.TestRun(Packet()));
        Assert.Equal(6ul, Drops(obj));
    }

    private static ulong Drops(BpfObject obj) => obj.Maps["output_map"].AsTyped<uint, ulong>()[0u];

    private static string ActionName(uint action) => action switch
    {
        0 => "XDP_ABORTED",
        XdpDrop => "XDP_DROP",
        XdpPass => "XDP_PASS",
        _ => $"action {action}",
    };

    private static byte[] Truncated(byte[] packet, int length) => packet[..length];

    /// <summary>
    /// An Ethernet frame, optionally VLAN-tagged, carrying IPv4 and a UDP (or other
    /// protocol) header plus a few payload bytes. Checksums are left zero: the program
    /// never looks at them, and BPF_PROG_TEST_RUN doesn't either. <paramref name="ihl"/>
    /// below 5 is written into the header as-is, over a normal 20-byte header.
    /// </summary>
    private static byte[] Packet(
        ushort destPort = BlockedPort,
        byte protocol = IpProtoUdp,
        int ihl = 5,
        ushort fragOff = 0,
        ushort etherType = EthPIp,
        ushort[]? vlans = null)
    {
        vlans ??= [];
        int ipHeaderLength = Math.Max(ihl, 5) * 4;
        int ipTotalLength = ipHeaderLength + UdpHeaderLength + PayloadLength;
        var packet = new byte[EthHeaderLength + vlans.Length * VlanHeaderLength + ipTotalLength];
        var span = packet.AsSpan();

        // Ethernet: locally administered MACs, then the first EtherType: the outer
        // VLAN TPID if tagged, otherwise the payload type.
        byte[] destMac = [0x02, 0, 0, 0, 0, 0x02];
        byte[] sourceMac = [0x02, 0, 0, 0, 0, 0x01];
        destMac.CopyTo(span);
        sourceMac.CopyTo(span[6..]);
        BinaryPrimitives.WriteUInt16BigEndian(span[12..], vlans.Length > 0 ? vlans[0] : etherType);
        int offset = EthHeaderLength;

        // Each tag: TCI (VLAN id 100 + depth), then the next EtherType in the chain.
        for (int i = 0; i < vlans.Length; i++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(span[offset..], (ushort)(100 + i));
            BinaryPrimitives.WriteUInt16BigEndian(span[(offset + 2)..],
                i + 1 < vlans.Length ? vlans[i + 1] : etherType);
            offset += VlanHeaderLength;
        }

        // IPv4, 127.0.0.1 → 127.0.0.1. Options, if any, are NOPs (0x01).
        var ip = span.Slice(offset, ipHeaderLength);
        ip[0] = (byte)(0x40 | (ihl & 0x0F));
        BinaryPrimitives.WriteUInt16BigEndian(ip[2..], (ushort)ipTotalLength);
        BinaryPrimitives.WriteUInt16BigEndian(ip[6..], fragOff);
        ip[8] = 64; // TTL
        ip[9] = protocol;
        BinaryPrimitives.WriteUInt32BigEndian(ip[12..], 0x7F000001);
        BinaryPrimitives.WriteUInt32BigEndian(ip[16..], 0x7F000001);
        ip[20..].Fill(0x01);
        offset += ipHeaderLength;

        // UDP (the same 8 bytes stand in for the start of a TCP header, whose first
        // two fields are also source and destination port).
        var udp = span[offset..];
        BinaryPrimitives.WriteUInt16BigEndian(udp, 40000);
        BinaryPrimitives.WriteUInt16BigEndian(udp[2..], destPort);
        BinaryPrimitives.WriteUInt16BigEndian(udp[4..], UdpHeaderLength + PayloadLength);
        udp[UdpHeaderLength..].Fill(0xAB);

        return packet;
    }
}
