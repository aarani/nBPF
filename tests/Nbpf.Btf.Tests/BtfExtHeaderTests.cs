using Xunit;

namespace Nbpf.Btf.Tests;

public class BtfExtHeaderTests
{
    [Fact]
    public void Rejects_a_blob_that_is_not_btf_ext()
    {
        var notBtfExt = new byte[64];
        notBtfExt[0] = 0x7F;
        notBtfExt[1] = (byte)'E'; // an ELF header, say

        var ex = Assert.Throws<BtfFormatException>(() => BtfExtReader.Read(notBtfExt, CompanionBtf()));
        Assert.Contains("magic", ex.Message);
    }

    [Fact]
    public void Rejects_a_blob_shorter_than_the_header()
    {
        var ex = Assert.Throws<BtfFormatException>(() => BtfExtReader.Read([0x9F, 0xEB, 1, 0], CompanionBtf()));
        Assert.Contains("at least 24", ex.Message);
    }

    [Fact]
    public void Rejects_an_unsupported_version()
    {
        var btf = new BtfBlobBuilder();
        var ext = new BtfExtBlobBuilder(btf) { Version = 2 };

        var ex = Assert.Throws<BtfFormatException>(() => BtfExtReader.Read(ext.Build(), btf.Build()));
        Assert.Contains("version 2", ex.Message);
    }

    [Fact]
    public void Rejects_an_hdr_len_smaller_than_the_header()
    {
        var btf = new BtfBlobBuilder();
        var blob = new BtfExtBlobBuilder(btf).Build();
        blob[4] = 12; // hdr_len, little-endian low byte

        var ex = Assert.Throws<BtfFormatException>(() => BtfExtReader.Read(blob, btf.Build()));
        Assert.Contains("hdr_len 12", ex.Message);
    }

    [Fact]
    public void Rejects_an_info_block_running_past_the_blob()
    {
        var btf = new BtfBlobBuilder();
        var ext = new BtfExtBlobBuilder(btf);
        ext.AddFuncSection("prog", (0, 1));

        var ex = Assert.Throws<BtfFormatException>(() => BtfExtReader.Read(ext.Build(truncateBytes: 4), btf.Build()));
        Assert.Contains("past the end", ex.Message);
    }

    [Fact]
    public void Rejects_a_misaligned_info_block_offset()
    {
        var btf = new BtfBlobBuilder();
        var ext = new BtfExtBlobBuilder(btf);
        ext.AddFuncSection("prog", (0, 1));

        var blob = ext.Build();
        blob[8] = 2; // func_info_off: 0 -> 2

        var ex = Assert.Throws<BtfFormatException>(() => BtfExtReader.Read(blob, btf.Build()));
        Assert.Contains("aligned", ex.Message);
    }

    [Fact]
    public void Accepts_the_legacy_24_byte_header()
    {
        // Before CO-RE existed the header stopped after line_info; such objects are
        // still valid, they just carry no relocations.
        var btf = new BtfBlobBuilder();
        var ext = new BtfExtBlobBuilder(btf) { LegacyHeader = true };
        ext.AddFuncSection("prog", (0, 1));

        var info = BtfExtReader.Read(ext.Build(), btf.Build());

        Assert.Equal("prog", Assert.Single(info.FuncInfo).SectionName);
        Assert.Empty(info.LineInfo);
        Assert.Empty(info.CoreRelos);
    }

    [Fact]
    public void Parses_a_big_endian_blob_identically()
    {
        static IBtfExtInfo Parse(bool bigEndian)
        {
            var btf = new BtfBlobBuilder { BigEndian = bigEndian };
            var ext = new BtfExtBlobBuilder(btf) { BigEndian = bigEndian };
            ext.AddFuncSection("prog", (8, 3));
            ext.AddCoreReloSection("prog", (16, 3, "0:2:1", (uint)BtfCoreReloKind.FieldByteOffset));
            return BtfExtReader.Read(ext.Build(), btf.Build());
        }

        var little = Parse(bigEndian: false);
        var big = Parse(bigEndian: true);

        Assert.Equal(
            Assert.Single(Assert.Single(little.FuncInfo).Records),
            Assert.Single(Assert.Single(big.FuncInfo).Records));
        Assert.Equal(
            Assert.Single(Assert.Single(little.CoreRelos).Records),
            Assert.Single(Assert.Single(big.CoreRelos).Records));
    }

    private static byte[] CompanionBtf() => new BtfBlobBuilder().Build();
}
