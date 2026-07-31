using Xunit;

namespace Ebpf.Btf.Tests;

public class BtfHeaderTests
{
    [Fact]
    public void Rejects_a_blob_that_is_not_btf()
    {
        var notBtf = new byte[64];
        notBtf[0] = 0x7F;
        notBtf[1] = (byte)'E'; // an ELF header, say

        var ex = Assert.Throws<BtfFormatException>(() => BtfReader.Read(notBtf));
        Assert.Contains("magic", ex.Message);
    }

    [Fact]
    public void Rejects_a_blob_shorter_than_the_header()
    {
        var ex = Assert.Throws<BtfFormatException>(() => BtfReader.Read([0x9F, 0xEB, 1, 0]));
        Assert.Contains("at least 24", ex.Message);
    }

    [Fact]
    public void Rejects_an_unsupported_version()
    {
        var builder = new BtfBlobBuilder { Version = 2 };
        builder.AddInt("int", 4);

        var ex = Assert.Throws<BtfFormatException>(() => BtfReader.Read(builder.Build()));
        Assert.Contains("version 2", ex.Message);
    }

    [Fact]
    public void Rejects_a_truncated_type_section()
    {
        var builder = new BtfBlobBuilder();
        builder.AddInt("int", 4);

        // Drop the last word of the INT record's trailing data.
        var ex = Assert.Throws<BtfFormatException>(() => BtfReader.Read(builder.Build(truncateTypeWords: 1)));
        Assert.Contains("truncated", ex.Message);
    }

    [Fact]
    public void Parses_a_big_endian_blob_identically()
    {
        static byte[] Blob(bool bigEndian)
        {
            var builder = new BtfBlobBuilder { BigEndian = bigEndian };
            var i32 = builder.AddInt("int", 4, BtfBlobBuilder.IntEncoding.Signed);
            builder.AddStruct("point", 8,
                new BtfBlobBuilder.Member("x", i32, 0),
                new BtfBlobBuilder.Member("y", i32, 32));
            return builder.Build();
        }

        var little = BtfReader.Read(Blob(bigEndian: false));
        var big = BtfReader.Read(Blob(bigEndian: true));

        var lhs = Assert.IsAssignableFrom<IBtfStruct>(little.Find("point", BtfKind.Struct));
        var rhs = Assert.IsAssignableFrom<IBtfStruct>(big.Find("point", BtfKind.Struct));

        Assert.Equal(lhs.SizeBytes, rhs.SizeBytes);
        Assert.Equal(
            lhs.Members.Select(m => (m.Name, m.BitOffset)),
            rhs.Members.Select(m => (m.Name, m.BitOffset)));
        Assert.Equal(4, ((IBtfInt)rhs.Members[0].Type).SizeBytes);
    }

    [Fact]
    public void Rejects_a_string_offset_past_the_string_section()
    {
        var builder = new BtfBlobBuilder();
        builder.AddRaw("", BtfKind.Int, 0, false, 4, 0x00000020);

        var blob = builder.Build();

        // Point the type's name_off at an offset well past the (tiny) string section.
        var nameOffset = 24; // first word of the first type record
        blob[nameOffset] = 0xF0;

        var ex = Assert.Throws<BtfFormatException>(() => BtfReader.Read(blob));
        Assert.Contains("string offset", ex.Message);
    }
}
