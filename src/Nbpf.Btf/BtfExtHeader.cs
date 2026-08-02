namespace Nbpf.Btf;

/// <summary>
/// The <c>struct btf_ext_header</c>. Like <see cref="BtfHeader"/>, block offsets are
/// relative to the end of the header (<c>hdr_len</c>). The header grew over time: the
/// original 24-byte form carries func and line info only; the 32-byte form appends the
/// CO-RE relocation block. A shorter header therefore just means "no CO-RE records",
/// not an error.
/// </summary>
internal readonly struct BtfExtHeader
{
    internal const int MinSize = 24;
    internal const int SizeWithCoreRelos = 32;
    internal const byte SupportedVersion = 1;

    private BtfExtHeader(bool bigEndian, uint hdrLen,
        uint funcInfoOff, uint funcInfoLen, uint lineInfoOff, uint lineInfoLen,
        uint coreReloOff, uint coreReloLen)
    {
        BigEndian = bigEndian;
        HdrLen = hdrLen;
        FuncInfoOff = funcInfoOff;
        FuncInfoLen = funcInfoLen;
        LineInfoOff = lineInfoOff;
        LineInfoLen = lineInfoLen;
        CoreReloOff = coreReloOff;
        CoreReloLen = coreReloLen;
    }

    internal bool BigEndian { get; }
    internal uint HdrLen { get; }
    internal uint FuncInfoOff { get; }
    internal uint FuncInfoLen { get; }
    internal uint LineInfoOff { get; }
    internal uint LineInfoLen { get; }
    internal uint CoreReloOff { get; }
    internal uint CoreReloLen { get; }

    internal static BtfExtHeader Parse(byte[] data)
    {
        if (data.Length < MinSize)
            throw new BtfFormatException($"not a .BTF.ext blob: {data.Length} byte(s), need at least {MinSize}");

        // Same magic and endianness detection as .BTF — the sections share a producer.
        bool bigEndian;
        if (data[0] == 0x9F && data[1] == 0xEB) bigEndian = false;
        else if (data[0] == 0xEB && data[1] == 0x9F) bigEndian = true;
        else throw new BtfFormatException(
            $"not a .BTF.ext blob: expected magic 0x{BtfHeader.Magic:X4}, found bytes 0x{data[0]:X2} 0x{data[1]:X2}");

        var c = new BtfCursor(data, 2, data.Length, bigEndian);
        var version = c.ReadU8();
        c.ReadU8(); // flags
        var hdrLen = c.ReadU32();

        if (version != SupportedVersion)
            throw new BtfFormatException($"unsupported .BTF.ext version {version}, expected {SupportedVersion}");

        if (hdrLen < MinSize)
            throw new BtfFormatException($".BTF.ext hdr_len {hdrLen} is smaller than the {MinSize}-byte header");

        if (hdrLen > (uint)data.Length)
            throw new BtfFormatException($".BTF.ext hdr_len {hdrLen} exceeds the blob length {data.Length}");

        var funcInfoOff = c.ReadU32();
        var funcInfoLen = c.ReadU32();
        var lineInfoOff = c.ReadU32();
        var lineInfoLen = c.ReadU32();

        uint coreReloOff = 0, coreReloLen = 0;
        if (hdrLen >= SizeWithCoreRelos)
        {
            coreReloOff = c.ReadU32();
            coreReloLen = c.ReadU32();
        }

        CheckBlock(data, hdrLen, funcInfoOff, funcInfoLen, "func_info");
        CheckBlock(data, hdrLen, lineInfoOff, lineInfoLen, "line_info");
        CheckBlock(data, hdrLen, coreReloOff, coreReloLen, "core_relo");

        return new BtfExtHeader(bigEndian, hdrLen,
            funcInfoOff, funcInfoLen, lineInfoOff, lineInfoLen, coreReloOff, coreReloLen);
    }

    private static void CheckBlock(byte[] data, uint hdrLen, uint off, uint len, string what)
    {
        // Everything in an info block is a u32, so the kernel requires alignment.
        if ((off & 3) != 0)
            throw new BtfFormatException($".BTF.ext {what} offset {off} is not 4-byte aligned");

        // Widened to long so a hostile offset+length cannot wrap around into a valid-looking range.
        var end = (long)hdrLen + off + len;
        if (end > data.Length)
            throw new BtfFormatException(
                $".BTF.ext {what} block runs past the end of the blob: ends at {end}, blob is {data.Length} byte(s)");
    }
}
