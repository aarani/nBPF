namespace Nbpf.Btf;

/// <summary>
/// The 24-byte <c>struct btf_header</c>. Section offsets in the header are relative to the
/// end of the header (i.e. to <c>hdr_len</c>), not to the start of the blob.
/// </summary>
internal readonly struct BtfHeader
{
    /// <summary>The magic value, used both to identify a BTF blob and to detect its endianness.</summary>
    internal const ushort Magic = 0xEB9F;

    internal const int Size = 24;
    internal const byte SupportedVersion = 1;

    private BtfHeader(bool bigEndian, byte version, byte flags, uint hdrLen,
        uint typeOff, uint typeLen, uint strOff, uint strLen)
    {
        BigEndian = bigEndian;
        Version = version;
        Flags = flags;
        HdrLen = hdrLen;
        TypeOff = typeOff;
        TypeLen = typeLen;
        StrOff = strOff;
        StrLen = strLen;
    }

    /// <summary>True when the blob was produced on a big-endian target (e.g. s390x).</summary>
    internal bool BigEndian { get; }

    internal byte Version { get; }
    internal byte Flags { get; }
    internal uint HdrLen { get; }
    internal uint TypeOff { get; }
    internal uint TypeLen { get; }
    internal uint StrOff { get; }
    internal uint StrLen { get; }

    /// <summary>Absolute offset of the type section within the blob.</summary>
    internal int TypeStart => checked((int)(HdrLen + TypeOff));

    /// <summary>Absolute offset of the string section within the blob.</summary>
    internal int StringStart => checked((int)(HdrLen + StrOff));

    internal static BtfHeader Parse(byte[] data)
    {
        if (data.Length < Size)
            throw new BtfFormatException($"not a BTF blob: {data.Length} byte(s), need at least {Size}");

        // The magic is stored in the producer's byte order, which is how we learn what that order is.
        bool bigEndian;
        if (data[0] == 0x9F && data[1] == 0xEB) bigEndian = false;
        else if (data[0] == 0xEB && data[1] == 0x9F) bigEndian = true;
        else throw new BtfFormatException(
            $"not a BTF blob: expected magic 0x{Magic:X4}, found bytes 0x{data[0]:X2} 0x{data[1]:X2}");

        var c = new BtfCursor(data, 0, data.Length, bigEndian);
        c.ReadU16(); // magic, already consumed logically
        var version = c.ReadU8();
        var flags = c.ReadU8();
        var hdrLen = c.ReadU32();
        var typeOff = c.ReadU32();
        var typeLen = c.ReadU32();
        var strOff = c.ReadU32();
        var strLen = c.ReadU32();

        if (version != SupportedVersion)
            throw new BtfFormatException($"unsupported BTF version {version}, expected {SupportedVersion}");

        if (hdrLen < Size)
            throw new BtfFormatException($"BTF hdr_len {hdrLen} is smaller than the {Size}-byte header");

        if (hdrLen > (uint)data.Length)
            throw new BtfFormatException($"BTF hdr_len {hdrLen} exceeds the blob length {data.Length}");

        // Type records are u32-based, so the kernel requires the section to be aligned.
        if ((typeOff & 3) != 0)
            throw new BtfFormatException($"BTF type_off {typeOff} is not 4-byte aligned");

        if ((typeLen & 3) != 0)
            throw new BtfFormatException($"BTF type_len {typeLen} is not a multiple of 4");

        CheckSection(data, hdrLen, typeOff, typeLen, "type");
        CheckSection(data, hdrLen, strOff, strLen, "string");

        return new BtfHeader(bigEndian, version, flags, hdrLen, typeOff, typeLen, strOff, strLen);
    }

    private static void CheckSection(byte[] data, uint hdrLen, uint off, uint len, string what)
    {
        // Widened to long so a hostile offset+length cannot wrap around into a valid-looking range.
        var end = (long)hdrLen + off + len;
        if (end > data.Length)
            throw new BtfFormatException(
                $"BTF {what} section runs past the end of the blob: ends at {end}, blob is {data.Length} byte(s)");
    }
}
