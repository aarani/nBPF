namespace Nbpf.Btf;

/// <summary>
/// A bounds-checked forward reader over a byte range of a BTF blob. Assembles integers
/// byte-by-byte from the blob's own endianness, so the host's endianness never matters.
/// </summary>
internal sealed class BtfCursor
{
    private readonly byte[] _data;
    private readonly int _end;
    private readonly bool _bigEndian;

    internal BtfCursor(byte[] data, int start, int end, bool bigEndian)
    {
        _data = data;
        _end = end;
        _bigEndian = bigEndian;
        Position = start;
    }

    internal int Position { get; private set; }

    internal int Remaining => _end - Position;

    internal byte ReadU8()
    {
        Require(1);
        return _data[Position++];
    }

    internal ushort ReadU16()
    {
        Require(2);
        var p = Position;
        Position += 2;
        return _bigEndian
            ? (ushort)((_data[p] << 8) | _data[p + 1])
            : (ushort)(_data[p] | (_data[p + 1] << 8));
    }

    internal uint ReadU32()
    {
        Require(4);
        var p = Position;
        Position += 4;
        return _bigEndian
            ? (uint)((_data[p] << 24) | (_data[p + 1] << 16) | (_data[p + 2] << 8) | _data[p + 3])
            : (uint)(_data[p] | (_data[p + 1] << 8) | (_data[p + 2] << 16) | (_data[p + 3] << 24));
    }

    internal int ReadI32() => unchecked((int)ReadU32());

    /// <summary>Advances past bytes whose meaning this parser does not know (forward compat).</summary>
    internal void Skip(int bytes)
    {
        Require(bytes);
        Position += bytes;
    }

    private void Require(int bytes)
    {
        if (Remaining < bytes)
            throw new BtfFormatException(
                $"truncated BTF: needed {bytes} byte(s) at offset {Position}, only {Remaining} left in section");
    }
}
