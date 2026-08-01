namespace Ebpf.Elf;

/// <summary>
/// A bounds-checked random-access reader over an ELF image. Integers are assembled from the
/// file's own byte order, so the host's endianness never enters into it.
/// </summary>
internal sealed class ElfCursor
{
    private readonly byte[] _data;
    private readonly bool _bigEndian;

    internal ElfCursor(byte[] data, bool bigEndian)
    {
        _data = data;
        _bigEndian = bigEndian;
    }

    internal int Length => _data.Length;

    internal byte ReadU8(long offset)
    {
        Require(offset, 1);
        return _data[offset];
    }

    internal ushort ReadU16(long offset)
    {
        Require(offset, 2);
        var p = (int)offset;
        return _bigEndian
            ? (ushort)((_data[p] << 8) | _data[p + 1])
            : (ushort)(_data[p] | (_data[p + 1] << 8));
    }

    internal uint ReadU32(long offset)
    {
        Require(offset, 4);
        var p = (int)offset;
        return _bigEndian
            ? (uint)((_data[p] << 24) | (_data[p + 1] << 16) | (_data[p + 2] << 8) | _data[p + 3])
            : (uint)(_data[p] | (_data[p + 1] << 8) | (_data[p + 2] << 16) | (_data[p + 3] << 24));
    }

    internal ulong ReadU64(long offset)
    {
        Require(offset, 8);
        return _bigEndian
            ? ((ulong)ReadU32(offset) << 32) | ReadU32(offset + 4)
            : ((ulong)ReadU32(offset + 4) << 32) | ReadU32(offset);
    }

    internal byte[] ReadBytes(long offset, long count)
    {
        Require(offset, count);

        var buffer = new byte[count];
        Array.Copy(_data, (int)offset, buffer, 0, (int)count);
        return buffer;
    }

    /// <summary>Reads a NUL-terminated string starting at an absolute offset.</summary>
    internal string ReadString(long offset, string what)
    {
        if (offset < 0 || offset >= _data.Length)
            throw new ElfFormatException($"{what}: string offset {offset} is outside the file");

        var end = (int)offset;
        while (end < _data.Length && _data[end] != 0)
            end++;

        if (end == _data.Length)
            throw new ElfFormatException($"{what}: string at offset {offset} is not NUL-terminated");

        return System.Text.Encoding.UTF8.GetString(_data, (int)offset, end - (int)offset);
    }

    /// <summary>Validates a range without reading it, for section bounds checks.</summary>
    internal void Require(long offset, long count)
    {
        // Widened to long throughout so a hostile offset+size cannot wrap into a valid range.
        if (offset < 0 || count < 0 || offset + count > _data.Length)
            throw new ElfFormatException(
                $"truncated ELF: range [{offset}, {offset + count}) is outside the {_data.Length}-byte file");
    }
}
