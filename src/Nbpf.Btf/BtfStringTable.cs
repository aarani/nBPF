using System.Text;

namespace Nbpf.Btf;

/// <summary>
/// The BTF string section: a run of NUL-terminated UTF-8 strings addressed by byte offset.
/// Offset 0 is always the empty string, which BTF uses to mean "anonymous".
/// </summary>
internal sealed class BtfStringTable
{
    private readonly byte[] _data;
    private readonly int _start;
    private readonly int _length;
    private readonly Dictionary<uint, string> _cache = new();

    internal BtfStringTable(byte[] data, int start, int length)
    {
        _data = data;
        _start = start;
        _length = length;

        if (length > 0 && data[start] != 0)
            throw new BtfFormatException("BTF string section does not begin with a NUL byte");
    }

    internal string Get(uint offset)
    {
        if (offset == 0)
            return string.Empty;

        if (offset >= (uint)_length)
            throw new BtfFormatException(
                $"BTF string offset {offset} is outside the {_length}-byte string section");

        if (_cache.TryGetValue(offset, out var cached))
            return cached;

        var begin = _start + (int)offset;
        var end = begin;
        var limit = _start + _length;
        while (end < limit && _data[end] != 0)
            end++;

        if (end == limit)
            throw new BtfFormatException($"BTF string at offset {offset} is not NUL-terminated");

        var value = Encoding.UTF8.GetString(_data, begin, end - begin);
        _cache[offset] = value;
        return value;
    }
}
