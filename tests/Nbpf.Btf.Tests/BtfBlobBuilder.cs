using System.Buffers.Binary;
using System.Text;
using Nbpf.Btf;

namespace Nbpf.Btf.Tests;

/// <summary>
/// Builds well-formed (or deliberately malformed) BTF blobs in memory, so parser tests can
/// pin down exact wire encodings without needing clang or a kernel.
/// </summary>
internal sealed class BtfBlobBuilder
{
    private readonly List<uint> _types = [];
    private readonly MemoryStream _strings = new();
    private readonly Dictionary<string, uint> _stringOffsets = [];

    private int _nextId = 1;

    internal BtfBlobBuilder()
    {
        _strings.WriteByte(0); // offset 0 is the empty name
    }

    /// <summary>Emit as big-endian, the way a blob built on s390x would look.</summary>
    internal bool BigEndian { get; set; }

    /// <summary>Overrides the version byte; used to test rejection of future formats.</summary>
    internal byte Version { get; set; } = 1;

    internal uint AddString(string value)
    {
        if (value.Length == 0)
            return 0;

        if (_stringOffsets.TryGetValue(value, out var existing))
            return existing;

        var offset = (uint)_strings.Length;
        var bytes = Encoding.UTF8.GetBytes(value);
        _strings.Write(bytes, 0, bytes.Length);
        _strings.WriteByte(0);

        _stringOffsets[value] = offset;
        return offset;
    }

    /// <summary>Appends one raw type record and returns its type id.</summary>
    internal int AddRaw(string name, BtfKind kind, int vlen, bool kindFlag, uint sizeOrType, params uint[] trailing)
    {
        var info = (uint)(vlen & 0xFFFF) | ((uint)kind << 24) | (kindFlag ? 0x80000000u : 0u);

        _types.Add(AddString(name));
        _types.Add(info);
        _types.Add(sizeOrType);
        foreach (var word in trailing)
            _types.Add(word);

        return _nextId++;
    }

    internal int AddInt(string name, int sizeBytes, IntEncoding encoding = IntEncoding.None, byte? bits = null, byte offset = 0)
    {
        var info = ((uint)encoding << 24) | ((uint)offset << 16) | (bits ?? (byte)(sizeBytes * 8));
        return AddRaw(name, BtfKind.Int, 0, false, (uint)sizeBytes, info);
    }

    internal int AddPtr(int pointeeId) => AddRaw("", BtfKind.Ptr, 0, false, (uint)pointeeId);

    internal int AddArray(int elementId, int indexId, uint length) =>
        AddRaw("", BtfKind.Array, 0, false, 0, (uint)elementId, (uint)indexId, length);

    internal int AddStruct(string name, int sizeBytes, params Member[] members) =>
        AddComposite(BtfKind.Struct, name, sizeBytes, members);

    internal int AddUnion(string name, int sizeBytes, params Member[] members) =>
        AddComposite(BtfKind.Union, name, sizeBytes, members);

    private int AddComposite(BtfKind kind, string name, int sizeBytes, Member[] members)
    {
        var bitfieldAware = members.Any(m => m.BitfieldSize > 0);

        var trailing = new List<uint>();
        foreach (var member in members)
        {
            trailing.Add(AddString(member.Name));
            trailing.Add((uint)member.TypeId);
            trailing.Add(bitfieldAware
                ? ((uint)member.BitfieldSize << 24) | (member.BitOffset & 0x00FFFFFF)
                : member.BitOffset);
        }

        return AddRaw(name, kind, members.Length, bitfieldAware, (uint)sizeBytes, trailing.ToArray());
    }

    internal int AddEnum(string name, int sizeBytes, bool signed, params (string Name, int Value)[] values)
    {
        var trailing = new List<uint>();
        foreach (var (valueName, value) in values)
        {
            trailing.Add(AddString(valueName));
            trailing.Add(unchecked((uint)value));
        }

        return AddRaw(name, BtfKind.Enum, values.Length, signed, (uint)sizeBytes, trailing.ToArray());
    }

    internal int AddEnum64(string name, int sizeBytes, bool signed, params (string Name, ulong Value)[] values)
    {
        var trailing = new List<uint>();
        foreach (var (valueName, value) in values)
        {
            trailing.Add(AddString(valueName));
            trailing.Add((uint)(value & 0xFFFFFFFF));
            trailing.Add((uint)(value >> 32));
        }

        return AddRaw(name, BtfKind.Enum64, values.Length, signed, (uint)sizeBytes, trailing.ToArray());
    }

    internal int AddFwd(string name, bool isUnion) => AddRaw(name, BtfKind.Fwd, 0, isUnion, 0);

    internal int AddTypedef(string name, int targetId) => AddRaw(name, BtfKind.Typedef, 0, false, (uint)targetId);

    internal int AddConst(int targetId) => AddRaw("", BtfKind.Const, 0, false, (uint)targetId);

    internal int AddVolatile(int targetId) => AddRaw("", BtfKind.Volatile, 0, false, (uint)targetId);

    internal int AddRestrict(int targetId) => AddRaw("", BtfKind.Restrict, 0, false, (uint)targetId);

    internal int AddTypeTag(string name, int targetId) => AddRaw(name, BtfKind.TypeTag, 0, false, (uint)targetId);

    internal int AddFloat(string name, int sizeBytes) => AddRaw(name, BtfKind.Float, 0, false, (uint)sizeBytes);

    internal int AddFuncProto(int returnTypeId, params (string Name, int TypeId)[] parameters)
    {
        var trailing = new List<uint>();
        foreach (var (paramName, typeId) in parameters)
        {
            trailing.Add(AddString(paramName));
            trailing.Add((uint)typeId);
        }

        return AddRaw("", BtfKind.FuncProto, parameters.Length, false, (uint)returnTypeId, trailing.ToArray());
    }

    internal int AddFunc(string name, int protoId, BtfLinkage linkage) =>
        AddRaw(name, BtfKind.Func, (int)linkage, false, (uint)protoId);

    internal int AddVar(string name, int typeId, BtfLinkage linkage) =>
        AddRaw(name, BtfKind.Var, 0, false, (uint)typeId, (uint)linkage);

    internal int AddDatasec(string name, uint sizeBytes, params (int VarId, uint Offset, uint Size)[] entries)
    {
        var trailing = new List<uint>();
        foreach (var (varId, offset, size) in entries)
        {
            trailing.Add((uint)varId);
            trailing.Add(offset);
            trailing.Add(size);
        }

        return AddRaw(name, BtfKind.Datasec, entries.Length, false, sizeBytes, trailing.ToArray());
    }

    internal int AddDeclTag(string value, int targetId, int componentIndex) =>
        AddRaw(value, BtfKind.DeclTag, 0, false, (uint)targetId, unchecked((uint)componentIndex));

    internal byte[] Build(int truncateTypeWords = 0)
    {
        var typeWords = _types.Count - truncateTypeWords;
        var typeLen = (uint)(typeWords * 4);
        var stringBytes = _strings.ToArray();

        var output = new MemoryStream();
        Write16(output, BtfHeaderMagic);
        output.WriteByte(Version);
        output.WriteByte(0); // flags
        Write32(output, 24); // hdr_len
        Write32(output, 0); // type_off
        Write32(output, typeLen);
        Write32(output, typeLen); // str_off, immediately after the type section
        Write32(output, (uint)stringBytes.Length);

        for (var i = 0; i < typeWords; i++)
            Write32(output, _types[i]);

        output.Write(stringBytes, 0, stringBytes.Length);
        return output.ToArray();
    }

    private const ushort BtfHeaderMagic = 0xEB9F;

    private void Write16(Stream s, ushort value)
    {
        Span<byte> buffer = stackalloc byte[2];
        if (BigEndian) BinaryPrimitives.WriteUInt16BigEndian(buffer, value);
        else BinaryPrimitives.WriteUInt16LittleEndian(buffer, value);
        s.Write(buffer);
    }

    private void Write32(Stream s, uint value)
    {
        Span<byte> buffer = stackalloc byte[4];
        if (BigEndian) BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        else BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
        s.Write(buffer);
    }

    internal readonly record struct Member(string Name, int TypeId, uint BitOffset, byte BitfieldSize = 0);

    [Flags]
    internal enum IntEncoding : uint
    {
        None = 0,
        Signed = 1 << 0,
        Char = 1 << 1,
        Bool = 1 << 2,
    }
}
