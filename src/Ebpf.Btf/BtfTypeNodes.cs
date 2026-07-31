namespace Ebpf.Btf;

/// <summary>A struct/union member as it appears on the wire, before type ids are resolved.</summary>
internal readonly record struct RawMember(string Name, uint TypeId, uint Offset);

/// <summary>A func_proto parameter as it appears on the wire, before type ids are resolved.</summary>
internal readonly record struct RawParam(string Name, uint TypeId);

/// <summary>A datasec entry as it appears on the wire, before type ids are resolved.</summary>
internal readonly record struct RawSecInfo(uint TypeId, uint Offset, uint Size);

/// <summary>
/// Base for every concrete BTF type. Parsing runs in two passes: the constructor stores raw
/// type ids, then <see cref="Link"/> turns them into references once every node exists — BTF
/// ids may point forward, so nothing can be resolved during the first pass.
/// </summary>
internal abstract class BtfTypeNode(int id, string name) : IBtfType
{
    public int Id { get; } = id;

    public string Name { get; } = name;

    public abstract BtfKind Kind { get; }

    internal virtual void Link(BtfTypeGraph graph) { }

    public override string ToString() =>
        Name.Length == 0 ? $"[{Id}] {Kind}" : $"[{Id}] {Kind} '{Name}'";
}

internal sealed class BtfIntNode : BtfTypeNode, IBtfInt
{
    private const uint SignedFlag = 1 << 0;
    private const uint CharFlag = 1 << 1;
    private const uint BoolFlag = 1 << 2;

    private readonly uint _encoding;

    internal BtfIntNode(int id, string name, int sizeBytes, uint info) : base(id, name)
    {
        SizeBytes = sizeBytes;
        _encoding = (info >> 24) & 0x0F;
        Offset = (byte)((info >> 16) & 0xFF);
        Bits = (byte)(info & 0xFF);
    }

    public override BtfKind Kind => BtfKind.Int;
    public int SizeBytes { get; }
    public byte Bits { get; }
    public byte Offset { get; }
    public bool IsSigned => (_encoding & SignedFlag) != 0;
    public bool IsChar => (_encoding & CharFlag) != 0;
    public bool IsBool => (_encoding & BoolFlag) != 0;
}

internal sealed class BtfPtrNode(int id, string name, uint pointeeId) : BtfTypeNode(id, name), IBtfPtr
{
    private readonly uint _pointeeId = pointeeId;

    public override BtfKind Kind => BtfKind.Ptr;
    public IBtfType? Pointee { get; private set; }

    internal override void Link(BtfTypeGraph graph) => Pointee = graph.ResolveOptional(_pointeeId);
}

internal sealed class BtfArrayNode(int id, string name, uint elementId, uint indexId, uint length)
    : BtfTypeNode(id, name), IBtfArray
{
    private readonly uint _elementId = elementId;
    private readonly uint _indexId = indexId;

    public override BtfKind Kind => BtfKind.Array;
    public uint Length { get; } = length;
    public IBtfType ElementType { get; private set; } = null!;
    public IBtfType IndexType { get; private set; } = null!;

    internal override void Link(BtfTypeGraph graph)
    {
        ElementType = graph.ResolveRequired(_elementId, this, "element type");
        IndexType = graph.ResolveRequired(_indexId, this, "index type");
    }
}

/// <summary>Shared implementation for STRUCT and UNION, which differ only in kind.</summary>
internal abstract class BtfCompositeNode(int id, string name, int sizeBytes, RawMember[] members, bool bitfieldAware)
    : BtfTypeNode(id, name)
{
    private readonly RawMember[] _raw = members;
    private readonly bool _bitfieldAware = bitfieldAware;

    public int SizeBytes { get; } = sizeBytes;

    public IReadOnlyList<BtfMember> Members { get; private set; } = Array.Empty<BtfMember>();

    internal override void Link(BtfTypeGraph graph)
    {
        var members = new BtfMember[_raw.Length];
        for (var i = 0; i < _raw.Length; i++)
        {
            var raw = _raw[i];
            var type = graph.ResolveRequired(raw.TypeId, this, $"member '{raw.Name}'");

            // With the kind_flag set, the offset word packs the bitfield width into its top byte.
            var bitOffset = _bitfieldAware ? raw.Offset & 0x00FFFFFF : raw.Offset;
            var bitfieldSize = _bitfieldAware ? (byte)(raw.Offset >> 24) : (byte)0;

            members[i] = new BtfMember(raw.Name, type, bitOffset, bitfieldSize);
        }

        Members = Array.AsReadOnly(members);
    }
}

internal sealed class BtfStructNode(int id, string name, int sizeBytes, RawMember[] members, bool bitfieldAware)
    : BtfCompositeNode(id, name, sizeBytes, members, bitfieldAware), IBtfStruct
{
    public override BtfKind Kind => BtfKind.Struct;
}

internal sealed class BtfUnionNode(int id, string name, int sizeBytes, RawMember[] members, bool bitfieldAware)
    : BtfCompositeNode(id, name, sizeBytes, members, bitfieldAware), IBtfUnion
{
    public override BtfKind Kind => BtfKind.Union;
}

internal sealed class BtfEnumNode(int id, string name, int sizeBytes, bool isSigned, BtfEnumValue[] values)
    : BtfTypeNode(id, name), IBtfEnum
{
    public override BtfKind Kind => BtfKind.Enum;
    public int SizeBytes { get; } = sizeBytes;
    public bool IsSigned { get; } = isSigned;
    public IReadOnlyList<BtfEnumValue> Values { get; } = Array.AsReadOnly(values);
}

internal sealed class BtfEnum64Node(int id, string name, int sizeBytes, bool isSigned, BtfEnum64Value[] values)
    : BtfTypeNode(id, name), IBtfEnum64
{
    public override BtfKind Kind => BtfKind.Enum64;
    public int SizeBytes { get; } = sizeBytes;
    public bool IsSigned { get; } = isSigned;
    public IReadOnlyList<BtfEnum64Value> Values { get; } = Array.AsReadOnly(values);
}

internal sealed class BtfFwdNode(int id, string name, bool isUnion) : BtfTypeNode(id, name), IBtfFwd
{
    public override BtfKind Kind => BtfKind.Fwd;
    public bool IsUnion { get; } = isUnion;
}

internal sealed class BtfFloatNode(int id, string name, int sizeBytes) : BtfTypeNode(id, name), IBtfFloat
{
    public override BtfKind Kind => BtfKind.Float;
    public int SizeBytes { get; } = sizeBytes;
}

/// <summary>
/// Shared implementation for the kinds that wrap another type without changing its layout:
/// typedef, the three qualifiers, and type_tag. All of them may wrap void.
/// </summary>
internal abstract class BtfModifierNode(int id, string name, uint targetId) : BtfTypeNode(id, name)
{
    private readonly uint _targetId = targetId;

    public IBtfType? Target { get; private set; }

    internal override void Link(BtfTypeGraph graph) => Target = graph.ResolveOptional(_targetId);
}

internal sealed class BtfTypedefNode(int id, string name, uint targetId)
    : BtfModifierNode(id, name, targetId), IBtfTypedef
{
    public override BtfKind Kind => BtfKind.Typedef;
}

internal sealed class BtfVolatileNode(int id, string name, uint targetId)
    : BtfModifierNode(id, name, targetId), IBtfVolatile
{
    public override BtfKind Kind => BtfKind.Volatile;
}

internal sealed class BtfConstNode(int id, string name, uint targetId)
    : BtfModifierNode(id, name, targetId), IBtfConst
{
    public override BtfKind Kind => BtfKind.Const;
}

internal sealed class BtfRestrictNode(int id, string name, uint targetId)
    : BtfModifierNode(id, name, targetId), IBtfRestrict
{
    public override BtfKind Kind => BtfKind.Restrict;
}

internal sealed class BtfTypeTagNode(int id, string name, uint targetId)
    : BtfModifierNode(id, name, targetId), IBtfTypeTag
{
    public override BtfKind Kind => BtfKind.TypeTag;
}

internal sealed class BtfFuncNode(int id, string name, uint protoId, BtfLinkage linkage)
    : BtfTypeNode(id, name), IBtfFunc
{
    private readonly uint _protoId = protoId;

    public override BtfKind Kind => BtfKind.Func;
    public BtfLinkage Linkage { get; } = linkage;
    public IBtfFuncProto Proto { get; private set; } = null!;

    internal override void Link(BtfTypeGraph graph) =>
        Proto = graph.ResolveRequired<IBtfFuncProto>(_protoId, this, "prototype");
}

internal sealed class BtfFuncProtoNode(int id, string name, uint returnTypeId, RawParam[] parameters)
    : BtfTypeNode(id, name), IBtfFuncProto
{
    private readonly uint _returnTypeId = returnTypeId;
    private readonly RawParam[] _raw = parameters;

    public override BtfKind Kind => BtfKind.FuncProto;
    public IBtfType? ReturnType { get; private set; }
    public IReadOnlyList<BtfParam> Params { get; private set; } = Array.Empty<BtfParam>();

    internal override void Link(BtfTypeGraph graph)
    {
        ReturnType = graph.ResolveOptional(_returnTypeId);

        var parameters = new BtfParam[_raw.Length];
        for (var i = 0; i < _raw.Length; i++)
        {
            var raw = _raw[i];

            // A trailing entry with no name and no type is the C ellipsis, not a void parameter.
            var type = raw.TypeId == 0 ? null : graph.ResolveRequired(raw.TypeId, this, $"parameter {i}");
            parameters[i] = new BtfParam(raw.Name, type);
        }

        Params = Array.AsReadOnly(parameters);
    }
}

internal sealed class BtfVarNode(int id, string name, uint typeId, BtfLinkage linkage)
    : BtfTypeNode(id, name), IBtfVar
{
    private readonly uint _typeId = typeId;

    public override BtfKind Kind => BtfKind.Var;
    public BtfLinkage Linkage { get; } = linkage;
    public IBtfType Type { get; private set; } = null!;

    internal override void Link(BtfTypeGraph graph) => Type = graph.ResolveRequired(_typeId, this, "variable type");
}

internal sealed class BtfDatasecNode(int id, string name, uint sizeBytes, RawSecInfo[] variables)
    : BtfTypeNode(id, name), IBtfDatasec
{
    private readonly RawSecInfo[] _raw = variables;

    public override BtfKind Kind => BtfKind.Datasec;
    public uint SizeBytes { get; } = sizeBytes;
    public IReadOnlyList<BtfDatasecVar> Variables { get; private set; } = Array.Empty<BtfDatasecVar>();

    internal override void Link(BtfTypeGraph graph)
    {
        var variables = new BtfDatasecVar[_raw.Length];
        for (var i = 0; i < _raw.Length; i++)
        {
            var raw = _raw[i];
            var variable = graph.ResolveRequired<IBtfVar>(raw.TypeId, this, $"entry {i}");
            variables[i] = new BtfDatasecVar(variable, raw.Offset, raw.Size);
        }

        Variables = Array.AsReadOnly(variables);
    }
}

internal sealed class BtfDeclTagNode(int id, string name, uint targetId, int componentIndex)
    : BtfTypeNode(id, name), IBtfDeclTag
{
    private readonly uint _targetId = targetId;

    public override BtfKind Kind => BtfKind.DeclTag;
    public string Value => Name;
    public int ComponentIndex { get; } = componentIndex;
    public IBtfType Target { get; private set; } = null!;

    internal override void Link(BtfTypeGraph graph) => Target = graph.ResolveRequired(_targetId, this, "tagged type");
}
