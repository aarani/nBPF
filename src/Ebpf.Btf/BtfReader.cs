namespace Ebpf.Btf;

/// <summary>
/// Parses a raw <c>.BTF</c> section — from an ELF object or from <c>/sys/kernel/btf/*</c> —
/// into a linked type graph.
/// </summary>
public sealed class BtfReader : IBtfReader
{
    /// <summary>Convenience entry point for callers that do not need the interface.</summary>
    public static IBtfTypeGraph Read(byte[] btf) => new BtfReader().Parse(btf);

    public IBtfTypeGraph Parse(byte[] btf)
    {
        if (btf is null)
            throw new ArgumentNullException(nameof(btf));

        var header = BtfHeader.Parse(btf);
        var strings = new BtfStringTable(btf, header.StringStart, checked((int)header.StrLen));

        var cursor = new BtfCursor(btf, header.TypeStart, header.TypeStart + (int)header.TypeLen, header.BigEndian);

        // Pass 1: decode each record, keeping cross-references as raw ids. Ids are 1-based;
        // id 0 is the implicit void and has no record.
        var nodes = new List<BtfTypeNode>();
        while (cursor.Remaining > 0)
            nodes.Add(ReadType(cursor, strings, nodes.Count + 1));

        // Pass 2: turn raw ids into references. Separate pass because ids may point forward.
        var graph = new BtfTypeGraph(nodes.ToArray());
        foreach (var node in nodes)
            node.Link(graph);

        return graph;
    }

    private static BtfTypeNode ReadType(BtfCursor c, BtfStringTable strings, int id)
    {
        var nameOffset = c.ReadU32();
        var info = c.ReadU32();
        var sizeOrType = c.ReadU32();

        // info packs: vlen in bits 0-15, kind in bits 24-28, kind_flag in bit 31.
        var kind = (BtfKind)((info >> 24) & 0x1F);
        var vlen = (int)(info & 0xFFFF);
        var kindFlag = (info & 0x80000000) != 0;

        var name = strings.Get(nameOffset);

        switch (kind)
        {
            case BtfKind.Int:
                return new BtfIntNode(id, name, CheckSize(sizeOrType, id, kind), c.ReadU32());

            case BtfKind.Ptr:
                return new BtfPtrNode(id, name, sizeOrType);

            case BtfKind.Array:
            {
                var elementId = c.ReadU32();
                var indexId = c.ReadU32();
                var length = c.ReadU32();
                return new BtfArrayNode(id, name, elementId, indexId, length);
            }

            case BtfKind.Struct:
            case BtfKind.Union:
            {
                var members = new RawMember[vlen];
                for (var i = 0; i < vlen; i++)
                {
                    var memberName = strings.Get(c.ReadU32());
                    var memberType = c.ReadU32();
                    var offset = c.ReadU32();
                    members[i] = new RawMember(memberName, memberType, offset);
                }

                var size = CheckSize(sizeOrType, id, kind);
                return kind == BtfKind.Struct
                    ? new BtfStructNode(id, name, size, members, kindFlag)
                    : new BtfUnionNode(id, name, size, members, kindFlag);
            }

            case BtfKind.Enum:
            {
                var values = new BtfEnumValue[vlen];
                for (var i = 0; i < vlen; i++)
                {
                    var valueName = strings.Get(c.ReadU32());
                    values[i] = new BtfEnumValue(valueName, c.ReadI32());
                }

                // For enums the kind_flag carries signedness rather than bitfield info.
                return new BtfEnumNode(id, name, CheckSize(sizeOrType, id, kind), kindFlag, values);
            }

            case BtfKind.Enum64:
            {
                var values = new BtfEnum64Value[vlen];
                for (var i = 0; i < vlen; i++)
                {
                    var valueName = strings.Get(c.ReadU32());
                    var low = c.ReadU32();
                    var high = c.ReadU32();
                    values[i] = new BtfEnum64Value(valueName, ((ulong)high << 32) | low);
                }

                return new BtfEnum64Node(id, name, CheckSize(sizeOrType, id, kind), kindFlag, values);
            }

            case BtfKind.Fwd:
                return new BtfFwdNode(id, name, kindFlag);

            case BtfKind.Typedef:
                return new BtfTypedefNode(id, name, sizeOrType);

            case BtfKind.Volatile:
                return new BtfVolatileNode(id, name, sizeOrType);

            case BtfKind.Const:
                return new BtfConstNode(id, name, sizeOrType);

            case BtfKind.Restrict:
                return new BtfRestrictNode(id, name, sizeOrType);

            case BtfKind.TypeTag:
                return new BtfTypeTagNode(id, name, sizeOrType);

            case BtfKind.Func:
                // FUNC has no trailing data; vlen is repurposed to carry the linkage.
                return new BtfFuncNode(id, name, sizeOrType, ReadLinkage((uint)vlen, id));

            case BtfKind.FuncProto:
            {
                var parameters = new RawParam[vlen];
                for (var i = 0; i < vlen; i++)
                {
                    var paramName = strings.Get(c.ReadU32());
                    parameters[i] = new RawParam(paramName, c.ReadU32());
                }

                return new BtfFuncProtoNode(id, name, sizeOrType, parameters);
            }

            case BtfKind.Var:
                return new BtfVarNode(id, name, sizeOrType, ReadLinkage(c.ReadU32(), id));

            case BtfKind.Datasec:
            {
                var variables = new RawSecInfo[vlen];
                for (var i = 0; i < vlen; i++)
                {
                    var varType = c.ReadU32();
                    var offset = c.ReadU32();
                    var size = c.ReadU32();
                    variables[i] = new RawSecInfo(varType, offset, size);
                }

                return new BtfDatasecNode(id, name, sizeOrType, variables);
            }

            case BtfKind.Float:
                return new BtfFloatNode(id, name, CheckSize(sizeOrType, id, kind));

            case BtfKind.DeclTag:
                return new BtfDeclTagNode(id, name, sizeOrType, c.ReadI32());

            case BtfKind.Void:
            default:
                // Unknown kinds cannot be skipped: their trailing data length is unknown, so the
                // rest of the section would be misparsed. Sanitization has to happen before this.
                throw new BtfFormatException($"BTF type id {id} has unsupported kind {(int)kind}");
        }
    }

    private static int CheckSize(uint size, int id, BtfKind kind)
    {
        if (size > int.MaxValue)
            throw new BtfFormatException($"BTF type id {id} ({kind}) declares an implausible size of {size} bytes");

        return (int)size;
    }

    private static BtfLinkage ReadLinkage(uint raw, int id) => raw switch
    {
        0 => BtfLinkage.Static,
        1 => BtfLinkage.Global,
        2 => BtfLinkage.Extern,
        _ => throw new BtfFormatException($"BTF type id {id} has unrecognized linkage {raw}"),
    };
}
