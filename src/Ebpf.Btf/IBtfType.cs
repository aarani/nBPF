namespace Ebpf.Btf;

/// <summary>Linkage of a BTF_KIND_FUNC or BTF_KIND_VAR entry.</summary>
public enum BtfLinkage : byte
{
    Static = 0,
    Global = 1,
    Extern = 2,
}

/// <summary>A single member of a BTF_KIND_STRUCT or BTF_KIND_UNION.</summary>
public readonly record struct BtfMember(string Name, IBtfType Type, uint BitOffset, byte BitfieldSize);

/// <summary>A single value of a BTF_KIND_ENUM.</summary>
public readonly record struct BtfEnumValue(string Name, int Value);

/// <summary>A single value of a BTF_KIND_ENUM64.</summary>
public readonly record struct BtfEnum64Value(string Name, ulong Value);

/// <summary>A single parameter of a BTF_KIND_FUNC_PROTO. <see cref="Type"/> is null for a trailing vararg ("...").</summary>
public readonly record struct BtfParam(string Name, IBtfType? Type);

/// <summary>A single variable entry within a BTF_KIND_DATASEC (e.g. one global inside .rodata).</summary>
public readonly record struct BtfDatasecVar(IBtfVar Variable, uint Offset, uint Size);

/// <summary>
/// A node in the BTF type graph. Every concrete BTF kind implements this plus the
/// matching <c>IBtf*</c> sub-interface for its kind-specific data.
/// </summary>
public interface IBtfType
{
    /// <summary>The type id, i.e. this type's index into <see cref="IBtfTypeGraph.Types"/>.</summary>
    int Id { get; }

    BtfKind Kind { get; }

    /// <summary>Empty for anonymous types (anonymous structs/unions, qualifiers, etc.).</summary>
    string Name { get; }
}

public interface IBtfInt : IBtfType
{
    int SizeBytes { get; }
    byte Bits { get; }
    byte Offset { get; }
    bool IsSigned { get; }
    bool IsChar { get; }
    bool IsBool { get; }
}

public interface IBtfPtr : IBtfType
{
    /// <summary>Null represents a pointer to void.</summary>
    IBtfType? Pointee { get; }
}

public interface IBtfArray : IBtfType
{
    IBtfType ElementType { get; }
    IBtfType IndexType { get; }
    uint Length { get; }
}

public interface IBtfStruct : IBtfType
{
    int SizeBytes { get; }
    IReadOnlyList<BtfMember> Members { get; }
}

public interface IBtfUnion : IBtfType
{
    int SizeBytes { get; }
    IReadOnlyList<BtfMember> Members { get; }
}

public interface IBtfEnum : IBtfType
{
    int SizeBytes { get; }
    bool IsSigned { get; }
    IReadOnlyList<BtfEnumValue> Values { get; }
}

public interface IBtfEnum64 : IBtfType
{
    int SizeBytes { get; }
    bool IsSigned { get; }
    IReadOnlyList<BtfEnum64Value> Values { get; }
}

public interface IBtfFwd : IBtfType
{
    bool IsUnion { get; }
}

public interface IBtfTypedef : IBtfType
{
    /// <summary>Null represents void, as in <c>typedef void foo;</c>.</summary>
    IBtfType? Target { get; }
}

/// <summary>Common shape of the three qualifier kinds: volatile, const, restrict.</summary>
public interface IBtfQualifier : IBtfType
{
    /// <summary>Null represents void. <c>const void *p</c> encodes as PTR → CONST → void, so this is a real case, not a malformed one.</summary>
    IBtfType? Target { get; }
}

public interface IBtfVolatile : IBtfQualifier;

public interface IBtfConst : IBtfQualifier;

public interface IBtfRestrict : IBtfQualifier;

public interface IBtfFunc : IBtfType
{
    IBtfFuncProto Proto { get; }
    BtfLinkage Linkage { get; }
}

public interface IBtfFuncProto : IBtfType
{
    /// <summary>Null return type means void.</summary>
    IBtfType? ReturnType { get; }
    IReadOnlyList<BtfParam> Params { get; }
}

public interface IBtfVar : IBtfType
{
    IBtfType Type { get; }
    BtfLinkage Linkage { get; }
}

public interface IBtfDatasec : IBtfType
{
    uint SizeBytes { get; }
    IReadOnlyList<BtfDatasecVar> Variables { get; }
}

public interface IBtfFloat : IBtfType
{
    int SizeBytes { get; }
}

public interface IBtfDeclTag : IBtfType
{
    IBtfType Target { get; }

    /// <summary>The tag text. BTF stores it in the type's name field, so this equals <see cref="IBtfType.Name"/>.</summary>
    string Value { get; }

    /// <summary>-1 when the tag applies to the target itself rather than one of its members/params.</summary>
    int ComponentIndex { get; }
}

public interface IBtfTypeTag : IBtfType
{
    /// <summary>Null represents void; a type tag decays like a qualifier and can sit directly on void.</summary>
    IBtfType? Target { get; }
}
