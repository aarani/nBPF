namespace Nbpf.Btf;

/// <summary>BTF_KIND_* from the kernel's BTF type encoding.</summary>
public enum BtfKind : byte
{
    Void = 0,
    Int = 1,
    Ptr = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    Enum = 6,
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Func = 12,
    FuncProto = 13,
    Var = 14,
    Datasec = 15,
    Float = 16,
    DeclTag = 17,
    TypeTag = 18,
    Enum64 = 19,
}
