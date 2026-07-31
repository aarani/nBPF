namespace Ebpf.Btf;

/// <summary>
/// A parsed BTF type section. Shared read-only view used by map definitions, CO-RE
/// relocation, and C# codegen alike — see DESIGN.md §4.3.
/// </summary>
public interface IBtfTypeGraph
{
    /// <summary>
    /// All types in id order, excluding the implicit void at id 0 — so <c>Types[i].Id == i + 1</c>.
    /// Void is never a list entry; it shows up as a null reference on <see cref="IBtfPtr.Pointee"/> and friends.
    /// To look up by type id, use <see cref="this[int]"/> rather than indexing this list.
    /// </summary>
    IReadOnlyList<IBtfType> Types { get; }

    IBtfType this[int id] { get; }

    bool TryGetType(int id, out IBtfType type);

    /// <summary>First type named <paramref name="name"/> of the given kind, or null. BTF allows name collisions across kinds (e.g. a struct and a typedef sharing a name).</summary>
    IBtfType? Find(string name, BtfKind kind);
}
