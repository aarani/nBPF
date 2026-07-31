namespace Ebpf.Btf;

/// <inheritdoc cref="IBtfTypeGraph"/>
internal sealed class BtfTypeGraph : IBtfTypeGraph
{
    private readonly BtfTypeNode[] _types;

    /// <summary>Built on first use — CO-RE looks types up by name constantly, but a plain load never does.</summary>
    private Dictionary<(string Name, BtfKind Kind), IBtfType>? _byName;

    internal BtfTypeGraph(BtfTypeNode[] types)
    {
        _types = types;
        Types = Array.AsReadOnly(types);
    }

    public IReadOnlyList<IBtfType> Types { get; }

    public IBtfType this[int id] =>
        TryGetType(id, out var type)
            ? type
            : throw new ArgumentOutOfRangeException(nameof(id), id,
                $"BTF type id out of range; this blob has ids 1..{_types.Length}" +
                (id == 0 ? " and id 0 is void, which is not a type entry" : string.Empty));

    public bool TryGetType(int id, out IBtfType type)
    {
        if (id >= 1 && id <= _types.Length)
        {
            type = _types[id - 1];
            return true;
        }

        type = null!;
        return false;
    }

    public IBtfType? Find(string name, BtfKind kind)
    {
        if (name.Length == 0)
            return null;

        if (_byName is null)
        {
            var index = new Dictionary<(string, BtfKind), IBtfType>(_types.Length);
            foreach (var type in _types)
            {
                if (type.Name.Length == 0)
                    continue;

                var key = (type.Name, type.Kind);
                if (!index.ContainsKey(key))
                    index[key] = type; // first definition wins
            }

            _byName = index;
        }

        return _byName.TryGetValue((name, kind), out var found) ? found : null;
    }

    /// <summary>Resolves a wire type id, mapping id 0 to null (void).</summary>
    internal IBtfType? ResolveOptional(uint id) =>
        id == 0 ? null : Resolve(id, null, null);

    /// <summary>Resolves a wire type id that must name a real type; id 0 (void) is an error here.</summary>
    internal IBtfType ResolveRequired(uint id, BtfTypeNode owner, string what) =>
        Resolve(id, owner, what)!;

    /// <summary>Resolves a wire type id that must name a real type of a specific kind.</summary>
    internal T ResolveRequired<T>(uint id, BtfTypeNode owner, string what) where T : class, IBtfType
    {
        var resolved = ResolveRequired(id, owner, what);
        if (resolved is not T typed)
            throw new BtfFormatException(
                $"{owner} {what} refers to type id {id}, which is {resolved.Kind}, not the expected kind");

        return typed;
    }

    private IBtfType? Resolve(uint id, BtfTypeNode? owner, string? what)
    {
        if (id == 0)
        {
            if (owner is null)
                return null;

            throw new BtfFormatException($"{owner} {what} refers to void (type id 0), which is not valid here");
        }

        if (id > int.MaxValue || !TryGetType((int)id, out var type))
            throw new BtfFormatException(owner is null
                ? $"BTF type id {id} is out of range; this blob has ids 1..{_types.Length}"
                : $"{owner} {what} refers to type id {id}, which is out of range 1..{_types.Length}");

        return type;
    }
}
