using System.Globalization;

namespace Nbpf.Btf;

/// <summary>
/// The CO-RE relocation algorithm (DESIGN §4.4 step 4), matching libbpf's
/// <c>relo_core.c</c> semantics, which the test suite pins down:
///
/// <para><b>Spec.</b> The access string ("0:1:2") is parsed against the local type. The
/// first index scales by the root type's size (pointer-arithmetic on the root); each
/// later index steps into a struct/union member or an array element, accumulating a bit
/// offset. Typedefs and qualifiers are transparent. Steps through <em>anonymous</em>
/// members contribute offset but no named step, so only named members and array indexes
/// take part in matching.</para>
///
/// <para><b>Candidates.</b> Target candidates are the target types whose kind is
/// compatible with the local root's and whose <em>essential name</em> matches — the name
/// with any "___flavor" suffix stripped, on both sides. Every candidate that matches the
/// spec must agree on the resulting values; disagreement is a
/// <see cref="CoreReloException"/>. Matching walks the spec by member <em>name</em>
/// (recursing into anonymous target members), rechecking array bounds, and requires
/// leaf field compatibility: any int matches any int, any pointer any pointer, arrays
/// recurse on elements, composites match composites, enums match by essential name.</para>
///
/// <para><b>No match.</b> Existence probes (<see cref="BtfCoreReloKind.FieldExists"/>,
/// <see cref="BtfCoreReloKind.TypeExists"/>, <see cref="BtfCoreReloKind.EnumValExists"/>,
/// <see cref="BtfCoreReloKind.TypeMatches"/>) resolve to 0; the other type-based kinds
/// also resolve to 0; field-value and enum-value kinds poison instead.</para>
///
/// <para><b>Bitfields.</b> A bitfield's byte offset is the offset of the smallest
/// naturally-aligned load (starting at the member type's size, doubling as needed) that
/// covers it; on a little-endian target, FieldLShiftU64 is
/// <c>64 − (bitOffset + bitSize − 8·byteOffset)</c> and FieldRShiftU64 is
/// <c>64 − bitSize</c>. Bitfield results never validate, except the right shift and
/// signedness, which are unambiguous.</para>
/// </summary>
public sealed class CoreReloResolver : ICoreReloResolver
{
    /// <summary>How deep the structural checks behind TypeExists/TypeMatches recurse
    /// before accepting on name + kind alone — libbpf's MAX_TYPES_MATCH_DEPTH. Keeps
    /// self-referential types (struct s { struct s *next; }) from recursing forever.</summary>
    private const int MatchDepth = 2;

    public CoreReloResult Resolve(BtfCoreRelo relo, IBtfTypeGraph localBtf, IBtfTypeGraph targetBtf)
    {
        var spec = ParseAccessString(relo);

        if (relo.TypeId > int.MaxValue || !localBtf.TryGetType((int)relo.TypeId, out var root))
            throw new CoreReloException(
                $"CO-RE relocation names local type id {relo.TypeId}, which is not in the local BTF.");

        switch (relo.Kind)
        {
            case BtfCoreReloKind.FieldByteOffset:
            case BtfCoreReloKind.FieldByteSize:
            case BtfCoreReloKind.FieldExists:
            case BtfCoreReloKind.FieldSigned:
            case BtfCoreReloKind.FieldLShiftU64:
            case BtfCoreReloKind.FieldRShiftU64:
                return ResolveField(relo, spec, root, targetBtf);

            case BtfCoreReloKind.TypeIdLocal:
                // Needs no target at all — and ids drift during linking, so no validation.
                RequireTypeSpec(relo, spec);
                return new CoreReloResult(relo.TypeId, relo.TypeId, Poison: false, Validate: false);

            case BtfCoreReloKind.TypeIdTarget:
            case BtfCoreReloKind.TypeExists:
            case BtfCoreReloKind.TypeSize:
            case BtfCoreReloKind.TypeMatches:
                return ResolveType(relo, spec, root, targetBtf);

            case BtfCoreReloKind.EnumValExists:
            case BtfCoreReloKind.EnumValValue:
                return ResolveEnumVal(relo, spec, root, targetBtf);

            default:
                throw new CoreReloException($"Unsupported CO-RE relocation kind {relo.Kind}.");
        }
    }

    // ---- field relocations -------------------------------------------------------

    private static CoreReloResult ResolveField(
        BtfCoreRelo relo, int[] spec, IBtfType root, IBtfTypeGraph targetBtf)
    {
        var local = WalkLocalField(relo, spec, root);

        // The validate flag is decided by the *local* field's shape (libbpf does the
        // same): a locally-plain field has an exact baked-in value even if the target
        // turns out to place it elsewhere.
        var (oldValue, validate) = CalcField(relo, local.BitOffset, local.Leaf, local.BitfieldSize);

        ulong? newValue = null;
        foreach (var candidate in Candidates(root, targetBtf))
        {
            if (!TryMatchField(spec[0], local.Accessors, candidate,
                    out long bitOffset, out var leaf, out byte bitfieldSize))
                continue;

            var (value, _) = CalcField(relo, bitOffset, leaf, bitfieldSize);
            if (newValue is { } seen && seen != value)
                throw new CoreReloException(
                    $"Ambiguous CO-RE relocation '{relo.AccessString}' against '{root.Name}': " +
                    $"target candidates disagree ({seen} vs {value}).");
            newValue = value;
        }

        if (newValue is null)
            return relo.Kind == BtfCoreReloKind.FieldExists
                ? new CoreReloResult(oldValue, 0, Poison: false, Validate: true)
                : new CoreReloResult(oldValue, 0, Poison: true, Validate: validate);

        return new CoreReloResult(oldValue, newValue.Value, Poison: false, Validate: validate);
    }

    private readonly record struct Accessor(string? Name, int Index, IBtfType? MemberType);

    private readonly record struct LocalField(
        long BitOffset, IReadOnlyList<Accessor> Accessors, IBtfType? Leaf, byte BitfieldSize);

    /// <summary>Evaluates the raw access spec against the local type: accumulates the
    /// bit offset, records the named/array steps (anonymous members vanish here), and
    /// remembers the leaf. Local-side failures are hard errors, never poison.</summary>
    private static LocalField WalkLocalField(BtfCoreRelo relo, int[] spec, IBtfType root)
    {
        var accessors = new List<Accessor>();
        long bitOffset = (long)spec[0] * SizeOf(root) * 8;
        IBtfType? current = root;
        var leaf = SkipModsAndTypedefs(root);
        byte bitfieldSize = 0;

        for (int i = 1; i < spec.Length; i++)
        {
            current = SkipModsAndTypedefs(current);
            int index = spec[i];

            if (MembersOf(current) is { } members)
            {
                if (index >= members.Count)
                    throw new CoreReloException(
                        $"Access spec '{relo.AccessString}' step {i}: index {index} is out of " +
                        $"range for '{current!.Name}', which has {members.Count} members.");

                var member = members[index];
                bitOffset += member.BitOffset;
                if (member.Name.Length > 0)
                    accessors.Add(new Accessor(member.Name, index, member.Type));
                leaf = SkipModsAndTypedefs(member.Type);
                bitfieldSize = member.BitfieldSize;
                current = member.Type;
            }
            else if (current is IBtfArray array)
            {
                if (array.Length != 0 && (uint)index >= array.Length)
                    throw new CoreReloException(
                        $"Access spec '{relo.AccessString}' step {i}: index {index} is out of " +
                        $"bounds of the local array of length {array.Length}.");

                bitOffset += (long)index * SizeOf(array.ElementType) * 8;
                accessors.Add(new Accessor(null, index, null));
                leaf = SkipModsAndTypedefs(array.ElementType);
                bitfieldSize = 0;
                current = array.ElementType;
            }
            else
            {
                throw new CoreReloException(
                    $"Access spec '{relo.AccessString}' step {i} descends into a " +
                    $"{current?.Kind.ToString() ?? "void"}, which has no fields.");
            }
        }

        return new LocalField(bitOffset, accessors, leaf, bitfieldSize);
    }

    /// <summary>Replays the local spec's steps against one target candidate, by member
    /// name rather than index. False means "this candidate doesn't have the field" —
    /// the poison/exists path, not an error.</summary>
    private static bool TryMatchField(
        int rootIndex, IReadOnlyList<Accessor> accessors, IBtfType candidate,
        out long bitOffset, out IBtfType? leaf, out byte bitfieldSize)
    {
        bitOffset = (long)rootIndex * SizeOf(candidate) * 8;
        IBtfType? current = candidate;
        leaf = SkipModsAndTypedefs(candidate);
        bitfieldSize = 0;

        foreach (var accessor in accessors)
        {
            current = SkipModsAndTypedefs(current);

            if (accessor.Name is { } name)
            {
                if (MembersOf(current) is not { } members ||
                    !TryFindMember(members, name, accessor.MemberType, ref bitOffset, out var member))
                    return false;

                leaf = SkipModsAndTypedefs(member.Type);
                bitfieldSize = member.BitfieldSize;
                current = member.Type;
            }
            else
            {
                if (current is not IBtfArray array)
                    return false;
                if (array.Length != 0 && (uint)accessor.Index >= array.Length)
                    return false;

                bitOffset += (long)accessor.Index * SizeOf(array.ElementType) * 8;
                leaf = SkipModsAndTypedefs(array.ElementType);
                bitfieldSize = 0;
                current = array.ElementType;
            }
        }

        return true;
    }

    /// <summary>Finds a member by name, recursing into anonymous nested composites the
    /// way `s.a` reaches through `struct s { struct { int a; }; }`.</summary>
    private static bool TryFindMember(
        IReadOnlyList<BtfMember> members, string name, IBtfType? localMemberType,
        ref long bitOffset, out BtfMember found)
    {
        foreach (var member in members)
        {
            if (member.Name == name)
            {
                if (FieldsCompatible(localMemberType, member.Type))
                {
                    bitOffset += member.BitOffset;
                    found = member;
                    return true;
                }
            }
            else if (member.Name.Length == 0 &&
                     MembersOf(SkipModsAndTypedefs(member.Type)) is { } inner)
            {
                long innerOffset = bitOffset + member.BitOffset;
                if (TryFindMember(inner, name, localMemberType, ref innerOffset, out found))
                {
                    bitOffset = innerOffset;
                    return true;
                }
            }
        }

        found = default;
        return false;
    }

    /// <summary>libbpf's bpf_core_fields_are_compat: how loose a matched leaf may be.
    /// Ints ignore width and signedness — that is what field-size relocations exist for.</summary>
    private static bool FieldsCompatible(IBtfType? local, IBtfType? target)
    {
        local = SkipModsAndTypedefs(local);
        target = SkipModsAndTypedefs(target);
        if (local is null || target is null)
            return local is null && target is null;

        if (IsComposite(local) && IsComposite(target))
            return true;
        if (!KindsCompatible(local, target))
            return false;

        return local switch
        {
            IBtfPtr or IBtfFloat => true,
            IBtfEnum or IBtfEnum64 or IBtfFwd => EssentialNamesAgree(local, target),
            // Reject only the legacy "int at a bit offset" encoding; sizes may differ.
            IBtfInt localInt => localInt.Offset == 0 && ((IBtfInt)target).Offset == 0,
            IBtfArray localArray =>
                FieldsCompatible(localArray.ElementType, ((IBtfArray)target).ElementType),
            _ => false,
        };
    }

    /// <summary>The per-kind value computation, shared verbatim between the local side
    /// (producing <see cref="CoreReloResult.OldValue"/>) and each matched target.</summary>
    private static (ulong Value, bool Validate) CalcField(
        BtfCoreRelo relo, long bitOffset, IBtfType? leaf, byte bitfieldSize)
    {
        if (relo.Kind == BtfCoreReloKind.FieldExists)
            return (1, true);

        if (leaf is null)
            throw new CoreReloException(
                $"Access spec '{relo.AccessString}' resolves to void, which has no layout.");

        bool bitfield = bitfieldSize > 0;
        long byteSize = SizeOf(leaf);
        long byteOffset;
        long bitSize;

        if (bitfield)
        {
            // The smallest naturally-aligned load, starting at the member type's own
            // width and doubling, that covers every bit of the field.
            byteOffset = bitOffset / 8 / byteSize * byteSize;
            while (bitOffset + bitfieldSize - byteOffset * 8 > byteSize * 8)
            {
                if (byteSize >= 8)
                    throw new CoreReloException(
                        $"Bitfield at bit {bitOffset} ('{relo.AccessString}') cannot be " +
                        "covered by a single 64-bit load.");
                byteSize *= 2;
                byteOffset = bitOffset / 8 / byteSize * byteSize;
            }
            bitSize = bitfieldSize;
        }
        else
        {
            byteOffset = bitOffset / 8;
            bitSize = byteSize * 8;
        }

        // Bitfield placement is ambiguous between compilers, so those values are not
        // validated — except signedness and the right shift, which never vary.
        bool validate = !bitfield;

        ulong value;
        switch (relo.Kind)
        {
            case BtfCoreReloKind.FieldByteOffset:
                value = (ulong)byteOffset;
                break;
            case BtfCoreReloKind.FieldByteSize:
                value = (ulong)byteSize;
                break;
            case BtfCoreReloKind.FieldSigned:
                value = IsSignedType(leaf) ? 1ul : 0ul;
                validate = true;
                break;
            case BtfCoreReloKind.FieldLShiftU64:
                // Little-endian form; the loader already rejects big-endian objects.
                value = (ulong)(64 - (bitOffset + bitSize - byteOffset * 8));
                break;
            case BtfCoreReloKind.FieldRShiftU64:
                value = (ulong)(64 - bitSize);
                validate = true;
                break;
            default:
                throw new CoreReloException($"{relo.Kind} is not a field relocation.");
        }

        return (value, validate);
    }

    // ---- enum-value relocations --------------------------------------------------

    private static CoreReloResult ResolveEnumVal(
        BtfCoreRelo relo, int[] spec, IBtfType root, IBtfTypeGraph targetBtf)
    {
        if (spec.Length != 1)
            throw new CoreReloException(
                $"Enum-value relocation access spec must be a single index, got '{relo.AccessString}'.");

        var localValues = EnumValuesOf(root) ?? throw new CoreReloException(
            $"Enum-value relocation against '{root.Name}', which is not an enum.");
        if (spec[0] >= localValues.Count)
            throw new CoreReloException(
                $"Enum-value index {spec[0]} is out of range for '{root.Name}', " +
                $"which has {localValues.Count} values.");

        var (localName, localValue) = localValues[spec[0]];
        string essentialName = EssentialName(localName);
        ulong oldValue = relo.Kind == BtfCoreReloKind.EnumValExists ? 1 : localValue;

        ulong? newValue = null;
        foreach (var candidate in Candidates(root, targetBtf))
        {
            if (EnumValuesOf(candidate) is not { } values)
                continue;

            foreach (var (name, value) in values)
            {
                if (EssentialName(name) != essentialName)
                    continue;

                ulong resolved = relo.Kind == BtfCoreReloKind.EnumValExists ? 1 : value;
                if (newValue is { } seen && seen != resolved)
                    throw new CoreReloException(
                        $"Ambiguous CO-RE relocation for enum value '{localName}' of " +
                        $"'{root.Name}': target candidates disagree ({seen} vs {resolved}).");
                newValue = resolved;
                break;
            }
        }

        if (newValue is null)
            return relo.Kind == BtfCoreReloKind.EnumValExists
                ? new CoreReloResult(oldValue, 0, Poison: false, Validate: true)
                : new CoreReloResult(oldValue, 0, Poison: true, Validate: true);

        return new CoreReloResult(oldValue, newValue.Value, Poison: false, Validate: true);
    }

    // ---- type relocations --------------------------------------------------------

    private static CoreReloResult ResolveType(
        BtfCoreRelo relo, int[] spec, IBtfType root, IBtfTypeGraph targetBtf)
    {
        RequireTypeSpec(relo, spec);

        ulong oldValue = relo.Kind switch
        {
            BtfCoreReloKind.TypeExists or BtfCoreReloKind.TypeMatches => 1,
            BtfCoreReloKind.TypeSize => (ulong)SizeOf(root),
            _ => relo.TypeId, // TypeIdTarget: the compiler baked the local id
        };

        ulong? newValue = null;
        foreach (var candidate in Candidates(root, targetBtf))
        {
            bool matches = relo.Kind == BtfCoreReloKind.TypeMatches
                ? TypesMatch(root, candidate, MatchDepth)
                : TypesAreCompatible(root, candidate, MatchDepth);
            if (!matches)
                continue;

            ulong value = relo.Kind switch
            {
                BtfCoreReloKind.TypeExists or BtfCoreReloKind.TypeMatches => 1,
                BtfCoreReloKind.TypeSize => (ulong)SizeOf(candidate),
                _ => (ulong)candidate.Id,
            };
            if (newValue is { } seen && seen != value)
                throw new CoreReloException(
                    $"Ambiguous CO-RE type relocation against '{root.Name}': " +
                    $"target candidates disagree ({seen} vs {value}).");
            newValue = value;
        }

        // Type relocations never poison: a missing type resolves to zero.
        if (newValue is null)
            return new CoreReloResult(oldValue, 0, Poison: false, Validate: true);

        // Target ids drift during linking, so TypeIdTarget is never validated.
        bool validate = relo.Kind != BtfCoreReloKind.TypeIdTarget;
        return new CoreReloResult(oldValue, newValue.Value, Poison: false, Validate: validate);
    }

    /// <summary>libbpf's types_are_compat: shallow structural agreement. Named kinds
    /// pass on kind alone (the candidate search already matched names); pointers,
    /// arrays, and prototypes recurse a bounded number of levels.</summary>
    private static bool TypesAreCompatible(IBtfType? local, IBtfType? target, int depth)
    {
        local = SkipModsAndTypedefs(local);
        target = SkipModsAndTypedefs(target);
        if (local is null || target is null)
            return local is null && target is null;
        if (!KindsCompatible(local, target))
            return false;
        if (depth <= 0)
            return true;

        return local switch
        {
            IBtfStruct or IBtfUnion or IBtfEnum or IBtfEnum64 or
            IBtfFwd or IBtfInt or IBtfFloat => true,
            IBtfPtr ptr => TypesAreCompatible(ptr.Pointee, ((IBtfPtr)target).Pointee, depth - 1),
            IBtfArray array =>
                TypesAreCompatible(array.ElementType, ((IBtfArray)target).ElementType, depth - 1),
            IBtfFuncProto proto => ProtosCompatible(proto, (IBtfFuncProto)target, depth - 1, TypesAreCompatible),
            _ => false,
        };
    }

    /// <summary>libbpf's types_match, behind <see cref="BtfCoreReloKind.TypeMatches"/>:
    /// names must agree at every level, every local member/value must exist in the
    /// target with a matching type, ints and floats must keep their width. The target
    /// may have extra members — that is the point of the probe.</summary>
    private static bool TypesMatch(IBtfType? local, IBtfType? target, int depth)
    {
        local = SkipModsAndTypedefs(local);
        target = SkipModsAndTypedefs(target);
        if (local is null || target is null)
            return local is null && target is null;
        if (!KindsCompatible(local, target))
            return false;
        if (EssentialName(local.Name) != EssentialName(target.Name))
            return false;
        if (depth <= 0)
            return true;

        switch (local)
        {
            case IBtfInt localInt:
                var targetInt = (IBtfInt)target;
                return localInt.SizeBytes == targetInt.SizeBytes &&
                       localInt.Offset == 0 && targetInt.Offset == 0;

            case IBtfFloat localFloat:
                return localFloat.SizeBytes == ((IBtfFloat)target).SizeBytes;

            case IBtfFwd:
                return true;

            case IBtfPtr localPtr:
                return TypesMatch(localPtr.Pointee, ((IBtfPtr)target).Pointee, depth - 1);

            case IBtfArray localArray:
                var targetArray = (IBtfArray)target;
                return localArray.Length == targetArray.Length &&
                       TypesMatch(localArray.ElementType, targetArray.ElementType, depth - 1);

            case IBtfEnum or IBtfEnum64:
                var localValues = EnumValuesOf(local)!;
                var targetValues = EnumValuesOf(target)!;
                return localValues.All(lv =>
                    targetValues.Any(tv => EssentialName(tv.Name) == EssentialName(lv.Name)));

            case IBtfStruct or IBtfUnion:
                var targetMembers = MembersOf(target)!;
                return MembersOf(local)!.All(lm => targetMembers.Any(tm =>
                    tm.Name == lm.Name && TypesMatch(lm.Type, tm.Type, depth - 1)));

            case IBtfFuncProto localProto:
                return ProtosCompatible(localProto, (IBtfFuncProto)target, depth - 1, TypesMatch);

            default:
                return false;
        }
    }

    private static bool ProtosCompatible(
        IBtfFuncProto local, IBtfFuncProto target, int depth,
        Func<IBtfType?, IBtfType?, int, bool> check)
    {
        if (local.Params.Count != target.Params.Count)
            return false;
        if (!check(local.ReturnType, target.ReturnType, depth))
            return false;
        for (int i = 0; i < local.Params.Count; i++)
        {
            if (!check(local.Params[i].Type, target.Params[i].Type, depth))
                return false;
        }
        return true;
    }

    // ---- shared helpers ----------------------------------------------------------

    private static int[] ParseAccessString(BtfCoreRelo relo)
    {
        if (relo.AccessString.Length == 0)
            throw new CoreReloException("CO-RE relocation has an empty access spec.");

        var parts = relo.AccessString.Split(':');
        var spec = new int[parts.Length];
        for (int i = 0; i < parts.Length; i++)
        {
            if (!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out spec[i]))
                throw new CoreReloException(
                    $"Malformed CO-RE access spec '{relo.AccessString}': '{parts[i]}' is not an index.");
        }

        return spec;
    }

    private static void RequireTypeSpec(BtfCoreRelo relo, int[] spec)
    {
        if (spec.Length != 1 || spec[0] != 0)
            throw new CoreReloException(
                $"Type relocation access spec must be \"0\", got '{relo.AccessString}'.");
    }

    /// <summary>Target types that can stand in for the local root: compatible kind and
    /// the same essential name. Enums and 64-bit enums are interchangeable kinds.</summary>
    private static IEnumerable<IBtfType> Candidates(IBtfType localRoot, IBtfTypeGraph targetBtf)
    {
        string name = EssentialName(localRoot.Name);
        if (name.Length == 0)
            throw new CoreReloException(
                $"Cannot search target candidates for anonymous local type id {localRoot.Id}.");

        foreach (var type in targetBtf.Types)
        {
            if (KindsCompatible(localRoot, type) && EssentialName(type.Name) == name)
                yield return type;
        }
    }

    /// <summary>The name with any "___flavor" suffix stripped.</summary>
    private static string EssentialName(string name)
    {
        int flavor = name.IndexOf("___", StringComparison.Ordinal);
        return flavor < 0 ? name : name.Substring(0, flavor);
    }

    private static bool EssentialNamesAgree(IBtfType a, IBtfType b)
    {
        string an = EssentialName(a.Name), bn = EssentialName(b.Name);
        return an.Length == 0 || bn.Length == 0 || an == bn;
    }

    private static bool KindsCompatible(IBtfType a, IBtfType b)
        => a.Kind == b.Kind || (IsAnyEnum(a) && IsAnyEnum(b));

    private static bool IsAnyEnum(IBtfType t) => t is IBtfEnum or IBtfEnum64;

    private static bool IsComposite(IBtfType t) => t is IBtfStruct or IBtfUnion;

    private static bool IsSignedType(IBtfType t) => t switch
    {
        IBtfInt i => i.IsSigned,
        IBtfEnum e => e.IsSigned,
        IBtfEnum64 e => e.IsSigned,
        _ => false,
    };

    private static IReadOnlyList<BtfMember>? MembersOf(IBtfType? t) => t switch
    {
        IBtfStruct s => s.Members,
        IBtfUnion u => u.Members,
        _ => null,
    };

    /// <summary>Enum values with 32-bit ones sign-extended, so -1 compares and patches
    /// the same whether it came from an ENUM or an ENUM64.</summary>
    private static List<(string Name, ulong Value)>? EnumValuesOf(IBtfType? t)
        => SkipModsAndTypedefs(t) switch
        {
            IBtfEnum e => e.Values.Select(v => (v.Name, (ulong)(long)v.Value)).ToList(),
            IBtfEnum64 e => e.Values.Select(v => (v.Name, v.Value)).ToList(),
            _ => null,
        };

    /// <summary>Unwraps typedefs, const/volatile/restrict, and type tags. Null is void
    /// and stays void.</summary>
    private static IBtfType? SkipModsAndTypedefs(IBtfType? t)
    {
        while (true)
        {
            switch (t)
            {
                case IBtfTypedef typedef: t = typedef.Target; break;
                case IBtfQualifier qualifier: t = qualifier.Target; break;
                case IBtfTypeTag tag: t = tag.Target; break;
                default: return t;
            }
        }
    }

    private static long SizeOf(IBtfType? t) => SkipModsAndTypedefs(t) switch
    {
        null => throw new CoreReloException("Cannot take the size of void."),
        IBtfInt i => i.SizeBytes,
        IBtfStruct s => s.SizeBytes,
        IBtfUnion u => u.SizeBytes,
        IBtfEnum e => e.SizeBytes,
        IBtfEnum64 e => e.SizeBytes,
        IBtfFloat f => f.SizeBytes,
        IBtfPtr => 8,
        IBtfArray a => a.Length * SizeOf(a.ElementType),
        { } other => throw new CoreReloException(
            $"Type '{other.Name}' ({other.Kind}) has no size."),
    };
}
