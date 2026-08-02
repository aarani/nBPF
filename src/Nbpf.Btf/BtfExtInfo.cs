namespace Nbpf.Btf;

/// <summary>
/// The parsed contents of a <c>.BTF.ext</c> section, grouped the way the section stores
/// them: per ELF program section. Instruction offsets are the raw on-disk values — byte
/// offsets into the ELF section, not instruction indexes; converting (dividing by 8) is
/// the loader's job, the same split as <see cref="BtfMapDef"/>'s raw linux/bpf.h numbers.
/// </summary>
public interface IBtfExtInfo
{
    IReadOnlyList<BtfExtSection<BtfFuncInfo>> FuncInfo { get; }
    IReadOnlyList<BtfExtSection<BtfLineInfo>> LineInfo { get; }
    IReadOnlyList<BtfExtSection<BtfCoreRelo>> CoreRelos { get; }
}

/// <summary>All records of one <c>.BTF.ext</c> info block that target a single ELF section.</summary>
public sealed class BtfExtSection<TRecord>
{
    internal BtfExtSection(string sectionName, IReadOnlyList<TRecord> records)
    {
        SectionName = sectionName;
        Records = records;
    }

    /// <summary>The ELF section the records apply to, e.g. <c>tracepoint/syscalls/sys_enter_execve</c>.</summary>
    public string SectionName { get; }

    public IReadOnlyList<TRecord> Records { get; }
}

/// <summary>
/// One <c>bpf_func_info</c> record: the instruction where a function starts, and the BTF
/// id of its <c>BTF_KIND_FUNC</c> type in the companion <c>.BTF</c> section.
/// </summary>
public readonly record struct BtfFuncInfo(uint InsnByteOffset, uint TypeId);

/// <summary>
/// One <c>bpf_line_info</c> record, with the packed <c>line_col</c> word already split
/// and the string offsets already resolved. <see cref="SourceLine"/> is the verbatim
/// source text clang embeds, leading whitespace included.
/// </summary>
public readonly record struct BtfLineInfo(
    uint InsnByteOffset,
    string FileName,
    string SourceLine,
    uint LineNumber,
    uint ColumnNumber);

/// <summary>
/// One <c>bpf_core_relo</c> record: which instruction to patch, the local type the
/// access spec starts from, and the spec itself as clang wrote it (e.g. <c>"0:1:2"</c>).
/// </summary>
public readonly record struct BtfCoreRelo(
    uint InsnByteOffset,
    uint TypeId,
    string AccessString,
    BtfCoreReloKind Kind);

/// <summary>The <c>enum bpf_core_relo_kind</c> values, numerically as linux/bpf.h defines them.</summary>
public enum BtfCoreReloKind : uint
{
    FieldByteOffset = 0,
    FieldByteSize = 1,
    FieldExists = 2,
    FieldSigned = 3,
    FieldLShiftU64 = 4,
    FieldRShiftU64 = 5,
    TypeIdLocal = 6,
    TypeIdTarget = 7,
    TypeExists = 8,
    TypeSize = 9,
    EnumValExists = 10,
    EnumValValue = 11,
    TypeMatches = 12,
}
