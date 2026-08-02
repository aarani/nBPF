namespace Nbpf.Btf;

/// <summary>
/// Parses a raw <c>.BTF.ext</c> section — clang's sidecar to <c>.BTF</c> carrying
/// func info, line info, and CO-RE relocations. Each info block is a record size
/// followed by per-ELF-section runs of fixed-size records; records larger than the
/// fields we know are legal (the format grows by appending) and the excess is skipped.
/// </summary>
public sealed class BtfExtReader : IBtfExtReader
{
    /// <summary>Convenience entry point for callers that do not need the interface.</summary>
    public static IBtfExtInfo Read(byte[] btfExt, byte[] btf) => new BtfExtReader().Parse(btfExt, btf);

    public IBtfExtInfo Parse(byte[] btfExt, byte[] btf)
    {
        if (btfExt is null)
            throw new ArgumentNullException(nameof(btfExt));
        if (btf is null)
            throw new ArgumentNullException(nameof(btf));

        var header = BtfExtHeader.Parse(btfExt);

        // .BTF.ext has no string section of its own; every string offset in it points
        // into the companion .BTF section's string table.
        var btfHeader = BtfHeader.Parse(btf);
        var strings = new BtfStringTable(btf, btfHeader.StringStart, checked((int)btfHeader.StrLen));

        return new BtfExtInfo(
            ReadBlock(btfExt, header, header.FuncInfoOff, header.FuncInfoLen, "func_info",
                minRecordSize: 8, strings,
                c => new BtfFuncInfo(c.ReadU32(), c.ReadU32())),
            ReadBlock(btfExt, header, header.LineInfoOff, header.LineInfoLen, "line_info",
                minRecordSize: 16, strings,
                c =>
                {
                    var insnOff = c.ReadU32();
                    var fileName = strings.Get(c.ReadU32());
                    var sourceLine = strings.Get(c.ReadU32());
                    var lineCol = c.ReadU32();
                    // line_col packs: line in bits 10-31, column in bits 0-9.
                    return new BtfLineInfo(insnOff, fileName, sourceLine, lineCol >> 10, lineCol & 0x3FF);
                }),
            ReadBlock(btfExt, header, header.CoreReloOff, header.CoreReloLen, "core_relo",
                minRecordSize: 16, strings,
                c =>
                {
                    var insnOff = c.ReadU32();
                    var typeId = c.ReadU32();
                    var accessString = strings.Get(c.ReadU32());
                    var kind = c.ReadU32();

                    // An unrecognized kind cannot be skipped: a relocation we do not
                    // understand is a program we cannot correctly load.
                    if (kind > (uint)BtfCoreReloKind.TypeMatches)
                        throw new BtfFormatException(
                            $".BTF.ext CO-RE relocation at instruction byte offset {insnOff} has unrecognized kind {kind}");

                    return new BtfCoreRelo(insnOff, typeId, accessString, (BtfCoreReloKind)kind);
                }));
    }

    private static IReadOnlyList<BtfExtSection<TRecord>> ReadBlock<TRecord>(
        byte[] data, BtfExtHeader header, uint off, uint len, string what,
        uint minRecordSize, BtfStringTable strings, Func<BtfCursor, TRecord> readRecord)
    {
        if (len == 0)
            return Array.Empty<BtfExtSection<TRecord>>();

        if (len < 4)
            throw new BtfFormatException(
                $".BTF.ext {what} block is {len} byte(s), too small to hold its record size");

        var start = checked((int)(header.HdrLen + off));
        var cursor = new BtfCursor(data, start, start + (int)len, header.BigEndian);

        var recordSize = cursor.ReadU32();
        if (recordSize < minRecordSize)
            throw new BtfFormatException(
                $".BTF.ext {what} record size {recordSize} is smaller than the {minRecordSize}-byte minimum");

        if ((recordSize & 3) != 0)
            throw new BtfFormatException($".BTF.ext {what} record size {recordSize} is not a multiple of 4");

        var extraPerRecord = checked((int)(recordSize - minRecordSize));

        var sections = new List<BtfExtSection<TRecord>>();
        while (cursor.Remaining > 0)
        {
            var sectionName = strings.Get(cursor.ReadU32());
            var count = cursor.ReadU32();

            // Zero records would make the run indistinguishable from garbage — and libbpf
            // rejects it too, so nothing real produces it.
            if (count == 0)
                throw new BtfFormatException(
                    $".BTF.ext {what} block declares zero records for section '{sectionName}'");

            var records = new TRecord[count];
            for (var i = 0; i < count; i++)
            {
                records[i] = readRecord(cursor);
                cursor.Skip(extraPerRecord);
            }

            sections.Add(new BtfExtSection<TRecord>(sectionName, records));
        }

        return sections;
    }

    private sealed class BtfExtInfo : IBtfExtInfo
    {
        internal BtfExtInfo(
            IReadOnlyList<BtfExtSection<BtfFuncInfo>> funcInfo,
            IReadOnlyList<BtfExtSection<BtfLineInfo>> lineInfo,
            IReadOnlyList<BtfExtSection<BtfCoreRelo>> coreRelos)
        {
            FuncInfo = funcInfo;
            LineInfo = lineInfo;
            CoreRelos = coreRelos;
        }

        public IReadOnlyList<BtfExtSection<BtfFuncInfo>> FuncInfo { get; }
        public IReadOnlyList<BtfExtSection<BtfLineInfo>> LineInfo { get; }
        public IReadOnlyList<BtfExtSection<BtfCoreRelo>> CoreRelos { get; }
    }
}
