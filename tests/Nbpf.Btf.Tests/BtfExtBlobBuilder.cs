using System.Buffers.Binary;

namespace Nbpf.Btf.Tests;

/// <summary>
/// Builds well-formed (or deliberately malformed) .BTF.ext blobs in memory, the companion
/// of <see cref="BtfBlobBuilder"/>. Strings (section names, file names, source lines,
/// access specs) are not stored in .BTF.ext itself — they are added to the companion
/// builder's string table, so tests must feed the parser both blobs from the same pair.
/// </summary>
internal sealed class BtfExtBlobBuilder
{
    private readonly BtfBlobBuilder _btf;
    private readonly List<(uint NameOff, List<uint[]> Records)> _funcSections = [];
    private readonly List<(uint NameOff, List<uint[]> Records)> _lineSections = [];
    private readonly List<(uint NameOff, List<uint[]> Records)> _coreSections = [];

    internal BtfExtBlobBuilder(BtfBlobBuilder companionBtf)
    {
        _btf = companionBtf;
    }

    /// <summary>Must match the companion builder — a real object's sections share a producer.</summary>
    internal bool BigEndian { get; set; }

    /// <summary>Overrides the version byte; used to test rejection of future formats.</summary>
    internal byte Version { get; set; } = 1;

    /// <summary>Emit the original 24-byte header, from before the CO-RE block existed.</summary>
    internal bool LegacyHeader { get; set; }

    /// <summary>Overrides the declared func_info record size (natural size 8).</summary>
    internal uint? FuncRecordSize { get; set; }

    /// <summary>Overrides the declared line_info record size (natural size 16).</summary>
    internal uint? LineRecordSize { get; set; }

    /// <summary>Overrides the declared core_relo record size (natural size 16).</summary>
    internal uint? CoreRecordSize { get; set; }

    internal void AddFuncSection(string name, params (uint InsnByteOff, uint TypeId)[] records)
    {
        var rows = records.Select(r => new[] { r.InsnByteOff, r.TypeId }).ToList();
        _funcSections.Add((_btf.AddString(name), rows));
    }

    internal void AddLineSection(
        string name, params (uint InsnByteOff, string File, string Source, uint Line, uint Col)[] records)
    {
        var rows = records
            .Select(r => new[]
            {
                r.InsnByteOff,
                _btf.AddString(r.File),
                _btf.AddString(r.Source),
                (r.Line << 10) | (r.Col & 0x3FFu),
            })
            .ToList();
        _lineSections.Add((_btf.AddString(name), rows));
    }

    internal void AddCoreReloSection(
        string name, params (uint InsnByteOff, uint TypeId, string Access, uint Kind)[] records)
    {
        var rows = records
            .Select(r => new[] { r.InsnByteOff, r.TypeId, _btf.AddString(r.Access), r.Kind })
            .ToList();
        _coreSections.Add((_btf.AddString(name), rows));
    }

    /// <summary>
    /// Assembles the blob. <paramref name="truncateBytes"/> drops bytes from the end, so a
    /// test can declare more records than the blob actually holds.
    /// </summary>
    internal byte[] Build(int truncateBytes = 0)
    {
        var func = BuildBlock(_funcSections, FuncRecordSize ?? 8, naturalRecordSize: 8);
        var line = BuildBlock(_lineSections, LineRecordSize ?? 16, naturalRecordSize: 16);
        var core = BuildBlock(_coreSections, CoreRecordSize ?? 16, naturalRecordSize: 16);

        if (LegacyHeader && core.Length > 0)
            throw new InvalidOperationException("a 24-byte header has nowhere to describe CO-RE sections");

        var output = new MemoryStream();
        Write16(output, 0xEB9F);
        output.WriteByte(Version);
        output.WriteByte(0); // flags
        Write32(output, LegacyHeader ? 24u : 32u); // hdr_len

        Write32(output, 0); // func_info_off
        Write32(output, (uint)func.Length);
        Write32(output, (uint)func.Length); // line_info_off, immediately after
        Write32(output, (uint)line.Length);
        if (!LegacyHeader)
        {
            Write32(output, (uint)(func.Length + line.Length)); // core_relo_off
            Write32(output, (uint)core.Length);
        }

        output.Write(func, 0, func.Length);
        output.Write(line, 0, line.Length);
        output.Write(core, 0, core.Length);

        var blob = output.ToArray();
        return truncateBytes == 0 ? blob : blob[..^truncateBytes];
    }

    private byte[] BuildBlock(
        List<(uint NameOff, List<uint[]> Records)> sections, uint declaredRecordSize, int naturalRecordSize)
    {
        if (sections.Count == 0)
            return [];

        var block = new MemoryStream();
        Write32(block, declaredRecordSize);

        // Records are written padded out to the declared size when it is larger than the
        // fields we have — that is exactly what a newer producer's blob looks like. A
        // declared size *smaller* than natural is only used to test rejection, which the
        // parser does before reading any record, so the record bytes do not matter then.
        var padWords = declaredRecordSize > (uint)naturalRecordSize
            ? (int)(declaredRecordSize - naturalRecordSize) / 4
            : 0;

        foreach (var (nameOff, records) in sections)
        {
            Write32(block, nameOff);
            Write32(block, (uint)records.Count);
            foreach (var record in records)
            {
                foreach (var word in record)
                    Write32(block, word);
                for (var i = 0; i < padWords; i++)
                    Write32(block, 0xA5A5A5A5); // junk the parser must skip, not zeros
            }
        }

        return block.ToArray();
    }

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
}
