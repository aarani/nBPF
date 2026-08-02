namespace Nbpf.Btf;

/// <summary>Parses a raw <c>.BTF.ext</c> section into its func/line/CO-RE record groups.</summary>
public interface IBtfExtReader
{
    /// <summary>
    /// Parses <paramref name="btfExt"/>. The companion <c>.BTF</c> section from the same
    /// object is required because every string in <c>.BTF.ext</c> — section names, file
    /// names, source lines, CO-RE access specs — is an offset into <em>its</em> string table.
    /// </summary>
    IBtfExtInfo Parse(byte[] btfExt, byte[] btf);
}
