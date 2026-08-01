namespace Nbpf.Btf;

/// <summary>Parses a raw <c>.BTF</c> section into a type graph.</summary>
public interface IBtfReader
{
    IBtfTypeGraph Parse(byte[] btf);
}
