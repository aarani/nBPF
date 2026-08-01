namespace Nbpf.Btf;

/// <summary>Thrown when a BTF blob is malformed, truncated, or uses a construct this parser rejects.</summary>
public sealed class BtfFormatException : Exception
{
    public BtfFormatException(string message) : base(message) { }

    public BtfFormatException(string message, Exception innerException) : base(message, innerException) { }
}
