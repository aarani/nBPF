using Xunit;

namespace Ebpf.Elf.Tests;

/// <summary>
/// A malformed object must produce <see cref="ElfFormatException"/> and nothing else. Leaking an
/// IndexOutOfRangeException or an OverflowException from a byte parser means some offset reached
/// an array without being bounds-checked first.
/// </summary>
public class ElfRobustnessTests
{
    public static TheoryData<int> TruncationLengths()
    {
        var data = new TheoryData<int>();
        var length = ElfFixture.Bytes.Length;

        // Dense over the headers, then sparse across the body.
        for (var i = 0; i < 200; i++)
            data.Add(i);

        for (var i = 200; i < length; i += 97)
            data.Add(i);

        return data;
    }

    [Theory]
    [MemberData(nameof(TruncationLengths))]
    public void Truncation_at_any_length_fails_cleanly(int length)
    {
        var truncated = new byte[length];
        Array.Copy(ElfFixture.Bytes, truncated, length);

        try
        {
            ElfReader.Read(truncated);
        }
        catch (ElfFormatException)
        {
            // The only acceptable failure.
        }
    }

    [Theory]
    [InlineData(0x28)] // e_shoff
    [InlineData(0x3A)] // e_shentsize
    [InlineData(0x3C)] // e_shnum
    [InlineData(0x3E)] // e_shstrndx
    public void Corrupting_a_header_field_fails_cleanly(int offset)
    {
        for (var value = 1; value <= 0xFF; value += 0x11)
        {
            var corrupt = (byte[])ElfFixture.Bytes.Clone();
            corrupt[offset] = (byte)value;
            corrupt[offset + 1] = (byte)value;

            try
            {
                ElfReader.Read(corrupt);
            }
            catch (ElfFormatException)
            {
                // Expected for most values.
            }
        }
    }

    [Fact]
    public void Corrupting_a_section_header_fails_cleanly()
    {
        var bytes = ElfFixture.Bytes;
        var shoff = BitConverter.ToInt64(bytes, 0x28);
        var shnum = BitConverter.ToUInt16(bytes, 0x3C);

        // Walk every field of every section header, flipping it to something implausible.
        for (var section = 0; section < shnum; section++)
        {
            for (var field = 0; field < 64; field += 4)
            {
                var corrupt = (byte[])bytes.Clone();
                var at = shoff + (section * 64) + field;

                for (var i = 0; i < 4; i++)
                    corrupt[at + i] = 0xFE;

                try
                {
                    ElfReader.Read(corrupt);
                }
                catch (ElfFormatException)
                {
                    // Expected for most mutations.
                }
            }
        }
    }
}
