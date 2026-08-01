using System.Runtime.InteropServices;

namespace Nbpf.Core.Insns;

/// <summary>The eBPF registers.</summary>
public enum Reg : byte
{
    R0 = 0, R1, R2, R3, R4, R5, R6, R7, R8, R9,
    /// <summary>Frame pointer, read-only.</summary>
    R10 = 10,
}

/// <summary>
/// One 64-bit eBPF instruction, laid out exactly as struct bpf_insn:
/// opcode:8, dst_reg:4, src_reg:4, off:16, imm:32.
/// </summary>
[StructLayout(LayoutKind.Sequential, Size = 8)]
public readonly struct BpfInsn(byte opCode, Reg dst, Reg src, short offset, int imm)
{
    public readonly byte OpCode = opCode;
    public readonly byte Regs = (byte)((byte)dst | ((byte)src << 4));
    public readonly short Offset = offset;
    public readonly int Imm = imm;

    public Reg Dst => (Reg)(Regs & 0xF);
    public Reg Src => (Reg)(Regs >> 4);

    /// <summary>Copy with a different imm — how relocations are patched in.</summary>
    internal BpfInsn WithImm(int newImm) => new(OpCode, Dst, Src, Offset, newImm);

    /// <summary>Copy with a different src_reg and imm. src takes the raw 4-bit value
    /// because relocations store pseudo markers (not registers) in src_reg.</summary>
    internal BpfInsn WithSrcImm(byte src, int newImm) => new(OpCode, Dst, (Reg)src, Offset, newImm);
}
