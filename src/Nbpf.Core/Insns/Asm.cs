namespace Nbpf.Core.Insns;

/// <summary>
/// Hand-assembly helpers for Phase 0 and for tests. Opcode values from the
/// kernel's BPF instruction set specification (Documentation/bpf/standardization).
/// This is not meant to become a full assembler — real programs come from clang.
/// </summary>
public static class Asm
{
    // Opcode classes / modes, or'd together per instruction below.
    internal const byte BPF_LD = 0x00, BPF_LDX = 0x01, BPF_ST = 0x02, BPF_STX = 0x03,
                       BPF_ALU = 0x04, BPF_ALU64 = 0x07, BPF_JMP = 0x05;

    /// <summary>Mask isolating the class bits of an opcode (BPF_CLASS in the kernel).</summary>
    internal const byte ClassMask = 0x07;
    internal const byte BPF_K = 0x00, BPF_X = 0x08;
    internal const byte BPF_MOV = 0xb0, BPF_ADD = 0x00;
    internal const byte BPF_IMM = 0x00, BPF_MEM = 0x60, BPF_DW = 0x18, BPF_W = 0x00;
    internal const byte BPF_EXIT = 0x90, BPF_CALL = 0x80, BPF_JEQ = 0x10;

    /// <summary>src_reg value marking a ld_imm64 whose imm is a map fd.</summary>
    public const byte PseudoMapFd = 1;

    /// <summary>src_reg value marking a ld_imm64 that loads a pointer into a map's
    /// value: imm of the low slot is the map fd, imm of the high slot the offset.</summary>
    public const byte PseudoMapValue = 2;

    /// <summary>src_reg value marking a call insn as bpf-to-bpf (imm is a pc-relative
    /// instruction offset) rather than a helper call.</summary>
    public const byte PseudoCall = 1;

    // Full opcodes the relocation engine needs to recognize in clang output.
    internal const byte LdImm64OpCode = BPF_LD | BPF_IMM | BPF_DW;  // 0x18
    internal const byte CallOpCode = BPF_JMP | BPF_CALL;            // 0x85

    // Helper function ids from the kernel's uapi helper list.
    public const int HelperMapLookupElem = 1;
    public const int HelperRingbufOutput = 130;

    /// <summary>*(u64*)(dst + off) = imm (sign-extended to 64 bits).</summary>
    public static BpfInsn StoreDwordImm(Reg dst, short off, int imm)
        => new(BPF_ST | BPF_MEM | BPF_DW, dst, 0, off, imm);

    /// <summary>dst = imm (64-bit mov).</summary>
    public static BpfInsn MovImm(Reg dst, int imm)
        => new(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm);

    /// <summary>dst = src (64-bit mov).</summary>
    public static BpfInsn MovReg(Reg dst, Reg src)
        => new(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0);

    /// <summary>dst += imm.</summary>
    public static BpfInsn AddImm(Reg dst, int imm)
        => new(BPF_ALU64 | BPF_ADD | BPF_K, dst, 0, 0, imm);

    /// <summary>*(u32*)(dst + off) = imm.</summary>
    public static BpfInsn StoreWordImm(Reg dst, short off, int imm)
        => new(BPF_ST | BPF_MEM | BPF_W, dst, 0, off, imm);

    /// <summary>dst = *(u64*)(src + off).</summary>
    public static BpfInsn LoadDword(Reg dst, Reg src, short off)
        => new(BPF_LDX | BPF_MEM | BPF_DW, dst, src, off, 0);

    /// <summary>if dst == imm goto pc + off.</summary>
    public static BpfInsn JumpEqImm(Reg dst, int imm, short off)
        => new(BPF_JMP | BPF_JEQ | BPF_K, dst, 0, off, imm);

    /// <summary>Call a BPF helper by id (e.g. 1 = bpf_map_lookup_elem).</summary>
    public static BpfInsn CallHelper(int helperId)
        => new(BPF_JMP | BPF_CALL, 0, 0, 0, helperId);

    /// <summary>Return r0 to the kernel.</summary>
    public static BpfInsn Exit()
        => new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);

    /// <summary>
    /// dst = map (by fd). This is the two-slot ld_imm64 form; the kernel resolves
    /// the fd to a map pointer at load time because src_reg == BPF_PSEUDO_MAP_FD.
    /// </summary>
    public static (BpfInsn Lo, BpfInsn Hi) LoadMapFd(Reg dst, int fd)
        => (new BpfInsn(BPF_LD | BPF_IMM | BPF_DW, dst, (Reg)PseudoMapFd, 0, fd),
            new BpfInsn(0, 0, 0, 0, 0));
}
