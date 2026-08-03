using System.Runtime.InteropServices;
using Nbpf.Btf;
using Nbpf.Core.Insns;
using Nbpf.Elf;

namespace Nbpf.Core.ObjectFile;

/// <summary>
/// Applies resolved CO-RE relocations to instructions (DESIGN §4.4 step 4). Pure like
/// <see cref="BpfLinker"/>: no syscalls, testable anywhere. Runs <em>before</em> the
/// linker, on the program sections themselves — CO-RE record offsets are
/// section-relative, and patching first means subprograms are already correct when
/// <see cref="BpfLinker"/> copies them out of <c>.text</c> (libbpf's order too).
/// </summary>
internal static class CoreRelocator
{
    /// <summary>The imm of the invalid call a poisoned instruction becomes; the verifier
    /// reports it as "invalid func unknown#195896080", but only on paths it cannot prune.</summary>
    internal const int PoisonCallImm = 0xbad2310;

    /// <summary>
    /// Resolves every CO-RE relocation in <paramref name="extInfo"/> against
    /// <paramref name="targetBtf"/> and patches the ELF program sections' instruction
    /// bytes in place (each record's <see cref="BtfCoreRelo.InsnByteOffset"/> is a byte
    /// offset into the section named by its group).
    /// </summary>
    internal static void Apply(
        IElfObject elf, IBtfTypeGraph localBtf, IBtfExtInfo extInfo,
        IBtfTypeGraph targetBtf, ICoreReloResolver resolver)
    {
        if (!BitConverter.IsLittleEndian)
            throw new NotSupportedException(
                "CO-RE patching assumes a little-endian host to reinterpret instruction bytes.");

        foreach (var group in extInfo.CoreRelos)
        {
            if (elf.FindSection(group.SectionName) is not { } section)
                throw new InvalidDataException(
                    $".BTF.ext carries CO-RE relocations for section '{group.SectionName}', " +
                    "which is not in the object.");

            // Patching the section's own buffer is deliberate: BpfLinker slices
            // programs and subprograms out of these arrays afterwards.
            var insns = MemoryMarshal.Cast<byte, BpfInsn>(section.Data.AsSpan());
            foreach (var relo in group.Records)
            {
                if (relo.InsnByteOffset % 8 != 0 || relo.InsnByteOffset / 8 >= (uint)insns.Length)
                    throw new InvalidDataException(
                        $"CO-RE relocation at byte offset {relo.InsnByteOffset} of " +
                        $"'{group.SectionName}' does not land on an instruction in the section.");

                Patch(insns, (int)(relo.InsnByteOffset / 8),
                    resolver.Resolve(relo, localBtf, targetBtf));
            }
        }
    }

    /// <summary>
    /// Patches the single instruction at <paramref name="index"/> with a resolved
    /// relocation. A poisoned result replaces the instruction with the invalid call.
    /// Otherwise the patched field follows from the instruction class: the 16-bit
    /// offset of a memory access (LDX/ST/STX), the imm of an ALU/ALU64 op, or the
    /// 64-bit imm spread across a two-slot ld_imm64. Anything else — or a value that
    /// does not fit the field, or a validated mismatch against
    /// <see cref="CoreReloResult.OldValue"/> — is an <see cref="InvalidDataException"/>.
    /// </summary>
    internal static void Patch(Span<BpfInsn> insns, int index, in CoreReloResult result)
    {
        if (index < 0 || index >= insns.Length)
            throw new ArgumentOutOfRangeException(nameof(index), index, "Instruction index out of range");

        if (result.Poison)
        {
            insns[index] = Asm.CallHelper(PoisonCallImm);
            return;
        }

        var insn = insns[index];
        var opCode = insn.OpCode;

        switch (opCode & Asm.ClassMask)
        {
            case Asm.BPF_LDX:
            case Asm.BPF_ST:
            case Asm.BPF_STX:
                if (result.Validate && insn.Offset != unchecked((short)result.OldValue))
                    throw new InvalidDataException($"Expected baked-in offset {result.OldValue} at index {index}, but the instruction carries {insn.Offset}");

                // The offset field is a *signed* 16-bit — anything past short.MaxValue
                // would come back negative.
                if (result.NewValue > (ulong)short.MaxValue)
                    throw new InvalidDataException($"Relocated offset {result.NewValue} does not fit in a signed 16-bit offset");

                insns[index] = insn.WithOffset((short)result.NewValue);
                break;
            case Asm.BPF_ALU:
            case Asm.BPF_ALU64:
                if (result.Validate && insn.Imm != unchecked((int)result.OldValue))
                    throw new InvalidDataException($"Expected baked-in immediate {result.OldValue} at index {index}, but the instruction carries {insn.Imm}");

                if (result.NewValue > uint.MaxValue)
                    throw new InvalidDataException($"Relocated immediate {result.NewValue} does not fit in 32 bits");

                insns[index] = insn.WithImm(unchecked((int)result.NewValue));
                break;
            case Asm.BPF_LD when opCode == Asm.LdImm64OpCode:
                if (index + 1 >= insns.Length)
                    throw new InvalidDataException($"Instruction at index {index} is a two-slot ld_imm64, but the next slot is missing");

                var nextSlot = insns[index + 1];
                var currentValue = (uint)insn.Imm | ((ulong)(uint)nextSlot.Imm << 32);

                if (result.Validate && currentValue != result.OldValue)
                    throw new InvalidDataException($"Expected baked-in value {result.OldValue} at index {index}, but the ld_imm64 carries {currentValue}");

                insns[index] = insn.WithImm(unchecked((int)result.NewValue));
                insns[index + 1] = nextSlot.WithImm(unchecked((int)(result.NewValue >> 32)));
                break;
            default:
                throw new InvalidDataException($"Instruction at index {index} is not a relocatable class (LDX/ST/STX/ALU/ALU64/LD_IMM64): {opCode:X2}");
        }
    }
}
