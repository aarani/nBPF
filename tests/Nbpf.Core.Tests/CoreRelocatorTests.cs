using Nbpf.Btf;
using Nbpf.Core.Insns;
using Nbpf.Core.ObjectFile;
using Xunit;

namespace Nbpf.Core.Tests;

/// <summary>
/// The per-instruction CO-RE patch rules (libbpf's bpf_core_patch_insn): which field of
/// which instruction class a resolved value lands in, validation against the baked-in
/// value, and poisoning. Pure — no kernel needed.
/// </summary>
public class CoreRelocatorTests
{
    [Fact]
    public void Poison_replaces_the_instruction_with_an_invalid_call()
    {
        var insns = new[] { Asm.LoadDword(Reg.R1, Reg.R2, 4), Asm.Exit() };

        CoreRelocator.Patch(insns, 0, new CoreReloResult(4, 0, Poison: true, Validate: true));

        Assert.Equal(0x85, insns[0].OpCode);           // BPF_JMP | BPF_CALL
        Assert.Equal(195896080, insns[0].Imm);         // 0xbad2310 — "invalid func"
        Assert.Equal(Reg.R0, insns[0].Dst);
        Assert.Equal(Reg.R0, insns[0].Src);
        Assert.Equal(0, insns[0].Offset);
        Assert.Equal(Asm.Exit(), insns[1]);            // neighbors untouched
    }

    [Fact]
    public void A_memory_access_is_patched_in_its_offset()
    {
        var insns = new[] { Asm.LoadDword(Reg.R1, Reg.R2, 4), Asm.Exit() };

        CoreRelocator.Patch(insns, 0, new CoreReloResult(4, 16, Poison: false, Validate: true));

        Assert.Equal(16, insns[0].Offset);
        Assert.Equal(Asm.LoadDword(Reg.R1, Reg.R2, 16), insns[0]);
        Assert.Equal(Asm.Exit(), insns[1]);
    }

    [Fact]
    public void A_store_is_patched_in_its_offset_too()
    {
        var insns = new[] { Asm.StoreWordImm(Reg.R1, 8, 42) };

        CoreRelocator.Patch(insns, 0, new CoreReloResult(8, 24, Poison: false, Validate: true));

        Assert.Equal(24, insns[0].Offset);
        Assert.Equal(42, insns[0].Imm); // the stored value is not the relocated field
    }

    [Fact]
    public void An_alu_op_is_patched_in_its_immediate()
    {
        var insns = new[] { Asm.AddImm(Reg.R3, 4) };

        CoreRelocator.Patch(insns, 0, new CoreReloResult(4, 16, Poison: false, Validate: true));

        Assert.Equal(16, insns[0].Imm);
        Assert.Equal(0, insns[0].Offset);
    }

    [Fact]
    public void An_exists_probe_patches_a_mov_from_one_to_zero()
    {
        var insns = new[] { Asm.MovImm(Reg.R0, 1) };

        CoreRelocator.Patch(insns, 0, new CoreReloResult(1, 0, Poison: false, Validate: true));

        Assert.Equal(0, insns[0].Imm);
    }

    [Fact]
    public void A_ld_imm64_is_patched_across_both_slots()
    {
        // ld_imm64 r1, 4 — low slot carries the low word, the zero pseudo-slot the high.
        var insns = new[]
        {
            new BpfInsn(0x18, Reg.R1, 0, 0, 4),
            new BpfInsn(0, 0, 0, 0, 0),
        };

        CoreRelocator.Patch(insns, 0,
            new CoreReloResult(4, 0x2_0000_0008, Poison: false, Validate: true));

        Assert.Equal(8, insns[0].Imm);
        Assert.Equal(2, insns[1].Imm);
    }

    [Fact]
    public void A_validated_mismatch_with_the_baked_in_value_throws()
    {
        var insns = new[] { Asm.LoadDword(Reg.R1, Reg.R2, 6) };

        Assert.Throws<InvalidDataException>(() =>
            CoreRelocator.Patch(insns, 0, new CoreReloResult(4, 16, Poison: false, Validate: true)));
    }

    [Fact]
    public void An_unvalidated_mismatch_is_patched_anyway()
    {
        // Bitfield results (Validate: false) legitimately differ from the baked value.
        var insns = new[] { Asm.LoadDword(Reg.R1, Reg.R2, 6) };

        CoreRelocator.Patch(insns, 0, new CoreReloResult(4, 16, Poison: false, Validate: false));

        Assert.Equal(16, insns[0].Offset);
    }

    [Fact]
    public void An_offset_that_does_not_fit_sixteen_bits_throws()
    {
        var insns = new[] { Asm.LoadDword(Reg.R1, Reg.R2, 4) };

        Assert.Throws<InvalidDataException>(() =>
            CoreRelocator.Patch(insns, 0, new CoreReloResult(4, 40_000, Poison: false, Validate: true)));
    }

    [Fact]
    public void An_immediate_that_does_not_fit_thirty_two_bits_throws()
    {
        var insns = new[] { Asm.AddImm(Reg.R3, 4) };

        Assert.Throws<InvalidDataException>(() =>
            CoreRelocator.Patch(insns, 0, new CoreReloResult(4, 5_000_000_000, Poison: false, Validate: true)));
    }

    [Fact]
    public void A_ld_imm64_missing_its_second_slot_throws()
    {
        var insns = new[] { new BpfInsn(0x18, Reg.R1, 0, 0, 4) };

        Assert.Throws<InvalidDataException>(() =>
            CoreRelocator.Patch(insns, 0, new CoreReloResult(4, 8, Poison: false, Validate: true)));
    }

    [Fact]
    public void An_instruction_no_relocation_can_target_throws()
    {
        var insns = new[] { Asm.Exit() };

        Assert.Throws<InvalidDataException>(() =>
            CoreRelocator.Patch(insns, 0, new CoreReloResult(0, 1, Poison: false, Validate: true)));
    }
}
