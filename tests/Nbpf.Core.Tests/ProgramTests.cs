using Nbpf.Core;
using Nbpf.Core.Insns;
using Nbpf.Core.Native;
using Xunit;

namespace Nbpf.Core.Tests;

public class ProgramTests
{
    [LinuxFact]
    public void Trivial_program_loads()
    {
        // r0 = 0; exit — the smallest verifier-accepted program.
        ReadOnlySpan<BpfInsn> insns =
        [
            Asm.MovImm(Reg.R0, 0),
            Asm.Exit(),
        ];

        using var prog = BpfProgram.Load(BpfProgType.SocketFilter, insns, name: "t_trivial");
        Assert.False(prog.Handle.IsInvalid);
    }

    [LinuxFact]
    public void Invalid_program_throws_with_verifier_log()
    {
        // Exit without initializing r0 — the verifier must reject this.
        ReadOnlySpan<BpfInsn> insns = [Asm.Exit()];
        BpfVerifierException? caught = null;
        try
        {
            BpfProgram.Load(BpfProgType.SocketFilter, insns);
        }
        catch (BpfVerifierException e)
        {
            caught = e;
        }

        Assert.NotNull(caught);
        Assert.Contains("R0", caught!.VerifierLog); // "R0 !read_ok" or similar
    }

    [LinuxFact]
    public void Program_can_read_a_map_through_ld_imm64()
    {
        // The Phase 0 milestone program: look up array[0], return it.
        //   r1 = map_fd (ld_imm64, pseudo-map-fd)
        //   r2 = fp; r2 += -4; *(u32*)(r2) = 0   // key = 0 on the stack
        //   call bpf_map_lookup_elem              // helper 1
        //   if r0 == 0 goto +2
        //   r0 = *(u64*)(r0 + 0)
        //   exit
        // miss: r0 = 0; exit
        using var map = Maps.BpfMap<uint, ulong>.Create(BpfMapType.Array, maxEntries: 1, name: "t_lookup");
        var (lo, hi) = Asm.LoadMapFd(Reg.R1, map.Handle.Fd);

        ReadOnlySpan<BpfInsn> insns =
        [
            lo, hi,
            Asm.MovReg(Reg.R2, Reg.R10),
            Asm.AddImm(Reg.R2, -4),
            Asm.StoreWordImm(Reg.R2, 0, 0),
            Asm.CallHelper(1),            // bpf_map_lookup_elem(map, &key)
            Asm.JumpEqImm(Reg.R0, 0, 2),  // null check — verifier requires it
            Asm.LoadDword(Reg.R0, Reg.R0, 0),
            Asm.Exit(),
            Asm.MovImm(Reg.R0, 0),
            Asm.Exit(),
        ];

        using var prog = BpfProgram.Load(BpfProgType.SocketFilter, insns, name: "t_map_read");
        Assert.False(prog.Handle.IsInvalid);
    }
}
