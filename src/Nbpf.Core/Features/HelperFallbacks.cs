using Nbpf.Core.Insns;
using Nbpf.Core.Native;
using static Nbpf.Core.KernelFeatureCatalog;

namespace Nbpf.Core;

/// <summary>
/// Rewrites helper calls a kernel lacks into older equivalents, before the program
/// is loaded (DESIGN §4.5: every probe needs a fallback or a clear error).
///
/// <para>The one family that needs this today is the 5.5 split of bpf_probe_read into
/// _kernel/_user variants. Programs written for current kernels call the new ones;
/// on 5.4 the verifier rejects them. Where the old, combined bpf_probe_read(_str) is
/// offered — every architecture whose user and kernel address ranges don't overlap
/// (CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE, which includes x86-64 and arm64) —
/// it does the same read, so the call is switched over. The signatures are identical,
/// so only the helper id changes. This matches libbpf's own sanitization of these
/// calls.</para>
/// </summary>
internal static class HelperFallbacks
{
    private static readonly Dictionary<int, int> ProbeReadFallbacks = new()
    {
        [ProbeReadKernel] = ProbeRead,
        [ProbeReadUser] = ProbeRead,
        [ProbeReadKernelStr] = ProbeReadStr,
        [ProbeReadUserStr] = ProbeReadStr,
    };

    /// <summary>
    /// Rewrites, in place, every helper call in <paramref name="insns"/> that
    /// <paramref name="features"/> says <paramref name="type"/> programs can't make but
    /// whose fallback they can. Throws when neither is available, since such a program
    /// can't load on this kernel at all. Probes only for helpers the program calls.
    /// </summary>
    internal static void Apply(BpfProgType type, Span<BpfInsn> insns, IKernelFeatures features)
    {
        // Program types that can't be probed without an attach target (fentry/fexit
        // and friends) all arrived in 5.5 or later, together with or after the probe_read
        // split, so there is nothing to fall back from.
        if (!KernelFeatures.CanProbe(type))
            return;

        Dictionary<int, int>? decided = null; // helper -> id to call instead (maybe itself)
        for (int i = 0; i < insns.Length; i++)
        {
            ref readonly var insn = ref insns[i];
            // A plain helper call: src_reg 0. Pseudo calls (subprograms, kfuncs) reuse
            // the opcode with a nonzero src_reg, and their imm is not a helper id.
            if (insn.OpCode != Asm.CallOpCode || insn.Src != 0 ||
                !ProbeReadFallbacks.TryGetValue(insn.Imm, out int fallback))
                continue;

            decided ??= [];
            if (!decided.TryGetValue(insn.Imm, out int replacement))
            {
                replacement = Decide(type, insn.Imm, fallback, features);
                decided[insn.Imm] = replacement;
            }
            if (replacement != insn.Imm)
                insns[i] = insn.WithImm(replacement);
        }
    }

    private static int Decide(BpfProgType type, int helper, int fallback, IKernelFeatures features)
    {
        if (features.HasHelper(type, helper))
            return helper;
        if (features.HasHelper(type, fallback))
            return fallback;

        const int EINVAL = 22; // what the kernel would have answered on load
        throw new BpfFeatureUnsupportedException(
            $"{DescribeHelper(helper)} in {Describe(type)} programs, nor its pre-{HelperSince(helper)} " +
            $"fallback {DescribeHelper(fallback)}",
            HelperSince(helper), EINVAL);
    }
}
