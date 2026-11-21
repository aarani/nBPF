using System.Collections.Concurrent;
using Nbpf.Core.Insns;
using Nbpf.Core.Native;

namespace Nbpf.Core;

/// <summary>
/// The running kernel's features, found by trying a tiny version of each thing and
/// checking the result, like libbpf's <c>libbpf_probe_*</c>. Each answer is cached
/// for the life of the process.
///
/// <para>A probe can't answer without the privileges a real load needs: EPERM is
/// thrown as <see cref="BpfPermissionException"/>, never read as "unsupported".</para>
/// </summary>
public sealed class KernelFeatures : IKernelFeatures
{
    public static KernelFeatures Running { get; } = new();

    private const int EPERM = 1;

    private readonly ConcurrentDictionary<BpfMapType, bool> _maps = new();
    private readonly ConcurrentDictionary<BpfProgType, bool> _programs = new();
    private readonly ConcurrentDictionary<(BpfProgType, int), bool> _helpers = new();

    private KernelFeatures() { }

    public bool HasMapType(BpfMapType type) => _maps.GetOrAdd(type, ProbeMapType);

    public bool HasProgramType(BpfProgType type)
    {
        RequireProbeable(type);
        return _programs.GetOrAdd(type, ProbeProgramType);
    }

    public bool HasHelper(BpfProgType programType, int helperId)
    {
        // The helper probe is a load of that program type too, so the same limit applies:
        // without an attach target the load fails before the helper is even looked at.
        RequireProbeable(programType);
        return _helpers.GetOrAdd((programType, helperId), key => ProbeHelper(key.Item1, key.Item2));
    }

    private static void RequireProbeable(BpfProgType type)
    {
        if (!CanProbe(type))
            throw new NotSupportedException(
                $"{KernelFeatureCatalog.Describe(type)} can't be probed generically: loading one " +
                "needs an attach target (expected_attach_type / attach_btf_id).");
    }

    /// <summary>Program types a bare <c>r0 = 0; exit</c> can be loaded as. The rest need
    /// an attach target to load at all, so a failed load says nothing about support.</summary>
    internal static bool CanProbe(BpfProgType type) => type != BpfProgType.Tracing;

    private static bool ProbeMapType(BpfMapType type)
    {
        RequireLinux();
        // Smallest valid shape per type; a wrong shape would read as "unsupported".
        var (key, value, entries, flags) = type switch
        {
            BpfMapType.RingBuf => (0u, 0u, (uint)Environment.SystemPageSize, 0u),
            BpfMapType.LpmTrie => (8u, 4u, 1u, 1u),   // u32 prefixlen + data; BPF_F_NO_PREALLOC required
            BpfMapType.StackTrace => (4u, 8u, 1u, 0u), // values are u64 instruction pointers
            _ => (4u, 4u, 1u, 0u),
        };
        return Succeeded(BpfSyscall.TryCreateMap(type, key, value, entries, flags, name: null),
                         $"probing {KernelFeatureCatalog.Describe(type)}");
    }

    private static bool ProbeProgramType(BpfProgType type)
    {
        RequireLinux();
        ReadOnlySpan<BpfInsn> insns = [Asm.MovImm(Reg.R0, 0), Asm.Exit()];
        return Succeeded(BpfSyscall.TryLoadProgram(type, insns, "GPL", name: null, out _, withLog: false),
                         $"probing {KernelFeatureCatalog.Describe(type)}");
    }

    /// <summary>
    /// Loads a program that only calls the helper. Its arguments are garbage, so the
    /// load usually fails anyway; what matters is <em>why</em>. The verifier checks the
    /// helper id before the arguments, and a missing helper is "invalid func" /
    /// "unknown func" — any other rejection means the helper is there.
    /// </summary>
    private bool ProbeHelper(BpfProgType programType, int helperId)
    {
        RequireLinux();
        if (!HasProgramType(programType))
            return false;

        ReadOnlySpan<BpfInsn> insns = [Asm.CallHelper(helperId), Asm.Exit()];
        int result = BpfSyscall.TryLoadProgram(programType, insns, "GPL", name: null, out string log, withLog: true);
        if (result >= 0)
        {
            BpfFdHandle.CloseFd(result);
            return true;
        }
        if (-result == EPERM)
            throw new BpfPermissionException($"probing helper #{helperId}", EPERM);
        return KernelFeatureCatalog.RejectedHelper(log) != helperId;
    }

    private static bool Succeeded(int result, string operation)
    {
        if (result >= 0)
        {
            BpfFdHandle.CloseFd(result);
            return true;
        }
        if (-result == EPERM)
            throw new BpfPermissionException(operation, EPERM);
        return false;
    }

    private static void RequireLinux()
    {
        // bpf(2) is a Linux syscall number; on other kernels the same number means
        // something else entirely, so never issue it there.
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Kernel feature probes require Linux.");
    }
}
