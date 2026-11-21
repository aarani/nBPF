namespace Nbpf.Core.Native;

/// <summary>Base class for all bpf(2) failures. Carries the raw errno.</summary>
public class BpfException : Exception
{
    public int Errno { get; }

    public BpfException(string message, int errno) : base(message) => Errno = errno;
}

/// <summary>EPERM — missing capabilities.</summary>
public sealed class BpfPermissionException : BpfException
{
    public BpfPermissionException(string operation, int errno)
        : base($"{operation} failed with EPERM. The process needs CAP_BPF and CAP_PERFMON " +
               "(kernel 5.8+) or CAP_SYS_ADMIN. Try: sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep <binary>",
               errno) { }
}

/// <summary>EACCES on program load — the verifier rejected the program.</summary>
public sealed class BpfVerifierException : BpfException
{
    public string VerifierLog { get; }

    public BpfVerifierException(string verifierLog, int errno)
        : base($"The BPF verifier rejected the program.\n--- verifier log ---\n{verifierLog}", errno)
        => VerifierLog = verifierLog;
}

/// <summary>E2BIG — program exceeds the instruction limit.</summary>
public sealed class BpfProgramTooLargeException : BpfException
{
    public BpfProgramTooLargeException(int instructionCount, int errno)
        : base($"Program too large: {instructionCount} instructions " +
               "(limit is 4096 pre-5.2, 1M after).", errno) { }
}

/// <summary>
/// The kernel doesn't support a requested feature: ENOTSUPP/EOPNOTSUPP, or an EINVAL
/// that a feature probe traced to a missing map type, program type or helper
/// (DESIGN §4.5), in which case <see cref="MinimumKernel"/> says where it arrived.
/// </summary>
public sealed class BpfFeatureUnsupportedException : BpfException
{
    /// <summary>What is missing, e.g. "BPF_MAP_TYPE_RINGBUF".</summary>
    public string Feature { get; }

    /// <summary>The upstream release that introduced the feature ("5.8"), when known.
    /// A newer kernel can still lack it if its config leaves the feature out.</summary>
    public string? MinimumKernel { get; }

    public BpfFeatureUnsupportedException(string feature, int errno)
        : this(feature, minimumKernel: null, errno) { }

    public BpfFeatureUnsupportedException(string feature, string? minimumKernel, int errno)
        : base(minimumKernel is null
                   ? $"The running kernel does not support {feature}."
                   : $"The running kernel does not support {feature} (introduced in Linux " +
                     $"{minimumKernel}; older kernels, and kernels built without the option " +
                     "providing it, lack it).",
               errno)
    {
        Feature = feature;
        MinimumKernel = minimumKernel;
    }
}
