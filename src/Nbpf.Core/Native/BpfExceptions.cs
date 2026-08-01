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

/// <summary>ENOTSUPP/EOPNOTSUPP/EINVAL — the kernel doesn't support a requested feature.</summary>
public sealed class BpfFeatureUnsupportedException : BpfException
{
    public BpfFeatureUnsupportedException(string feature, int errno)
        : base($"The running kernel does not support {feature}.", errno) { }
}
