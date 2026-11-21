using Nbpf.Core.Native;

namespace Nbpf.Core;

/// <summary>
/// Before 5.11, the kernel charges every BPF map and program against the process's
/// RLIMIT_MEMLOCK. That limit defaults to 64 KiB, and later to 8 MiB, which a real
/// program's maps outgrow at once (EPERM on BPF_MAP_CREATE). From 5.11 the memory is
/// charged to the memory cgroup instead, and the limit doesn't matter.
///
/// <para>So, like libbpf, the first map or program this library creates raises the
/// limit to unlimited, but only on a kernel that still charges against it. That's told
/// apart the same way libbpf does: bpf_ktime_get_coarse_ns arrived in the same release
/// as memcg accounting, so a kernel offering it no longer needs the bump. The limit is
/// process-wide, so this is a process-wide side effect. Set <see cref="AutoRaise"/> to
/// false before creating anything to manage the limit yourself.</para>
/// </summary>
public static class MemlockLimit
{
    /// <summary>Whether the library raises RLIMIT_MEMLOCK where the kernel needs it.
    /// Read once, when the first map or program is created.</summary>
    public static bool AutoRaise { get; set; } = true;

    internal enum Outcome
    {
        /// <summary>The kernel charges the memory cgroup (5.11+); the limit is irrelevant.</summary>
        NotNeeded,
        /// <summary>The limit is now (or already was) unlimited.</summary>
        Raised,
        /// <summary>The kernel charges the limit, and it couldn't be raised to unlimited
        /// (no CAP_SYS_RESOURCE, and a finite hard limit).</summary>
        RaiseFailed,
        /// <summary><see cref="AutoRaise"/> was off.</summary>
        Disabled,
    }

    /// <summary>bpf_ktime_get_coarse_ns, 5.11 like memcg-based accounting.</summary>
    private const int KtimeGetCoarseNs = 160;

    private static readonly object Gate = new();
    private static Outcome? _outcome;

    /// <summary>What the first creation decided, or null before it.</summary>
    internal static Outcome? Result
    {
        get { lock (Gate) return _outcome; }
    }

    /// <summary>Called before every map and program creation; decides once.</summary>
    internal static void EnsureRaised()
    {
        lock (Gate)
            _outcome ??= Decide();
    }

    private static Outcome Decide()
    {
        if (!AutoRaise)
            return Outcome.Disabled;
        if (!OperatingSystem.IsLinux())
            return Outcome.NotNeeded;

        try
        {
            if (KernelFeatures.Running.HasHelper(BpfProgType.CgroupSkb, KtimeGetCoarseNs))
                return Outcome.NotNeeded;
        }
        catch (BpfPermissionException)
        {
            // An EPERM here can be the memlock limit itself, on a kernel where it is
            // tiny enough to refuse even the probe. Raising it is harmless either way.
        }
        return TryRaise() ? Outcome.Raised : Outcome.RaiseFailed;
    }

    private static bool TryRaise()
    {
        if (Libc.getrlimit(Libc.RLIMIT_MEMLOCK, out var current) != 0)
            return false;
        if (current.Current == Libc.RLIM_INFINITY)
            return true;

        var unlimited = new Libc.RLimit { Current = Libc.RLIM_INFINITY, Maximum = Libc.RLIM_INFINITY };
        if (Libc.setrlimit(Libc.RLIMIT_MEMLOCK, in unlimited) == 0)
            return true;

        // Without CAP_SYS_RESOURCE the hard limit can't be raised, but the soft limit
        // can still go up to it, which may be enough.
        var toHard = new Libc.RLimit { Current = current.Maximum, Maximum = current.Maximum };
        Libc.setrlimit(Libc.RLIMIT_MEMLOCK, in toHard);
        return current.Maximum == Libc.RLIM_INFINITY;
    }

    /// <summary>For an EPERM: the extra explanation, when the memlock limit is the
    /// likely cause rather than missing capabilities.</summary>
    internal static string? EpermHint()
    {
        if (Result != Outcome.RaiseFailed)
            return null;
        Libc.getrlimit(Libc.RLIMIT_MEMLOCK, out var limit);
        string current = limit.Current == Libc.RLIM_INFINITY ? "unlimited" : $"{limit.Current / 1024} KiB";
        return "This kernel predates 5.11, so BPF maps and programs are charged against " +
               $"RLIMIT_MEMLOCK, which is {current} and couldn't be raised. Raise it before " +
               "starting the process (ulimit -l unlimited, or LimitMEMLOCK=infinity for a " +
               "systemd service), or grant CAP_SYS_RESOURCE.";
    }
}
