using System.Runtime.InteropServices;
using System.Text;
using Nbpf.Core.Insns;
using Nbpf.Core.ObjectFile;

namespace Nbpf.Core.Native;

/// <summary>
/// Direct bpf(2) syscall interface. No libbpf, no native dependencies.
/// </summary>
internal static unsafe partial class BpfSyscall
{
    private const int EPERM = 1, E2BIG = 7, EACCES = 13, ENOENT = 2, EEXIST = 17,
                      EINVAL = 22, EOPNOTSUPP = 95, ENOTSUPP = 524;

    // __NR_bpf differs per architecture; there is no portable constant.
    private static readonly long BpfNr = RuntimeInformation.ProcessArchitecture switch
    {
        Architecture.X64 => 321,
        Architecture.Arm64 => 280,
        Architecture.Arm => 386,
        _ => -1,
    };

    [LibraryImport("libc", EntryPoint = "syscall", SetLastError = true)]
    private static partial long Syscall(long number, long cmd, void* attr, uint size);

    /// <summary>
    /// Issues one bpf(2) command. Returns the non-negative result (an fd for
    /// create/load commands, 0 otherwise), or the negated errno on failure.
    /// </summary>
    internal static int Invoke<TAttr>(BpfCmd cmd, ref TAttr attr) where TAttr : unmanaged
    {
        if (BpfNr < 0)
            throw new PlatformNotSupportedException(
                $"No __NR_bpf known for {RuntimeInformation.ProcessArchitecture}.");

        fixed (TAttr* p = &attr)
        {
            long result = Syscall(BpfNr, (long)cmd, p, (uint)sizeof(TAttr));
            return result >= 0 ? (int)result : -Marshal.GetLastPInvokeError();
        }
    }

    internal static BpfMapHandle CreateMap(
        BpfMapType type, uint keySize, uint valueSize, uint maxEntries,
        uint flags = 0, string? name = null)
    {
        MemlockLimit.EnsureRaised();
        int result = TryCreateMap(type, keySize, valueSize, maxEntries, flags, name);
        if (result < 0)
        {
            int errno = -result;
            // EINVAL is also what a kernel says about a map type it has never heard
            // of; ask the probe so that case gets a "too old" error, not a bare errno.
            if (errno == EINVAL && !KernelFeatures.Running.HasMapType(type))
                throw KernelFeatureCatalog.Unsupported(type, errno);
            throw TranslateError(errno, $"BPF_MAP_CREATE ({type})");
        }

        var handle = new BpfMapHandle();
        handle.SetFd(result);
        return handle;
    }

    /// <summary>BPF_MAP_CREATE without any error interpretation: the new fd, or the
    /// negated errno. The feature probes build on this, so it must never probe.</summary>
    internal static int TryCreateMap(
        BpfMapType type, uint keySize, uint valueSize, uint maxEntries, uint flags, string? name)
    {
        var attr = new MapCreateAttr
        {
            MapType = (uint)type,
            KeySize = keySize,
            ValueSize = valueSize,
            MaxEntries = maxEntries,
            MapFlags = flags,
        };
        CopyName(name, attr.MapName);
        return Invoke(BpfCmd.MapCreate, ref attr);
    }

    internal static bool LookupElem(BpfMapHandle map, void* key, void* value)
    {
        var attr = new MapElemAttr { MapFd = (uint)map.Fd, Key = (ulong)key, Value = (ulong)value };
        int result = Invoke(BpfCmd.MapLookupElem, ref attr);
        if (result == -ENOENT) return false;
        if (result < 0) throw TranslateError(-result, "BPF_MAP_LOOKUP_ELEM");
        return true;
    }

    internal static void UpdateElem(BpfMapHandle map, void* key, void* value, MapUpdateFlags flags)
    {
        var attr = new MapElemAttr
        {
            MapFd = (uint)map.Fd, Key = (ulong)key, Value = (ulong)value, Flags = (ulong)flags,
        };
        int result = Invoke(BpfCmd.MapUpdateElem, ref attr);
        if (result < 0) throw TranslateError(-result, "BPF_MAP_UPDATE_ELEM");
    }

    /// <summary>UPDATE_ELEM with caller-supplied raw key/value bytes, for maps whose
    /// key and value sizes are only known at runtime (e.g. global-data array maps).</summary>
    internal static void UpdateElem(
        BpfMapHandle map, ReadOnlySpan<byte> key, ReadOnlySpan<byte> value, MapUpdateFlags flags)
    {
        fixed (byte* k = key)
        fixed (byte* v = value)
        {
            UpdateElem(map, k, v, flags);
        }
    }

    /// <summary>BPF_MAP_FREEZE: no further writes from userspace, ever. Combined with
    /// BPF_F_RDONLY_PROG this makes the contents constants the verifier can fold.</summary>
    internal static void FreezeMap(BpfMapHandle map)
    {
        var attr = new MapFreezeAttr { MapFd = (uint)map.Fd };
        int result = Invoke(BpfCmd.MapFreeze, ref attr);
        if (result < 0) throw TranslateError(-result, "BPF_MAP_FREEZE");
    }

    internal static bool DeleteElem(BpfMapHandle map, void* key)
    {
        var attr = new MapElemAttr { MapFd = (uint)map.Fd, Key = (ulong)key };
        int result = Invoke(BpfCmd.MapDeleteElem, ref attr);
        if (result == -ENOENT) return false;
        if (result < 0) throw TranslateError(-result, "BPF_MAP_DELETE_ELEM");
        return true;
    }

    /// <summary>GET_NEXT_KEY. Pass null prevKey to get the first key.</summary>
    internal static bool GetNextKey(BpfMapHandle map, void* prevKey, void* nextKey)
    {
        var attr = new MapElemAttr { MapFd = (uint)map.Fd, Key = (ulong)prevKey, Value = (ulong)nextKey };
        int result = Invoke(BpfCmd.MapGetNextKey, ref attr);
        if (result == -ENOENT) return false; // no more keys
        if (result < 0) throw TranslateError(-result, "BPF_MAP_GET_NEXT_KEY");
        return true;
    }

    internal static BpfProgHandle LoadProgram(
        BpfProgType type, ReadOnlySpan<BpfInsn> insns, string license = "GPL", string? name = null)
    {
        MemlockLimit.EnsureRaised();
        int result = TryLoadProgram(type, insns, license, name, out _, withLog: false);
        if (result < 0 && -result is EACCES or EINVAL)
        {
            // Retry with the verifier log enabled so the exception can carry it.
            result = TryLoadProgram(type, insns, license, name, out string log, withLog: true);
            if (result < 0 && log.Length > 0)
            {
                // A helper this kernel lacks (or doesn't offer this program type) is a
                // feature gap, not a program bug: say which, and since when.
                if (KernelFeatureCatalog.RejectedHelper(log) is { } helper &&
                    helper != CoreRelocator.PoisonCallImm &&
                    KernelFeatures.CanProbe(type) &&
                    !KernelFeatures.Running.HasHelper(type, helper))
                    throw KernelFeatureCatalog.Unsupported(type, helper, -result);
                throw new BpfVerifierException(log, -result);
            }
        }
        if (result >= 0)
        {
            var handle = new BpfProgHandle();
            handle.SetFd(result);
            return handle;
        }

        int errno = -result;
        if (errno == E2BIG)
            throw new BpfProgramTooLargeException(insns.Length, errno);
        // An unknown program type is rejected with EINVAL before the verifier runs,
        // so there is no log; the probe tells it apart from other EINVALs.
        if (errno == EINVAL && KernelFeatures.CanProbe(type) && !KernelFeatures.Running.HasProgramType(type))
            throw KernelFeatureCatalog.Unsupported(type, errno);
        throw TranslateError(errno, $"BPF_PROG_LOAD ({type})");
    }

    /// <summary>BPF_PROG_LOAD without any error interpretation: the new fd, or the
    /// negated errno, plus the verifier log when <paramref name="withLog"/> is set
    /// (empty otherwise). The feature probes build on this, so it must never probe.</summary>
    internal static int TryLoadProgram(
        BpfProgType type, ReadOnlySpan<BpfInsn> insns, string license, string? name,
        out string log, bool withLog)
    {
        Span<byte> licenseBytes = stackalloc byte[license.Length + 1];
        Encoding.ASCII.GetBytes(license, licenseBytes);
        licenseBytes[license.Length] = 0;

        var logBuf = withLog ? new byte[256 * 1024] : [];
        fixed (BpfInsn* insnPtr = insns)
        fixed (byte* licensePtr = licenseBytes)
        fixed (byte* logPtr = logBuf)
        {
            var attr = new ProgLoadAttr
            {
                ProgType = (uint)type,
                InsnCnt = (uint)insns.Length,
                Insns = (ulong)insnPtr,
                License = (ulong)licensePtr,
            };
            CopyName(name, attr.ProgName);
            if (withLog)
            {
                attr.LogLevel = 1;
                attr.LogSize = (uint)logBuf.Length;
                attr.LogBuf = (ulong)logPtr;
            }

            int result = Invoke(BpfCmd.ProgLoad, ref attr);
            int nul = Array.IndexOf<byte>(logBuf, 0);
            log = Encoding.ASCII.GetString(logBuf, 0, nul < 0 ? logBuf.Length : nul);
            return result;
        }
    }

    /// <summary>Runs a program via BPF_PROG_TEST_RUN and returns its return value.</summary>
    internal static uint ProgTestRun(BpfProgHandle prog, ReadOnlySpan<byte> dataIn, uint repeat)
    {
        fixed (byte* dataPtr = dataIn)
        {
            var attr = new ProgTestRunAttr
            {
                ProgFd = (uint)prog.Fd,
                DataSizeIn = (uint)dataIn.Length,
                DataIn = (ulong)dataPtr,
                Repeat = repeat,
            };
            int result = Invoke(BpfCmd.ProgTestRun, ref attr);
            if (result < 0) throw TranslateError(-result, "BPF_PROG_TEST_RUN");
            return attr.Retval;
        }
    }

    private static BpfException TranslateError(int errno, string operation) => errno switch
    {
        EPERM => new BpfPermissionException(operation, errno, MemlockLimit.EpermHint()),
        ENOTSUPP or EOPNOTSUPP => new BpfFeatureUnsupportedException(operation, errno),
        EEXIST => new BpfException($"{operation} failed with EEXIST (key already exists).", errno),
        _ => new BpfException($"{operation} failed with errno {errno}.", errno),
    };

    /// <summary>Copies an object name into a fixed 16-byte kernel name field (15 chars max, NUL-padded).</summary>
    private static void CopyName(string? name, byte* dest)
    {
        if (string.IsNullOrEmpty(name)) return;
        if (name.Length > 15)
            throw new ArgumentException($"BPF object names are limited to 15 characters: '{name}'.");
        foreach (char c in name)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c != '_' && c != '.')
                throw new ArgumentException($"Invalid character '{c}' in BPF object name '{name}'.");
        }
        for (int i = 0; i < name.Length; i++) dest[i] = (byte)name[i];
    }
}
