using System.Runtime.InteropServices;
using System.Text;
using Ebpf.Core.Insns;

namespace Ebpf.Core.Native;

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
        var attr = new MapCreateAttr
        {
            MapType = (uint)type,
            KeySize = keySize,
            ValueSize = valueSize,
            MaxEntries = maxEntries,
            MapFlags = flags,
        };
        CopyName(name, attr.MapName);

        int result = Invoke(BpfCmd.MapCreate, ref attr);
        if (result < 0)
            throw TranslateError(-result, $"BPF_MAP_CREATE ({type})");

        var handle = new BpfMapHandle();
        handle.SetFd(result);
        return handle;
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
        Span<byte> licenseBytes = stackalloc byte[license.Length + 1];
        Encoding.ASCII.GetBytes(license, licenseBytes);
        licenseBytes[license.Length] = 0;

        fixed (BpfInsn* insnPtr = insns)
        fixed (byte* licensePtr = licenseBytes)
        {
            var attr = new ProgLoadAttr
            {
                ProgType = (uint)type,
                InsnCnt = (uint)insns.Length,
                Insns = (ulong)insnPtr,
                License = (ulong)licensePtr,
            };
            CopyName(name, attr.ProgName);

            int result = Invoke(BpfCmd.ProgLoad, ref attr);
            if (result >= 0)
            {
                var handle = new BpfProgHandle();
                handle.SetFd(result);
                return handle;
            }

            int errno = -result;
            if (errno is EACCES or EINVAL)
            {
                // Retry with the verifier log enabled so the exception can carry it.
                var logBuf = new byte[256 * 1024];
                fixed (byte* logPtr = logBuf)
                {
                    attr.LogLevel = 1;
                    attr.LogSize = (uint)logBuf.Length;
                    attr.LogBuf = (ulong)logPtr;
                    result = Invoke(BpfCmd.ProgLoad, ref attr);
                    if (result >= 0)
                    {
                        var handle = new BpfProgHandle();
                        handle.SetFd(result);
                        return handle;
                    }
                    int nul = Array.IndexOf<byte>(logBuf, 0);
                    string log = Encoding.ASCII.GetString(logBuf, 0, nul < 0 ? logBuf.Length : nul);
                    if (log.Length > 0)
                        throw new BpfVerifierException(log, -result);
                }
            }
            if (errno == E2BIG)
                throw new BpfProgramTooLargeException(insns.Length, errno);
            throw TranslateError(errno, $"BPF_PROG_LOAD ({type})");
        }
    }

    private static BpfException TranslateError(int errno, string operation) => errno switch
    {
        EPERM => new BpfPermissionException(operation, errno),
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
