using System.Text.RegularExpressions;
using Nbpf.Core.Native;

namespace Nbpf.Core;

/// <summary>
/// Kernel names and first upstream release for the map types, program types and
/// helpers this library knows, so a probe that comes back negative turns into
/// "your kernel is too old for X, minimum is Y" (DESIGN §4.5) instead of an errno.
/// </summary>
internal static partial class KernelFeatureCatalog
{
    private static readonly Dictionary<BpfMapType, (string Name, string Since)> Maps = new()
    {
        [BpfMapType.Hash] = ("BPF_MAP_TYPE_HASH", "3.19"),
        [BpfMapType.Array] = ("BPF_MAP_TYPE_ARRAY", "3.19"),
        [BpfMapType.ProgArray] = ("BPF_MAP_TYPE_PROG_ARRAY", "4.2"),
        [BpfMapType.PerfEventArray] = ("BPF_MAP_TYPE_PERF_EVENT_ARRAY", "4.3"),
        [BpfMapType.PerCpuHash] = ("BPF_MAP_TYPE_PERCPU_HASH", "4.6"),
        [BpfMapType.PerCpuArray] = ("BPF_MAP_TYPE_PERCPU_ARRAY", "4.6"),
        [BpfMapType.StackTrace] = ("BPF_MAP_TYPE_STACK_TRACE", "4.6"),
        [BpfMapType.CgroupArray] = ("BPF_MAP_TYPE_CGROUP_ARRAY", "4.8"),
        [BpfMapType.LruHash] = ("BPF_MAP_TYPE_LRU_HASH", "4.10"),
        [BpfMapType.LruPerCpuHash] = ("BPF_MAP_TYPE_LRU_PERCPU_HASH", "4.10"),
        [BpfMapType.LpmTrie] = ("BPF_MAP_TYPE_LPM_TRIE", "4.11"),
        [BpfMapType.RingBuf] = ("BPF_MAP_TYPE_RINGBUF", "5.8"),
    };

    private static readonly Dictionary<BpfProgType, (string Name, string Since)> Programs = new()
    {
        [BpfProgType.SocketFilter] = ("BPF_PROG_TYPE_SOCKET_FILTER", "3.19"),
        [BpfProgType.Kprobe] = ("BPF_PROG_TYPE_KPROBE", "4.1"),
        [BpfProgType.SchedCls] = ("BPF_PROG_TYPE_SCHED_CLS", "4.1"),
        [BpfProgType.SchedAct] = ("BPF_PROG_TYPE_SCHED_ACT", "4.1"),
        [BpfProgType.Tracepoint] = ("BPF_PROG_TYPE_TRACEPOINT", "4.7"),
        [BpfProgType.Xdp] = ("BPF_PROG_TYPE_XDP", "4.8"),
        [BpfProgType.PerfEvent] = ("BPF_PROG_TYPE_PERF_EVENT", "4.9"),
        [BpfProgType.CgroupSkb] = ("BPF_PROG_TYPE_CGROUP_SKB", "4.10"),
        [BpfProgType.CgroupSock] = ("BPF_PROG_TYPE_CGROUP_SOCK", "4.10"),
        [BpfProgType.RawTracepoint] = ("BPF_PROG_TYPE_RAW_TRACEPOINT", "4.17"),
        [BpfProgType.Tracing] = ("BPF_PROG_TYPE_TRACING", "5.5"),
    };

    // Helper ids from the kernel's uapi helper list (include/uapi/linux/bpf.h).
    internal const int ProbeRead = 4, ProbeReadStr = 45,
                       ProbeReadUser = 112, ProbeReadKernel = 113,
                       ProbeReadUserStr = 114, ProbeReadKernelStr = 115;

    private static readonly Dictionary<int, (string Name, string Since)> Helpers = new()
    {
        [1] = ("bpf_map_lookup_elem", "3.19"),
        [2] = ("bpf_map_update_elem", "3.19"),
        [3] = ("bpf_map_delete_elem", "3.19"),
        [ProbeRead] = ("bpf_probe_read", "4.1"),
        [35] = ("bpf_get_current_task", "4.8"),
        [ProbeReadStr] = ("bpf_probe_read_str", "4.11"),
        [ProbeReadUser] = ("bpf_probe_read_user", "5.5"),
        [ProbeReadKernel] = ("bpf_probe_read_kernel", "5.5"),
        [ProbeReadUserStr] = ("bpf_probe_read_user_str", "5.5"),
        [ProbeReadKernelStr] = ("bpf_probe_read_kernel_str", "5.5"),
        [130] = ("bpf_ringbuf_output", "5.8"),
        [131] = ("bpf_ringbuf_reserve", "5.8"),
        [132] = ("bpf_ringbuf_submit", "5.8"),
        [133] = ("bpf_ringbuf_discard", "5.8"),
        [134] = ("bpf_ringbuf_query", "5.8"),
    };

    internal static string Describe(BpfMapType type) =>
        Maps.TryGetValue(type, out var m) ? m.Name : $"BPF map type {(uint)type}";

    internal static string Describe(BpfProgType type) =>
        Programs.TryGetValue(type, out var p) ? p.Name : $"BPF program type {(uint)type}";

    internal static string DescribeHelper(int id) =>
        Helpers.TryGetValue(id, out var h) ? $"{h.Name} (#{id})" : $"helper #{id}";

    internal static string? Since(BpfMapType type) => Maps.TryGetValue(type, out var m) ? m.Since : null;
    internal static string? Since(BpfProgType type) => Programs.TryGetValue(type, out var p) ? p.Since : null;
    internal static string? HelperSince(int id) => Helpers.TryGetValue(id, out var h) ? h.Since : null;

    internal static BpfFeatureUnsupportedException Unsupported(BpfMapType type, int errno) =>
        new(Describe(type), Since(type), errno);

    internal static BpfFeatureUnsupportedException Unsupported(BpfProgType type, int errno) =>
        new(Describe(type), Since(type), errno);

    internal static BpfFeatureUnsupportedException Unsupported(BpfProgType type, int helperId, int errno) =>
        new($"{DescribeHelper(helperId)} in {Describe(type)} programs", HelperSince(helperId), errno);

    /// <summary>
    /// The helper id the verifier refused as missing, or null if the log says
    /// nothing of the kind. Kernels have worded this three ways: "invalid func" for
    /// an id past the end of the helper list, and for a known helper the program type
    /// doesn't offer, "unknown func" (older kernels) or "program of this type cannot
    /// use helper" (newer ones).
    /// </summary>
    internal static int? RejectedHelper(string verifierLog) =>
        MissingHelper().Match(verifierLog) is { Success: true } m &&
        int.TryParse(m.Groups[1].ValueSpan, out int id)
            ? id
            : null;

    [GeneratedRegex(@"(?:invalid func|unknown func|program of this type cannot use helper) \S+#(-?\d+)")]
    private static partial Regex MissingHelper();
}
