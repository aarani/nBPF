namespace Nbpf.Core.Native;

/// <summary>Commands for the bpf(2) syscall. Values from linux/bpf.h.</summary>
internal enum BpfCmd
{
    MapCreate = 0,
    MapLookupElem = 1,
    MapUpdateElem = 2,
    MapDeleteElem = 3,
    MapGetNextKey = 4,
    ProgLoad = 5,
    ObjPin = 6,
    ObjGet = 7,
    ProgAttach = 8,
    ProgDetach = 9,
    ProgTestRun = 10,
    BtfLoad = 18,
    MapFreeze = 22,
    LinkCreate = 28,
    MapLookupBatch = 24,
    MapUpdateBatch = 26,
}

/// <summary>BPF_MAP_CREATE map_flags bits. Values from linux/bpf.h.</summary>
[Flags]
internal enum BpfMapCreateFlags : uint
{
    None = 0,
    /// <summary>BPF_F_RDONLY_PROG — the program side may only read the map.</summary>
    RdonlyProg = 1u << 7,
}

public enum BpfMapType : uint
{
    Unspec = 0,
    Hash = 1,
    Array = 2,
    ProgArray = 3,
    PerfEventArray = 4,
    PerCpuHash = 5,
    PerCpuArray = 6,
    StackTrace = 7,
    CgroupArray = 8,
    LruHash = 9,
    LruPerCpuHash = 10,
    LpmTrie = 11,
    RingBuf = 27,
}

public enum BpfProgType : uint
{
    Unspec = 0,
    SocketFilter = 1,
    Kprobe = 2,
    SchedCls = 3,
    SchedAct = 4,
    Tracepoint = 5,
    Xdp = 6,
    PerfEvent = 7,
    CgroupSkb = 8,
    CgroupSock = 9,
    RawTracepoint = 17,
    Tracing = 26,
}

public enum MapUpdateFlags : ulong
{
    /// <summary>BPF_ANY — create or update.</summary>
    Any = 0,
    /// <summary>BPF_NOEXIST — create only, fail if the key exists.</summary>
    NoExist = 1,
    /// <summary>BPF_EXIST — update only, fail if the key is absent.</summary>
    Exist = 2,
}
