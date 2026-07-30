using System.Runtime.InteropServices;

namespace Ebpf.Core.Native;

// One blittable struct per bpf(2) command, sized exactly as far as we use it.
// The kernel accepts any size as long as bytes beyond what it knows are zero,
// and treats missing trailing fields as zero — so these can stay minimal and
// grow additively. Field offsets must match linux/bpf.h's union bpf_attr.

/// <summary>Attr for BPF_MAP_CREATE.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct MapCreateAttr
{
    public uint MapType;
    public uint KeySize;
    public uint ValueSize;
    public uint MaxEntries;
    public uint MapFlags;
    public uint InnerMapFd;
    public uint NumaNode;
    public fixed byte MapName[16];
}

/// <summary>
/// Attr for BPF_MAP_{LOOKUP,UPDATE,DELETE}_ELEM and BPF_MAP_GET_NEXT_KEY.
/// <see cref="Value"/> doubles as next_key for GET_NEXT_KEY.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct MapElemAttr
{
    public uint MapFd;
    private uint _pad; // key is __aligned_u64 in the kernel
    public ulong Key;   // user-space pointer
    public ulong Value; // user-space pointer (or next_key pointer)
    public ulong Flags;
}

/// <summary>Attr for BPF_PROG_TEST_RUN.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct ProgTestRunAttr
{
    public uint ProgFd;
    public uint Retval;      // out: the program's return value
    public uint DataSizeIn;
    public uint DataSizeOut;
    public ulong DataIn;     // user-space pointer
    public ulong DataOut;    // user-space pointer, 0 = don't copy out
    public uint Repeat;
    public uint Duration;    // out: mean ns per run
}

/// <summary>Attr for BPF_PROG_LOAD.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct ProgLoadAttr
{
    public uint ProgType;
    public uint InsnCnt;
    public ulong Insns;   // user-space pointer to BpfInsn[]
    public ulong License; // user-space pointer to NUL-terminated string
    public uint LogLevel;
    public uint LogSize;
    public ulong LogBuf;  // user-space pointer
    public uint KernVersion;
    public uint ProgFlags;
    public fixed byte ProgName[16];
    public uint ProgIfIndex;
    public uint ExpectedAttachType;
}
