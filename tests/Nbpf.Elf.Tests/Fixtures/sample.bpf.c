// Fixture for the ELF reader tests. Self-contained: no vmlinux.h and no kernel headers,
// so the object can be regenerated on any host that has clang with a BPF target.
// Regenerate with eng/gen-fixtures.sh — do not edit sample.bpf.o by hand.
//
// This is shaped to exercise the reader rather than to be a useful program: two program
// sections, BTF-defined maps, a non-inlined subprogram, and globals in .rodata/.bss, so
// the object carries map, global-data, and subprogram-call relocations.

typedef unsigned int u32;
typedef unsigned long long u64;

// The raw form of the bpf_helpers.h BPF_MAP_TYPE macros — an anonymous struct whose
// members encode the map attributes as pointer-to-array types.
struct {
    int (*type)[27];            // BPF_MAP_TYPE_RINGBUF
    int (*max_entries)[4096];
} events __attribute__((section(".maps"), used));

struct {
    int (*type)[1];             // BPF_MAP_TYPE_HASH
    int (*max_entries)[1024];
    u32 *key;
    u64 *value;
} counts __attribute__((section(".maps"), used));

// Helpers are ordinary function pointers at fixed helper ids, exactly as
// bpf_helper_defs.h declares them.
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
                                   u64 flags) = (void *)2;

const volatile u32 min_uid = 0;

u64 dropped;

// noinline forces a real BPF_PSEUDO_CALL rather than an inlined body, so the object
// carries a subprogram relocation for the loader to resolve.
static __attribute__((noinline)) u64 bump(u64 previous)
{
    return previous + 1;
}

static __attribute__((always_inline)) int record(u32 pid)
{
    u64 *slot = bpf_map_lookup_elem(&counts, &pid);
    if (!slot) {
        u64 one = 1;
        return (int)bpf_map_update_elem(&counts, &pid, &one, 0);
    }

    *slot = bump(*slot);
    return 0;
}

__attribute__((section("tracepoint/syscalls/sys_enter_execve"), used))
int handle_exec(void *ctx)
{
    u32 pid = min_uid;
    if (!ctx)
        return 0;

    return record(pid);
}

__attribute__((section("tracepoint/syscalls/sys_enter_openat"), used))
int handle_open(void *ctx)
{
    if (!ctx)
        dropped = bump(dropped);

    return 0;
}

char _license[] __attribute__((section("license"), used)) = "GPL";
