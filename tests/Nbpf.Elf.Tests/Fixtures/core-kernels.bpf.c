// Fixture for the cross-kernel CO-RE tests: one object, resolved against the vmlinux
// BTF of Ubuntu's 5.4 and 6.8 kernels (minimized copies, see eng/gen-kernel-btf.sh).
// Self-contained like core-sample.bpf.c: no vmlinux.h, no kernel headers.
// Regenerate with eng/gen-fixtures.sh — do not edit core-kernels.bpf.o by hand.
//
// Each relocation was picked because the two kernels disagree about it, so an identity
// resolution (or one that ignores the target) can't pass by accident:
//
//   task_struct.pid/tgid   real offsets move as the struct grows between versions
//   task_struct.state      renamed to __state (and narrowed long -> unsigned int) in 5.14;
//                          the classic ___flavor idiom resolves exactly one of the two
//   sizeof(task_struct)    a TYPE_SIZE that differs per kernel
//   struct bpf_ringbuf     TYPE_EXISTS: added in 5.8
//   BPF_MAP_TYPE_RINGBUF   ENUMVAL_EXISTS: added in 5.8
//   sk_buff.pkt_type       a real 3-bit bitfield, for the offset/size/shift kinds. Its
//                          values happen to match on both kernels; what differs is the
//                          path: a direct member on 5.4, nested in an anonymous
//                          union/struct by 6.8, which the matcher must recurse into
//
// Deliberately absent: TYPE_ID_TARGET on task_struct. Ubuntu's 5.4.0-26 BTF carries two
// identical task_struct definitions (ids 147 and 28278, a pahole dedup leftover), so
// that relocation is genuinely ambiguous there — libbpf rejects it, and so would
// bpftool's minimizer when regenerating the fixtures. Field relocations are fine: both
// copies agree on every offset.
//
// Each builtin's result is stored in its own global so the program stays trivially
// verifiable and every relocation stays live (none is folded into another).

typedef unsigned int u32;
typedef unsigned long long u64;

struct task_struct {
    int pid;
    int tgid;
    unsigned int __state;
} __attribute__((preserve_access_index));

// The pre-5.14 layout. The ___old suffix is stripped before matching, so this flavor
// is matched against the target's task_struct too.
struct task_struct___old {
    long state;
} __attribute__((preserve_access_index));

struct sk_buff {
    unsigned char pkt_type : 3;
} __attribute__((preserve_access_index));

// Only the name matters to TYPE_EXISTS; the body is never compared beyond its kind.
struct bpf_ringbuf {
    int unused;
};

// Local enumerator values are placeholders: ENUMVAL relos re-resolve by name.
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_RINGBUF = 27,
};

static long (*bpf_probe_read_kernel)(void *dst, u32 size, const void *src) = (void *)113;
static u64 (*bpf_get_current_task)(void) = (void *)35;

u64 observed_pid;
u64 observed_tgid;
u64 observed_state;

u64 has_new_state;
u64 has_old_state;
u64 old_state_size;
u64 task_struct_size;
u64 has_ringbuf_type;
u64 has_ringbuf_map;

u64 pkt_type_offset;
u64 pkt_type_size;
u64 pkt_type_lshift;
u64 pkt_type_rshift;
u64 pkt_type_signed;

__attribute__((section("tracepoint/syscalls/sys_enter_execve"), used))
int handle_exec(void *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    int pid = 0;
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
    observed_pid = (u64)pid;

    int tgid = 0;
    bpf_probe_read_kernel(&tgid, sizeof(tgid), &task->tgid);
    observed_tgid = (u64)tgid;

    // FIELD_EXISTS (kind 2) on each side of the rename; exactly one is live per kernel.
    has_new_state = __builtin_preserve_field_info(task->__state, 2);
    has_old_state = __builtin_preserve_field_info(((struct task_struct___old *)task)->state, 2);
    if (has_new_state) {
        unsigned int state = 0;
        bpf_probe_read_kernel(&state, sizeof(state), &task->__state);
        observed_state = state;
    } else if (has_old_state) {
        // FIELD_BYTE_SIZE (kind 1): 8 on 5.4. Guarded, so 6.8 never needs it.
        old_state_size = __builtin_preserve_field_info(((struct task_struct___old *)task)->state, 1);
        long state = 0;
        bpf_probe_read_kernel(&state, sizeof(state), &((struct task_struct___old *)task)->state);
        observed_state = (u64)state;
    }

    // TYPE_SIZE (9), TYPE_EXISTS (8).
    task_struct_size = __builtin_preserve_type_info(*(struct task_struct *)0, 1);
    has_ringbuf_type = __builtin_preserve_type_info(*(struct bpf_ringbuf *)0, 0);

    // ENUMVAL_EXISTS (10).
    has_ringbuf_map = __builtin_preserve_enum_value(*(enum bpf_map_type *)BPF_MAP_TYPE_RINGBUF, 0);

    // The bitfield kinds BPF_CORE_READ_BITFIELD needs: offset (0), size (1),
    // signed (3), lshift (4), rshift (5). sk_buff is never dereferenced.
    struct sk_buff *skb = (struct sk_buff *)0;
    pkt_type_offset = __builtin_preserve_field_info(skb->pkt_type, 0);
    pkt_type_size = __builtin_preserve_field_info(skb->pkt_type, 1);
    pkt_type_signed = __builtin_preserve_field_info(skb->pkt_type, 3);
    pkt_type_lshift = __builtin_preserve_field_info(skb->pkt_type, 4);
    pkt_type_rshift = __builtin_preserve_field_info(skb->pkt_type, 5);

    return 0;
}

char _license[] __attribute__((section("license"), used)) = "GPL";
