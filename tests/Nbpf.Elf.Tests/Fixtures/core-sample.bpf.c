// Fixture for the CO-RE tests. Self-contained: no vmlinux.h and no kernel headers, so
// it can be regenerated on any host that has clang with a BPF target.
// Regenerate with eng/gen-fixtures.sh — do not edit core-sample.bpf.o by hand.
//
// The struct below is a deliberately tiny stand-in for the kernel's task_struct:
// preserve_access_index makes clang record every member access as a CO-RE relocation,
// and the loader re-resolves them against the running kernel's vmlinux BTF — where pid
// is a real field thousands of bytes in. That re-resolution is the whole point of the
// fixture; the local offsets (0 and 4) are meaningless at run time.

typedef unsigned int u32;
typedef unsigned long long u64;

struct task_struct {
    int pid;
    int tgid;
} __attribute__((preserve_access_index));

// Helpers as bpf_helper_defs.h declares them: function pointers at fixed helper ids.
static long (*bpf_probe_read_kernel)(void *dst, u32 size, const void *src) = (void *)113;
static u64 (*bpf_get_current_task)(void) = (void *)35;

u64 observed_pid;
u64 observed_tgid;

__attribute__((section("tracepoint/syscalls/sys_enter_execve"), used))
int handle_exec(void *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // Unguarded access: FIELD_BYTE_OFFSET relo, poisoned if the target has no pid.
    int pid = 0;
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
    observed_pid = (u64)pid;

    // Guarded access: __builtin_preserve_field_info(..., 2) is FIELD_EXISTS, so a
    // target without tgid turns this whole branch into provably dead code.
    if (__builtin_preserve_field_info(task->tgid, 2)) {
        int tgid = 0;
        bpf_probe_read_kernel(&tgid, sizeof(tgid), &task->tgid);
        observed_tgid = (u64)tgid;
    }

    return 0;
}

char _license[] __attribute__((section("license"), used)) = "GPL";
