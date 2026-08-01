// Fixture for the BTF parser tests. Deliberately self-contained: no vmlinux.h and no
// kernel headers, so the .BTF section can be regenerated on any host that has clang.
// Regenerate with eng/gen-fixtures.sh — do not edit sample.btf by hand.
//
// Only types reachable from a function or a global variable end up in BTF, which is why
// `struct event` is anchored by a global rather than being a local in handle_exec.

typedef unsigned int u32;
typedef unsigned long long u64;

enum kind { KIND_A = 0, KIND_B = 1, KIND_C = -1 };

struct inner { u32 a; u32 b; };

struct event {
    u64 ts;
    u32 pid;
    char comm[16];
    struct inner nested;
    enum kind kind;
    unsigned int flag_x : 1;
    unsigned int flag_y : 3;
    const void *ctx;
    struct event *next;
};

const volatile u32 min_uid = 0;

struct event last_event;

__attribute__((section("tracepoint/syscalls/sys_enter_execve"), used))
int handle_exec(void *ctx)
{
    last_event.ctx = ctx;
    last_event.pid = min_uid;
    return 0;
}

char _license[] __attribute__((section("license"), used)) = "GPL";
