# Sourced by the eng/ scripts that run work in a Linux container. Picks the runtime and
# the flag that grants what bpf(2) needs:
#
#   macOS with Apple's `container` CLI  -> container, --cap-add ALL
#       Every container is its own lightweight VM, so all capabilities inside it
#       touch only that VM's kernel. (No --privileged flag exists there.)
#   anything else (Linux, CI)           -> docker, --privileged
#
# CONTAINER_RUNTIME=docker|container overrides the choice.
#
# Apple's default (Kata) kernel has BPF_SYSCALL but no FTRACE/KPROBES and no
# DEBUG_INFO_BTF: maps, ring buffers and socket-filter programs work, tracepoint
# programs fail with EINVAL and vmlinux BTF is absent. CONTAINER_KERNEL=<vmlinux path>
# boots a BPF-capable kernel instead (`container run -k`; container runtime only),
# e.g. the one eng/build-kernel.sh builds.

if [ -z "${CONTAINER_RUNTIME:-}" ]; then
    if [ "$(uname -s)" = Darwin ] && command -v container >/dev/null; then
        CONTAINER_RUNTIME=container
    else
        CONTAINER_RUNTIME=docker
    fi
fi

case "$CONTAINER_RUNTIME" in
    container)
        BPF_PRIVILEGE=(--cap-add ALL)
        if [ -n "${CONTAINER_KERNEL:-}" ]; then BPF_PRIVILEGE+=(-k "$CONTAINER_KERNEL"); fi
        ;;
    docker)    BPF_PRIVILEGE=(--privileged) ;;
    *) echo "error: CONTAINER_RUNTIME must be docker or container, not '$CONTAINER_RUNTIME'" >&2; exit 1 ;;
esac

command -v "$CONTAINER_RUNTIME" >/dev/null || {
    echo "error: $CONTAINER_RUNTIME not found (set CONTAINER_RUNTIME to override)" >&2
    exit 1
}
