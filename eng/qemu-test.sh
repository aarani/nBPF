#!/usr/bin/env bash
# Boots a kernel in QEMU and runs the Linux tests (tests/Nbpf.Core.Tests) inside it,
# for kernels Apple's `container` can't run (see eng/build-kernel.sh). Built for a
# Linux CI runner; plain QEMU, no VM tooling on top.
#
#   eng/qemu-test.sh <bzImage> [extra dotnet test args...]
#
# The guest has no disk image. Its root filesystem is this host's own, shared
# read-only over 9p, so it sees the same dotnet SDK and the same paths. The checkout
# is a second, writable 9p share mounted over its own path, where the tests write
# their results. eng/qemu-init.sh is the guest's PID 1: it mounts what a root
# filesystem needs, runs the tests, records the exit code and powers off.
#
# Build the tests on the host first (dotnet build tests/Nbpf.Core.Tests -c Release):
# the guest runs them with --no-build and never touches NuGet.
#
#   QEMU_MEMORY (default 4G), QEMU_TIMEOUT seconds (default 1800)
set -euo pipefail

kernel="${1:?usage: eng/qemu-test.sh <bzImage> [dotnet test args...]}"
shift
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
kernel="$(cd "$(dirname "$kernel")" && pwd)/$(basename "$kernel")"

state="$root/artifacts/qemu"
mkdir -p "$state"
rm -f "$state/exit"

# What the guest runs, and the environment it runs with: the host's PATH and
# DOTNET_ROOT, so the same SDK is found through the shared root filesystem.
{
    printf 'export PATH=%q\n' "$PATH"
    printf 'export DOTNET_ROOT=%q\n' "${DOTNET_ROOT:-$(dirname "$(readlink -f "$(command -v dotnet)")")}"
} > "$state/env"
{
    printf 'cd %q\n' "$root"
    printf 'dotnet test tests/Nbpf.Core.Tests -c Release --no-build -l %q' "console;verbosity=normal"
    printf ' %q' "$@"
    printf '\n'
} > "$state/cmd"

accel=(-machine accel=tcg)
if [ -w /dev/kvm ]; then
    accel=(-enable-kvm -cpu host)
else
    echo "warning: /dev/kvm is not writable; falling back to (slow) emulation" >&2
fi

# Kernel arguments the kernel doesn't recognize as its own become environment
# variables of init, which is how the guest learns where the checkout is.
#
# The guest mounts /proc, /sys, /dev, tmpfs and the checkout over directories of the
# 9p root, and those mounts must stick. So the root share uses 9p's default cache
# mode: with cache=loose the client revalidates directory entries, and an entry that
# fails revalidation is dropped together with whatever is mounted on it. And it
# remaps inode numbers (multidevs=remap): host /proc, /sys, /dev and /run are other
# filesystems inside the same export, whose colliding ids would otherwise make
# entries look changed. The first 5.4 boot lost its /proc mount to exactly this.
append="console=ttyS0 panic=-1 ro"
append+=" root=/dev/root rootfstype=9p rootflags=trans=virtio,version=9p2000.L,msize=262144"
append+=" init=$root/eng/qemu-init.sh NBPF_ROOT=$root"

status=0
timeout "${QEMU_TIMEOUT:-1800}" qemu-system-x86_64 "${accel[@]}" \
    -m "${QEMU_MEMORY:-4G}" -smp "$(nproc)" \
    -nographic -no-reboot \
    -kernel "$kernel" -append "$append" \
    -fsdev local,id=hostroot,path=/,security_model=none,readonly=on,multidevs=remap \
    -device virtio-9p-pci,fsdev=hostroot,mount_tag=/dev/root \
    -fsdev local,id=checkout,path="$root",security_model=none,multidevs=remap \
    -device virtio-9p-pci,fsdev=checkout,mount_tag=nbpf \
    || status=$?

if [ ! -f "$state/exit" ]; then
    echo "error: the guest never reported an exit code (QEMU exited with $status)" >&2
    exit 1
fi
exit "$(cat "$state/exit")"
