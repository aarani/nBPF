#!/bin/sh
# PID 1 of the eng/qemu-test.sh guest. The root filesystem is the host's, read-only
# over 9p; nothing is mounted yet and nothing else runs. Mount what the tests need,
# run the command eng/qemu-test.sh left in artifacts/qemu/, record its exit code
# there, and power off. The kernel hands us NBPF_ROOT (the checkout's path) through
# its command line.

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
# The kernel may already have mounted devtmpfs (CONFIG_DEVTMPFS_MOUNT).
grep -q '^devtmpfs /dev ' /proc/mounts || mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /dev/shm
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run

# The writable checkout, over the read-only copy the root share shows at that path.
mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144 nbpf "$NBPF_ROOT"

# Mounts over 9p directories can silently vanish (see eng/qemu-test.sh); without
# /proc nothing else works, so say so plainly instead of failing obscurely later.
if [ ! -e /proc/self/mounts ] || [ ! -w "$NBPF_ROOT/artifacts" ]; then
    echo "nbpf guest: error: the /proc or checkout mount did not stick" >&2
fi

# Loopback: `dotnet test` talks to its testhost process over a localhost TCP socket,
# and with lo down it waits out its connection timeout and fails without running a
# test. Nothing else in the guest is networked.
ip link set lo up

state="$NBPF_ROOT/artifacts/qemu"
echo "nbpf guest: kernel $(uname -r)"

. "$state/env"
export HOME=/tmp/home DOTNET_CLI_HOME=/tmp/home TMPDIR=/tmp
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
mkdir -p "$HOME"

# The output also goes to a file in the checkout, which eng/qemu-test.sh prints after
# QEMU exits. The serial console alone isn't enough: it drains slowly, and output
# still buffered when the VM powers off is lost. That's how a passing 5.4 run once
# showed nothing past dotnet test's first line.
{ sh "$state/cmd"; echo $? > "$state/exit"; } 2>&1 | tee "$state/output.log"
sync

# Let the console drain, then power off; if sysrq is unavailable, exiting PID 1
# panics the kernel, and with panic=-1 and QEMU's -no-reboot that ends the VM too.
sleep 2
echo o > /proc/sysrq-trigger
sleep 10
