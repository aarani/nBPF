#!/usr/bin/env bash
# Builds a Linux kernel with everything the nBPF test suite needs (tracepoint/kprobe
# programs, the BPF JIT, /sys/kernel/btf/vmlinux, AF_XDP, tc BPF), in one of two
# flavors (KERNEL_FLAVOR):
#
#   container (default)  arm64, for Apple's `container` (`container run -k`, see
#                        eng/container-runtime.sh). Apple's default (Kata) kernel has
#                        none of the above beyond BPF_SYSCALL.
#     config = eng/kernel/kata-<ver>.config  Apple's default kernel config, verbatim
#                                            (it boots: virtio, vsock, virtiofs built
#                                            in, no modules, no initramfs needed)
#
#   qemu                 x86_64, for eng/qemu-test.sh on a CI runner. This is the
#                        route for kernels Apple's `container` can't run processes on:
#                        its in-VM agent fails on 5.4 with ENOSYS, most likely for
#                        openat2 (5.6).
#     config = x86_64 defconfig + the kernel's own KVM guest config
#            + eng/kernel/qemu-x86.config   9p root, serial console, debug info
#
#   either + eng/kernel/nbpf.config          the BPF/tracing options on top
#          + eng/kernel/nbpf-pre-6.10.config for kernels before 6.10 only: module
#                                            support, which BPF_JIT and KPROBES
#                                            depend on there
#
# Every option in the fragments is checked against the final .config, so an option
# that `make olddefconfig` drops for an unmet dependency fails the build instead of
# producing a kernel that quietly lacks it.
#
# Output, in OUT_DIR (default artifacts/kernel/, git-ignored):
#   vmlinux-<ver>-nbpf   container: uncompressed arm64 Image (named like Apple's own)
#   bzImage-<ver>-nbpf   qemu: x86_64 bzImage
#   config-<ver>-nbpf    the final .config
#   SHA256SUMS
#
# Then: CONTAINER_KERNEL=artifacts/kernel/vmlinux-<ver>-nbpf eng/test-linux.sh
#   or: eng/qemu-test.sh artifacts/kernel/bzImage-<ver>-nbpf
#
# The build runs in CI, on a native runner for the flavor's architecture
# (.github/workflows/container-kernel.yml, .github/workflows/live-kernels.yml); it
# needs a few GB of RAM. It runs in a Debian container via eng/container-runtime.sh
# and needs network access.
#
#   KERNEL_FLAVOR=container|qemu  see above (default container)
#   KERNEL_VERSION=<x.y.z>  kernel to build (default below); each version needs a
#                           pinned sha256 in the table below
#   CONFIG_ONLY=1           stop after producing and checking the .config (cheap:
#                           no compile, a good first check after editing the fragment)
#   OUT_DIR=<dir>           where outputs go
#   DOWNLOAD_CACHE=<dir>    reuse (and fill) a directory of kernel tarballs
#   KERNEL_BUILD_CPUS / KERNEL_BUILD_MEMORY   VM size under Apple's `container`
#                           (default: all host CPUs, 4G)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/eng/container-runtime.sh"

kernel_version="${KERNEL_VERSION:-6.18.64}"
flavor="${KERNEL_FLAVOR:-container}"

# version -> sha256 of linux-<version>.tar.xz (from kernel.org's signed
# sha256sums.asc), the container flavor's base config, extra fragments, and the
# builder image. Old kernels need an old toolchain: current gcc and pahole don't
# build them cleanly, and a new pahole writes BTF kinds an old kernel can't read
# back, so it would reject its own vmlinux BTF.
extra_fragments=""  # space-separated, merged after nbpf.config
builder_image=debian:trixie-slim
case "$kernel_version" in
    6.18.64)
        tarball_sha256=020d45510c539972e6f14c5c71566878d3b7ef56fb082b3e09134f2ebaade562
        base_config=kata-6.18.15.config
        ;;
    6.8.12)
        # Last 6.8 stable; phase 2's "6.8" kernel. Kata's 6.18 config is the base:
        # olddefconfig drops what 6.8 doesn't know, and the fragment check below
        # catches anything BPF-related that drops with it.
        tarball_sha256=19b31956d229b5b9ca5671fa1c74320179682a3d8d00fc86794114b21da86039
        base_config=kata-6.18.15.config
        extra_fragments=nbpf-pre-6.10.config
        ;;
    5.4.302)
        # Last 5.4 LTS; phase 2's "5.4" kernel. Built with Debian bullseye's
        # toolchain (gcc 10, pahole 1.20), contemporary with it. The container flavor
        # builds and boots, but Apple's agent can't start processes on it (see the
        # top of this file); the qemu flavor is the one that runs the tests.
        tarball_sha256=ae6a3207f12aa4d6cfb0fa793ec9da4a6fcdfdcb57d869d63d6b77e3a8c1423d
        base_config=kata-6.18.15.config
        extra_fragments=nbpf-pre-6.10.config
        builder_image=debian:bullseye-slim
        ;;
    *)
        echo "error: no pinned sha256/base config for kernel $kernel_version; add it to $0" >&2
        exit 1
        ;;
esac

case "$flavor" in
    container)
        arch=aarch64 image=arch/arm64/boot/Image make_target=Image out_name=vmlinux
        ;;
    qemu)
        # The kernel's own defaults plus its KVM guest config (`make kvmconfig`
        # before 5.10, `make kvm_guest.config` after) instead of a checked-in base.
        base_config=@x86-defconfig-kvm
        extra_fragments="$extra_fragments qemu-x86.config"
        arch=x86_64 image=arch/x86/boot/bzImage make_target=bzImage out_name=bzImage
        ;;
    *)
        echo "error: KERNEL_FLAVOR must be container or qemu, not '$flavor'" >&2
        exit 1
        ;;
esac

out_dir="${OUT_DIR:-$root/artifacts/kernel}"
mkdir -p "$out_dir"
mounts=(-v "$root":/src:ro -v "$(cd "$out_dir" && pwd)":/out)
if [ -n "${DOWNLOAD_CACHE:-}" ]; then
    mkdir -p "$DOWNLOAD_CACHE"
    mounts+=(-v "$(cd "$DOWNLOAD_CACHE" && pwd)":/cache)
fi

resources=()
if [ "$CONTAINER_RUNTIME" = container ]; then
    # Apple's `container` gives each VM 1 GiB by default; linking a vmlinux with full
    # debug info (needed for BTF) takes more.
    resources=(-c "${KERNEL_BUILD_CPUS:-$(sysctl -n hw.ncpu)}" -m "${KERNEL_BUILD_MEMORY:-4G}")
fi

exec "$CONTAINER_RUNTIME" run --rm -i ${resources[@]+"${resources[@]}"} "${mounts[@]}" \
    -e KV="$kernel_version" -e SHA="$tarball_sha256" -e BASE="$base_config" \
    -e EXTRA_FRAGMENTS="$extra_fragments" \
    -e ARCH_EXPECTED="$arch" -e IMAGE="$image" -e MAKE_TARGET="$make_target" \
    -e OUT_NAME="$out_name" \
    -e CONFIG_ONLY="${CONFIG_ONLY:-}" \
    "$builder_image" bash -s <<'EOF'
set -euo pipefail

if [ "$(uname -m)" != "$ARCH_EXPECTED" ]; then
    echo "error: this flavor builds a $ARCH_EXPECTED kernel natively; the container is $(uname -m)" >&2
    exit 1
fi

# dwarves = pahole, which DEBUG_INFO_BTF needs both at configure and link time.
install_toolchain() {
    apt-get update -qq >/dev/null &&
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        bc bison build-essential ca-certificates cpio curl dwarves flex kmod libelf-dev \
        libssl-dev python3 xz-utils >/dev/null
}
if ! install_toolchain; then
    # Old builder images (bullseye for 5.4) outlive their release's support, and
    # the release moves to archive.debian.org. In between, deb.debian.org kept
    # listing bullseye-security updates whose files were already gone (404). The
    # security suite can't simply be dropped: the image itself ships packages from
    # it, so the point-release -dev packages that must match them exactly wouldn't
    # install. So point every source, security included, at the archive. Its Release
    # files are past their Valid-Until, so don't check that. Only the one-line
    # sources.list format is edited; deb822 images (trixie and later) are current
    # and never get here.
    echo "apt install failed; retrying via archive.debian.org" >&2
    sed -i -e 's|deb.debian.org|archive.debian.org|g' \
           -e 's|security.debian.org|archive.debian.org|g' /etc/apt/sources.list
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99archive
    install_toolchain
fi

tarball="linux-$KV.tar.xz"
mkdir -p /build && cd /build
if [ -f "/cache/$tarball" ]; then
    cp "/cache/$tarball" .
else
    curl -fsSL --retry 3 -o "$tarball" "https://cdn.kernel.org/pub/linux/kernel/v${KV%%.*}.x/$tarball"
fi
echo "$SHA  $tarball" | sha256sum -c --quiet
if [ -d /cache ] && [ ! -f "/cache/$tarball" ]; then cp "$tarball" /cache/; fi
tar -xJf "$tarball"
cd "linux-$KV"

fragments=(/src/eng/kernel/nbpf.config)
for extra in $EXTRA_FRAGMENTS; do fragments+=("/src/eng/kernel/$extra"); done
if [ "$BASE" = @x86-defconfig-kvm ]; then
    make -s defconfig
    make -s kvm_guest.config 2>/dev/null || make -s kvmconfig
    base=.config
else
    base="/src/eng/kernel/$BASE"
fi
scripts/kconfig/merge_config.sh -m "$base" "${fragments[@]}" >/dev/null
make -s olddefconfig

missing=0
while IFS= read -r line; do
    if ! grep -qxF -- "$line" .config; then
        name="${line%%=*}"
        echo "error: $line did not survive olddefconfig; final .config has: $(grep -E "^(# )?$name[= ]" .config || echo '(absent)')" >&2
        missing=1
    fi
done < <(grep -hE '^CONFIG_' "${fragments[@]}")
[ "$missing" = 0 ] || exit 1

suffix="$KV-nbpf"
cp .config "/out/config-$suffix"
if [ -n "$CONFIG_ONLY" ]; then
    echo "config OK: /out/config-$suffix"
    exit 0
fi

make -s -j"$(nproc)" "$MAKE_TARGET"
cp "$IMAGE" "/out/$OUT_NAME-$suffix"
cd /out
sha256sum "$OUT_NAME-$suffix" "config-$suffix" > SHA256SUMS
cat SHA256SUMS
EOF
