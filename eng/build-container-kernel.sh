#!/usr/bin/env bash
# Builds an arm64 Linux kernel that Apple's `container` can boot (`container run -k`)
# with everything the nBPF test suite needs: tracepoint/kprobe programs, the BPF JIT,
# /sys/kernel/btf/vmlinux, AF_XDP and tc BPF. Apple's default (Kata) kernel has none of
# those beyond BPF_SYSCALL; see eng/container-runtime.sh.
#
#   config = eng/kernel/kata-<ver>.config  Apple's default kernel config, verbatim
#                                          (it boots: virtio, vsock, virtiofs built in,
#                                          no modules, no initramfs needed)
#          + eng/kernel/nbpf.config        the BPF/tracing options on top
#          + eng/kernel/nbpf-pre-6.10.config  for kernels before 6.10 only:
#                                          module support, which BPF_JIT and
#                                          KPROBES depend on there
#
# Every option in the fragments is checked against the final .config, so an option
# that `make olddefconfig` drops for an unmet dependency fails the build instead of
# producing a kernel that quietly lacks it.
#
# Output, in OUT_DIR (default artifacts/kernel/, git-ignored):
#   vmlinux-<ver>-nbpf   uncompressed arm64 Image (named like Apple's own kernels)
#   config-<ver>-nbpf    the final .config
#   SHA256SUMS
#
# Then: CONTAINER_KERNEL=artifacts/kernel/vmlinux-<ver>-nbpf eng/test-linux.sh
#
# The build normally runs in CI (.github/workflows/container-kernel.yml, on a native
# arm64 runner, which uploads the result as a workflow artifact); locally it needs
# a machine with a few GB of RAM to spare. It runs in a Debian container via
# eng/container-runtime.sh and needs network access.
#
#   KERNEL_VERSION=<x.y.z>  kernel to build (default below); each version needs a
#                           pinned sha256 and a base config in the table below
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

# version -> sha256 of linux-<version>.tar.xz (from kernel.org's signed
# sha256sums.asc) and the base config it starts from. Older kernels (5.4, 6.8 for
# phase 2's cross-kernel run) need their own base config and possibly an older
# builder image, since current gcc/pahole may not build them.
extra_fragments=""  # space-separated, merged after nbpf.config
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
    *)
        echo "error: no pinned sha256/base config for kernel $kernel_version; add it to $0" >&2
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
    -e CONFIG_ONLY="${CONFIG_ONLY:-}" \
    debian:trixie-slim bash -s <<'EOF'
set -euo pipefail

if [ "$(uname -m)" != aarch64 ]; then
    echo "error: this builds an arm64 kernel natively; the container is $(uname -m)" >&2
    exit 1
fi

apt-get update -qq >/dev/null
# dwarves = pahole, which DEBUG_INFO_BTF needs both at configure and link time.
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    bc bison build-essential ca-certificates cpio curl dwarves flex kmod libelf-dev \
    libssl-dev python3 xz-utils >/dev/null

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
scripts/kconfig/merge_config.sh -m "/src/eng/kernel/$BASE" "${fragments[@]}" >/dev/null
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

make -s -j"$(nproc)" Image
cp arch/arm64/boot/Image "/out/vmlinux-$suffix"
cd /out
sha256sum "vmlinux-$suffix" "config-$suffix" > SHA256SUMS
cat SHA256SUMS
EOF
