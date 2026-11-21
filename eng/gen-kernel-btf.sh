#!/usr/bin/env bash
# Regenerates the minimized kernel BTF fixtures the cross-kernel CO-RE tests resolve
# against — the "same binary on 5.4 and 6.8" half of phase 2, checked offline.
#
#   tests/Nbpf.Btf.Tests/Fixtures/vmlinux-5.4.0-26-generic.min.btf   Ubuntu 20.04 GA kernel
#   tests/Nbpf.Btf.Tests/Fixtures/vmlinux-6.8.0-31-generic.min.btf   Ubuntu 24.04 GA kernel
#
# Full vmlinux BTF is megabytes per kernel, so what gets committed is bpftool's
# `gen min_core_btf` output: only the types (and members) core-kernels.bpf.o's CO-RE
# relocations touch, with their real offsets and sizes. Rerun this after
# eng/gen-fixtures.sh whenever core-kernels.bpf.c changes, and commit the result.
#
# Sources, pinned by sha256:
#   5.4: BTFHub's archive (Ubuntu 20.04's stock kernel shipped without vmlinux BTF)
#   6.8: Ubuntu's own kernel package; the .BTF section is cut out of the vmlinux
#        decompressed from its bzImage
#
# Runs in a Debian container (for bpftool) via eng/container-runtime.sh — Apple's
# `container` on macOS, docker elsewhere — and needs network access.
# Set KEEP_FULL_BTF=<dir> to also keep the full BTF blobs, e.g. to inspect them with
# `bpftool btf dump file <blob>` when updating the tests' expected values.
# Set DOWNLOAD_CACHE=<dir> to reuse (and fill) a directory of the downloads above.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/eng/container-runtime.sh"
obj="tests/Nbpf.Elf.Tests/Fixtures/core-kernels.bpf.o"
[ -f "$root/$obj" ] || { echo "error: $obj missing; run eng/gen-fixtures.sh first" >&2; exit 1; }

keep=()
if [ -n "${KEEP_FULL_BTF:-}" ]; then
    mkdir -p "$KEEP_FULL_BTF"
    keep=(-v "$(cd "$KEEP_FULL_BTF" && pwd)":/keep)
fi
if [ -n "${DOWNLOAD_CACHE:-}" ]; then
    mkdir -p "$DOWNLOAD_CACHE"
    keep+=(-v "$(cd "$DOWNLOAD_CACHE" && pwd)":/cache)
fi

exec "$CONTAINER_RUNTIME" run --rm -i \
    -v "$root":/src -w /src ${keep[@]+"${keep[@]}"} \
    -e OBJ="$obj" \
    debian:trixie-slim bash -s <<'EOF'
set -euo pipefail

apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    bpftool ca-certificates curl python3 xz-utils zstd >/dev/null

work="$(mktemp -d)"
out=tests/Nbpf.Btf.Tests/Fixtures

fetch() { # url sha256 dest
    local cached="/cache/$(basename "$1")"
    if [ -f "$cached" ]; then
        cp "$cached" "$3"
    else
        curl -fsSL --retry 3 -o "$3" "$1"
        if [ -d /cache ]; then cp "$3" "$cached"; fi
    fi
    echo "$2  $3" | sha256sum -c --quiet - || { echo "error: checksum mismatch for $1" >&2; exit 1; }
}

# --- 5.4: BTFHub ships the raw BTF blob inside a tarball.
k54=5.4.0-26-generic
fetch "https://github.com/aquasecurity/btfhub-archive/raw/main/ubuntu/20.04/x86_64/$k54.btf.tar.xz" \
      f5435aba2a2f85c289dec4c52f7f3f01f7139f3143561e9c1b02ced174514b9d \
      "$work/$k54.btf.tar.xz"
tar -xJf "$work/$k54.btf.tar.xz" -C "$work"
mv "$work/$k54.btf" "$work/$k54.full.btf"

# --- 6.8: the bzImage's payload is a compressed vmlinux ELF, and .BTF is an allocated
# section, so it survives the stripping the boot image goes through.
k68=6.8.0-31-generic
fetch "http://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-image-unsigned-${k68}_6.8.0-31.31_amd64.deb" \
      35115ceb5ddc1e73034a73d6b064b9c6d38c534f20279fd7229c510515b931d8 \
      "$work/$k68.deb"
dpkg-deb -x "$work/$k68.deb" "$work/$k68"
python3 -I - "$work/$k68/boot/vmlinuz-$k68" "$work/$k68.full.btf" <<'PY'
# What scripts/extract-vmlinux does — find a compressed stream that inflates to an ELF —
# then cut that ELF's .BTF section out by hand (the container's binutils only reads
# its own architecture, and this vmlinux is x86-64).
import struct, subprocess, sys

def vmlinux(image):
    codecs = [(b"\x28\xb5\x2f\xfd", ["zstd", "-dcq"]),
              (b"\xfd7zXZ\x00", ["xz", "-dcq"]),
              (b"\x1f\x8b\x08", ["gzip", "-dcq"])]
    for magic, cmd in codecs:
        pos = image.find(magic)
        while pos != -1:
            out = subprocess.run(cmd, input=image[pos:], capture_output=True).stdout
            if out[:4] == b"\x7fELF":
                return out
            pos = image.find(magic, pos + 1)
    sys.exit("no compressed vmlinux found in " + sys.argv[1])

def section(elf, wanted):
    assert elf[4] == 2 and elf[5] == 1, "expected a little-endian ELF64"
    shoff, = struct.unpack_from("<Q", elf, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", elf, 0x3A)
    def header(i):  # -> (name offset, file offset, size)
        name, _, _, _, off, size = struct.unpack_from("<IIQQQQ", elf, shoff + i * shentsize)
        return name, off, size
    _, stroff, _ = header(shstrndx)
    for i in range(shnum):
        name, off, size = header(i)
        if elf[stroff + name:].split(b"\0", 1)[0] == wanted:
            return elf[off:off + size]
    sys.exit("vmlinux has no %s section" % wanted.decode())

open(sys.argv[2], "wb").write(section(vmlinux(open(sys.argv[1], "rb").read()), b".BTF"))
PY

for k in "$k54" "$k68"; do
    if [ -d /keep ]; then cp "$work/$k.full.btf" /keep/; fi
    bpftool gen min_core_btf "$work/$k.full.btf" "$out/vmlinux-$k.min.btf" "$OBJ"
    echo "wrote $out/vmlinux-$k.min.btf ($(wc -c < "$out/vmlinux-$k.min.btf") bytes," \
         "from $(wc -c < "$work/$k.full.btf") bytes of full BTF)"
done
EOF
