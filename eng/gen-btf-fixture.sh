#!/usr/bin/env bash
# Regenerates the BTF parser test fixture from its C source.
#
# The fixture is checked in so the test suite runs anywhere, including hosts without
# clang. Rerun this only when Fixtures/sample.bpf.c changes, and commit the result.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixtures="$root/tests/Ebpf.Btf.Tests/Fixtures"

clang="${CLANG:-clang}"
objcopy="${LLVM_OBJCOPY:-llvm-objcopy}"

for tool in "$clang" "$objcopy"; do
    command -v "$tool" >/dev/null || {
        echo "error: $tool not found (set CLANG / LLVM_OBJCOPY to override)" >&2
        exit 1
    }
done

"$clang" --print-targets | grep -q '^ *bpf ' || {
    echo "error: $clang has no BPF target" >&2
    exit 1
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# -g is mandatory: no debug info means no BTF section at all.
"$clang" -target bpf -O2 -g -c "$fixtures/sample.bpf.c" -o "$tmp/sample.bpf.o"
"$objcopy" --dump-section .BTF="$fixtures/sample.btf" "$tmp/sample.bpf.o"

echo "wrote $fixtures/sample.btf ($(wc -c < "$fixtures/sample.btf" | tr -d ' ') bytes)"
