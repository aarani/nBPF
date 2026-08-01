#!/usr/bin/env bash
# Regenerates the checked-in test fixtures from their C sources.
#
# Fixtures are committed so the test suites run anywhere, including hosts without clang.
# Rerun this only when a sample.bpf.c changes, and commit the result.
#
#   tests/Ebpf.Btf.Tests/Fixtures/sample.btf     just the .BTF section
#   tests/Ebpf.Elf.Tests/Fixtures/sample.bpf.o   the whole relocatable object
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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
compile() {
    "$clang" -target bpf -O2 -g -c "$1" -o "$2"
}

# The BTF fixture keeps only the .BTF section, so those tests need no ELF reader.
btf_src="$root/tests/Ebpf.Btf.Tests/Fixtures/sample.bpf.c"
compile "$btf_src" "$tmp/btf-sample.o"
"$objcopy" --dump-section .BTF="$root/tests/Ebpf.Btf.Tests/Fixtures/sample.btf" "$tmp/btf-sample.o"

# The ELF fixture is the whole object, relocations and all.
elf_src="$root/tests/Ebpf.Elf.Tests/Fixtures/sample.bpf.c"
compile "$elf_src" "$root/tests/Ebpf.Elf.Tests/Fixtures/sample.bpf.o"

for f in "$root/tests/Ebpf.Btf.Tests/Fixtures/sample.btf" \
         "$root/tests/Ebpf.Elf.Tests/Fixtures/sample.bpf.o"; do
    echo "wrote ${f#"$root/"} ($(wc -c < "$f" | tr -d ' ') bytes)"
done
