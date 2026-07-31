# nBPF

A pure-managed eBPF loader and toolchain for C# — no libbpf, no native
dependencies, NativeAOT-friendly. Issues `bpf(2)` directly and (eventually)
parses ELF/BTF itself, in the spirit of [`cilium/ebpf`](https://github.com/cilium/ebpf)
for Go.

The long-term goal is a compile-time, type-provider-style surface generated
from kernel BTF, so map names, program names, tracepoints, and event struct
layouts are all real C# types instead of strings. See [DESIGN.md](DESIGN.md)
for the full plan, rationale, and phasing.

> **Status:** early. Phase 0 is done and phase 1 is underway — see
> [Current status](#current-status) below. Everything past that is design,
> not code.

## Requirements

- .NET 10 SDK
- Linux 5.4+ at runtime (the loader talks to the kernel via `bpf(2)`)
- `CAP_BPF`/`CAP_SYS_ADMIN` (and `CAP_PERFMON` on 5.8+) to load and run
  programs

## Repository layout

```
src/Ebpf.Core/        Core library: syscalls, program/map wrappers, ring buffer
  Native/                bpf(2) syscall layer, bpf_attr structs, errno mapping
  Insns/                 BPF instruction/assembler types
  Maps/                  Map CRUD wrappers
  RingBuf/               Ring buffer consumer (mmap + epoll)
src/Ebpf.Btf/         BTF parser and type graph (netstandard2.0, shared with
                        the future source generator)
tests/Ebpf.Core.Tests/ xUnit tests (require a Linux kernel with BPF support)
tests/Ebpf.Btf.Tests/  xUnit tests for the BTF parser (run on any host)
eng/test-linux.sh      Runs the Linux-only tests in a privileged container
eng/gen-btf-fixture.sh Regenerates the checked-in BTF test fixture via clang
```

`Ebpf.Btf` targets netstandard2.0 rather than net10.0 on purpose: the Roslyn
source generator planned in
[DESIGN.md §6.6](DESIGN.md#66-generator-engineering-constraints) will need this
same parser and cannot reference a net10.0 assembly.

## Current status

Phase 0 of the plan in [DESIGN.md](DESIGN.md#11-phasing) is complete:

- `bpf(2)` syscall layer with typed exceptions for common `errno`s
- Map create/read/update/delete
- Loading a hand-assembled instruction array (`BpfProgram.Load`)
- `BPF_PROG_TEST_RUN` support
- Ring buffer consumer (mmap + epoll)

Phase 1 is in progress. Done so far:

- **BTF parser** (`Ebpf.Btf`) — full type graph for all 19 `BTF_KIND_*` kinds,
  including bitfield members, signed/unsigned enums, `ENUM64`, datasecs, and
  decl/type tags. Handles both endiannesses and rejects malformed input with
  `BtfFormatException` rather than misparsing it. Verified against a checked-in
  `.BTF` section produced by a real clang.

Still to do in phase 1: the ELF reader, and map / global-data / subprogram
relocations. Not yet started: CO-RE, attachment beyond test-run, and all of the
source-generator and design-time tooling described in DESIGN.md. There is no
BPF program compiler here — programs are currently either hand-assembled or
loaded from an already-compiled object.

## Building

```bash
dotnet build
```

## Testing

The BTF parser tests are pure parsing with no syscalls, so they run anywhere:

```bash
dotnet test tests/Ebpf.Btf.Tests
```

Their fixture (`tests/Ebpf.Btf.Tests/Fixtures/sample.btf`) is checked in, so
clang is not needed to run them. If you change `sample.bpf.c`, regenerate it
with `eng/gen-btf-fixture.sh` (needs clang with a BPF target and
`llvm-objcopy`) and commit the result.

The `Ebpf.Core` tests exercise real `bpf(2)` syscalls and need `CAP_BPF` (or
`CAP_SYS_ADMIN`) on a Linux kernel, so they won't run on macOS/Windows hosts
directly — they skip rather than fail. Run them in a privileged Linux
container instead:

```bash
eng/test-linux.sh
```

This runs `dotnet test` inside `mcr.microsoft.com/dotnet/sdk:10.0` via
`docker run --privileged`, with NuGet packages cached in a named volume.
Extra arguments are forwarded to `dotnet test`, e.g.:

```bash
eng/test-linux.sh --filter FullyQualifiedName~RingBufTests
```

## License

GPL-3.0 — see [LICENSE](LICENSE).
