# nBPF

A pure-managed eBPF loader and toolchain for C# — no libbpf, no native
dependencies, NativeAOT-friendly. Issues `bpf(2)` directly and (eventually)
parses ELF/BTF itself, in the spirit of [`cilium/ebpf`](https://github.com/cilium/ebpf)
for Go.

The long-term goal is a compile-time, type-provider-style surface generated
from kernel BTF, so map names, program names, tracepoints, and event struct
layouts are all real C# types instead of strings. See [DESIGN.md](DESIGN.md)
for the full plan, rationale, and phasing.

> **Status:** early. Phase 0 is done — see [Current status](#current-status)
> below. Everything past that is design, not code.

## Requirements

- .NET 10 SDK
- Linux 5.4+ at runtime (the loader talks to the kernel via `bpf(2)`)
- `CAP_BPF`/`CAP_SYS_ADMIN` (and `CAP_PERFMON` on 5.8+) to load and run
  programs

## Repository layout

```
src/Ebpf.Core/       Core library: syscalls, program/map wrappers, ring buffer
  Native/               bpf(2) syscall layer, bpf_attr structs, errno mapping
  Insns/                BPF instruction/assembler types
  Maps/                 Map CRUD wrappers
  RingBuf/              Ring buffer consumer (mmap + epoll)
tests/Ebpf.Core.Tests/ xUnit tests (require a Linux kernel with BPF support)
eng/test-linux.sh      Runs the test suite in a privileged Linux container
```

## Current status

Phase 0 of the plan in [DESIGN.md](DESIGN.md#11-phasing) is complete:

- `bpf(2)` syscall layer with typed exceptions for common `errno`s
- Map create/read/update/delete
- Loading a hand-assembled instruction array (`BpfProgram.Load`)
- `BPF_PROG_TEST_RUN` support
- Ring buffer consumer (mmap + epoll)

Not yet implemented: ELF/BTF parsing, relocations, CO-RE, attachment beyond
test-run, and all of the source-generator/design-time tooling described in
DESIGN.md. There is no BPF program compiler here — programs are currently
either hand-assembled or loaded from an already-compiled object.

## Building

```bash
dotnet build
```

## Testing

The test suite exercises real `bpf(2)` syscalls and needs `CAP_BPF` (or
`CAP_SYS_ADMIN`) on a Linux kernel, so it won't run on macOS/Windows hosts
directly. Run it in a privileged Linux container instead:

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
