# nBPF

A pure-managed eBPF loader and toolchain for C# — no libbpf, no native
dependencies, NativeAOT-friendly. Issues `bpf(2)` directly and (eventually)
parses ELF/BTF itself, in the spirit of [`cilium/ebpf`](https://github.com/cilium/ebpf)
for Go.

The long-term goal is a compile-time, type-provider-style surface generated
from kernel BTF, so map names, program names, tracepoints, and event struct
layouts are all real C# types instead of strings. See [DESIGN.md](DESIGN.md)
for the full plan, rationale, and phasing.

> **Status:** early. Phases 0 and 1 are done — see
> [Current status](#current-status) below. Everything past that is design,
> not code.

## Requirements

- .NET 10 SDK
- Linux 5.4+ at runtime (the loader talks to the kernel via `bpf(2)`)
- `CAP_BPF`/`CAP_SYS_ADMIN` (and `CAP_PERFMON` on 5.8+) to load and run
  programs

## Repository layout

```
src/Nbpf.Core/        Core library: syscalls, program/map wrappers, ring buffer
  Native/                bpf(2) syscall layer, bpf_attr structs, errno mapping
  Insns/                 BPF instruction/assembler types
  Maps/                  Map CRUD wrappers
  RingBuf/               Ring buffer consumer (mmap + epoll)
  ObjectFile/            .bpf.o loader: map planning, relocations, BpfObject
src/Nbpf.Btf/         BTF parser and type graph (netstandard2.0)
src/Nbpf.Elf/         ELF64 reader for BPF objects (netstandard2.0)
src/Shared/           Small source files linked into the netstandard2.0 projects
tests/Nbpf.Core.Tests/ xUnit tests (require a Linux kernel with BPF support)
tests/Nbpf.Btf.Tests/  xUnit tests for the BTF parser (run on any host)
tests/Nbpf.Elf.Tests/  xUnit tests for the ELF reader (run on any host)
eng/test-linux.sh      Runs the Linux-only tests in a privileged container
eng/gen-fixtures.sh    Regenerates the checked-in test fixtures via clang
```

`Nbpf.Btf` and `Nbpf.Elf` target netstandard2.0 rather than net10.0 on purpose.
The Roslyn source generator planned in
[DESIGN.md §6.6](DESIGN.md#66-generator-engineering-constraints) needs both —
it reads a `.bpf.o` and parses the BTF inside it — and a generator cannot
reference a net10.0 assembly. Note this puts the ELF reader in its own package
rather than in `Nbpf.Core` as
[DESIGN.md §10](DESIGN.md#10-package-layout) originally sketched; `Nbpf.Core`
references both and hosts the relocation engine on top of them.

## Current status

Phase 0 of the plan in [DESIGN.md](DESIGN.md#11-phasing) is complete:

- `bpf(2)` syscall layer with typed exceptions for common `errno`s
- Map create/read/update/delete
- Loading a hand-assembled instruction array (`BpfProgram.Load`)
- `BPF_PROG_TEST_RUN` support
- Ring buffer consumer (mmap + epoll)

Phase 1 is complete:

- **BTF parser** (`Nbpf.Btf`) — full type graph for all 19 `BTF_KIND_*` kinds,
  including bitfield members, signed/unsigned enums, `ENUM64`, datasecs, and
  decl/type tags. Handles both endiannesses and rejects malformed input with
  `BtfFormatException` rather than misparsing it. Verified against a checked-in
  `.BTF` section produced by a real clang.

- **ELF reader** (`Nbpf.Elf`) — ELF64 relocatable objects: sections with their
  contents, symbols, and relocations already resolved back to the section they
  apply to. Verified against a checked-in clang-produced object, with the
  expectations taken from `llvm-readelf`. Malformed input yields
  `ElfFormatException` and never a raw index error, which is covered by
  truncating and corrupting the fixture across several hundred cases.

- **Object loader** (`Nbpf.Core.ObjectFile.BpfObject`) — loads a clang-compiled
  `.bpf.o` end to end: creates the BTF-defined `.maps` maps, materializes
  `.rodata`/`.data`/`.bss` as single-entry array maps sized from the ELF
  (freezing `.rodata` so the verifier treats it as constant), applies map,
  global-data, and subprogram-call relocations, and loads every program. The
  relocation engine itself is pure and tested instruction-by-instruction on any
  host; the end-to-end load — real clang output accepted by the verifier, the
  phase 1 exit criterion — runs in the container tests.

Phase 2 (CO-RE) is in progress:

- **`.BTF.ext` parser** (`Nbpf.Btf.BtfExtReader`) — func info, line info, and
  CO-RE relocation records, grouped per ELF section, with strings resolved
  through the companion `.BTF` section's string table. Handles both the legacy
  24-byte and the modern 32-byte header, skips the unknown tail of oversized
  records from newer producers, and rejects malformed input (zero-record
  sections, undersized/misaligned record sizes, unknown relocation kinds) with
  `BtfFormatException`. Verified against the `.BTF.ext`/`.BTF` pair dumped from
  the checked-in clang object.

Still to come in phase 2: the CO-RE relocation engine itself, vmlinux BTF, and
feature probes; extern resolution (kconfig, kfuncs) also remains from
[DESIGN.md §4.4](DESIGN.md#44-relocations). Not yet started: attachment beyond
test-run, and all of the source-generator and design-time tooling described in
DESIGN.md. There is no BPF program compiler here — programs are either
hand-assembled or loaded from an already-compiled object.

## Building

```bash
dotnet build
```

## Testing

The BTF and ELF tests are pure parsing with no syscalls, so they run anywhere:

```bash
dotnet test tests/Nbpf.Btf.Tests tests/Nbpf.Elf.Tests
```

Their fixtures are checked in, so clang is not needed to run them. If you
change either `sample.bpf.c`, regenerate them with `eng/gen-fixtures.sh` (needs
clang with a BPF target and `llvm-objcopy`) and commit the result.

The `Nbpf.Core` tests exercise real `bpf(2)` syscalls and need `CAP_BPF` (or
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
