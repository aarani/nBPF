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
eng/container-runtime.sh  Picks Apple `container` (macOS) or docker for the above
eng/gen-fixtures.sh    Regenerates the checked-in test fixtures via clang
eng/gen-kernel-btf.sh  Regenerates the minimized 5.4/6.8 kernel BTF fixtures
eng/build-container-kernel.sh  Builds a BPF-capable arm64 kernel for Apple `container`
eng/kernel/            Its base config (Apple's default kernel) and BPF fragment
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

- **CO-RE engine** — `Nbpf.Btf.CoreReloResolver` resolves all thirteen
  relocation kinds against target BTF with libbpf's `relo_core.c` semantics:
  access-spec parsing, flavor-stripped candidate matching (with the
  ambiguity check across agreeing candidates), anonymous-member traversal,
  bitfield load computation, and the exists-probe-zero vs. poison split for
  missing targets. `Nbpf.Core.ObjectFile.CoreRelocator.Patch` applies a
  resolved value to the right instruction field (memory offset, ALU
  immediate, or two-slot `ld_imm64`), validating baked-in values and
  poisoning unresolvable instructions with the invalid-call marker.
  `Nbpf.Core.KernelBtf` loads `/sys/kernel/btf/vmlinux`, and
  `BpfObject.Load` applies it all automatically — kernel BTF is the default
  relocation target, or pass a `BpfLoadOptions` with an explicit graph for
  tests and cross-kernel tooling. Verified against blob-built type graphs
  case by case, a dedicated CO-RE clang fixture (`core-sample.bpf.c`), and
  end-to-end loads in the container tests, including the poison path (a
  wrong-target load is rejected by the verifier exactly because the
  unguarded access was poisoned). Note: the two tests needing the *running*
  kernel's BTF skip under Docker Desktop's linuxkit kernel and Apple
  `container`'s default kernel (neither has `CONFIG_DEBUG_INFO_BTF`); CI's
  Ubuntu kernel covers them, and so does the kernel from
  `eng/build-container-kernel.sh` locally (see Testing).

- **Cross-kernel resolution, offline** — one object
  (`core-kernels.bpf.c`) resolved against the real vmlinux BTF of Ubuntu's
  5.4.0-26 and 6.8.0-31 kernels, with expectations taken from `bpftool btf
  dump` of the full BTF: `task_struct` offsets and size, the `state` →
  `__state` rename via a `___old` flavor, `bpf_ringbuf` / `BPF_MAP_TYPE_RINGBUF`
  existence, and a real bitfield (`sk_buff.pkt_type`, nested in anonymous
  members on 6.8). The kernel BTF is minimized with `bpftool gen
  min_core_btf` to a few hundred bytes per kernel and committed, so these run
  on any host. A container test also loads the object relocated for each
  kernel to check that the side of the rename that kernel lacks is dead code
  to the verifier.

Still to come in phase 2: the live half of the exit criterion (booting 5.4
and 6.8 and loading there) and feature probes; extern resolution (kconfig,
kfuncs) also remains from [DESIGN.md §4.4](DESIGN.md#44-relocations). Not yet started: attachment beyond
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
change any of the `*.bpf.c` sources, regenerate them with `eng/gen-fixtures.sh` (needs
clang with a BPF target and `llvm-objcopy`) and commit the result. After a change
to `core-kernels.bpf.c`, also rerun `eng/gen-kernel-btf.sh`. It downloads the
pinned 5.4 (BTFHub) and 6.8 (Ubuntu kernel package) BTF, checks their sha256,
and minimizes them against the new object in a Debian container. Set
`DOWNLOAD_CACHE=<dir>` to avoid re-downloading.

The `Nbpf.Core` tests exercise real `bpf(2)` syscalls and need `CAP_BPF` (or
`CAP_SYS_ADMIN`) on a Linux kernel, so they won't run on macOS/Windows hosts
directly — they skip rather than fail. Run them in a privileged Linux
container instead:

```bash
eng/test-linux.sh
```

This runs `dotnet test` inside `mcr.microsoft.com/dotnet/sdk:10.0`, with NuGet
packages cached in a named volume. On macOS it uses Apple's `container` CLI
(`--cap-add ALL`; every container is its own VM, and `container system start`
must have run). Elsewhere, including CI, it uses `docker run --privileged`. Set
`CONTAINER_RUNTIME=docker|container` to choose.

Apple's default kernel has `bpf(2)` but no `CONFIG_FTRACE`/`KPROBES` and no
`CONFIG_DEBUG_INFO_BTF`, so tracepoint programs fail to load with `EINVAL` and
`/sys/kernel/btf/vmlinux` is absent. Under it, the object-load tests
(`ObjectLoadTests`, the `CoreObjectLoadTests` loads) fail and the two
kernel-BTF tests skip, while maps, ring buffers and hand-assembled programs
pass. CI's Ubuntu kernel runs the full suite.

To run everything locally, boot a BPF-capable kernel instead (`container run
-k`) by setting `CONTAINER_KERNEL`:

```bash
run=$(gh run list -R aarani/nBPF -w container-kernel.yml -b main -s success -L 1 --json databaseId -q '.[0].databaseId')
```

```bash
gh run download "$run" -R aarani/nBPF -n container-kernel-6.18.64 -D artifacts/kernel
```

```bash
CONTAINER_KERNEL=artifacts/kernel/vmlinux-6.18.64-nbpf eng/test-linux.sh
```

That kernel is Apple's default kernel config (`eng/kernel/kata-6.18.15.config`)
plus the BPF and tracing options in `eng/kernel/nbpf.config`, built from a pinned
kernel.org tarball by `eng/build-container-kernel.sh`. Prebuilt distro kernels
don't work here: they ship vsock, virtiofs and overlayfs as modules, and
`container` boots without an initramfs. Building takes a few GB of RAM, so it
runs in CI: the **Container kernel** workflow (`.github/workflows/container-kernel.yml`,
native arm64 runner) builds it whenever those files change, or when run
manually, and uploads it as the `container-kernel-<version>` workflow artifact
downloaded above. Artifacts expire after 90 days; rerun the workflow from the
Actions tab to get a fresh one. To build locally anyway, run
`eng/build-container-kernel.sh` (output in `artifacts/kernel/`, git-ignored).
After editing the fragment, `CONFIG_ONLY=1 eng/build-container-kernel.sh` checks
in about a minute, without compiling, that every option in it survives `make
olddefconfig`.

Extra arguments are forwarded to `dotnet test`, e.g.:

```bash
eng/test-linux.sh --filter FullyQualifiedName~RingBufTests
```

## License

GPL-3.0 — see [LICENSE](LICENSE).
