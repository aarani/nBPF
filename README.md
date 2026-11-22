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
  Features/              Kernel feature probes and the fallbacks built on them
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
eng/build-kernel.sh    Builds BPF-capable kernels: arm64 for Apple `container`, x86_64 for QEMU
eng/kernel/            Their base config (Apple's default kernel) and config fragments
eng/qemu-test.sh       Boots a kernel in QEMU and runs the Linux tests inside it (CI)
eng/qemu-init.sh       The QEMU guest's init: mounts, runs the tests, powers off
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

Phase 2 (CO-RE) is complete. Its exit criterion, the same binary running on 5.4 and
6.8 unmodified, holds on booted kernels:

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
  `eng/build-kernel.sh` locally (see Testing).

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

- **Feature probes** (`Nbpf.Core.KernelFeatures`) — answers whether the running
  kernel has a map type, a program type, or a helper for a given program type.
  Each probe creates or loads something tiny, and answers are cached per
  process. A helper counts as missing only when the verifier refuses it by
  name; kernels have worded that three ways, and all three are recognized.
  The probes feed two things:
  - Clear errors. A map create or program load that fails because something
    is missing throws `BpfFeatureUnsupportedException`, naming the feature and
    the release that introduced it (e.g. `BPF_MAP_TYPE_RINGBUF`, 5.8), instead
    of a bare `EINVAL`.
  - The first fallback. Before 5.5, `bpf_probe_read_kernel`/`_user` and their
    `_str` variants don't exist, so `BpfObject.Load` rewrites calls to them
    into the older `bpf_probe_read`/`bpf_probe_read_str`, as libbpf does. When
    neither exists it throws before loading.

  `BpfLoadOptions.Features` swaps in another set of answers, which is how the
  fallback is tested: the CO-RE sample loads through the real verifier while
  the loader believes it is on a pre-5.5 kernel. The Linux tests also skip by
  probed feature (`KernelFeatureFact`) rather than failing on kernels that
  lack it. Program types that need an attach target to load
  (`BPF_PROG_TYPE_TRACING`) can't be probed this way yet.

- **Live 6.8** — the same Linux suite, including the CO-RE load against the
  booted kernel's own BTF, passes on a 6.8.12 kernel under Apple `container`
  (83 of 83, none skipped).

- **Live 5.4** — on a 5.4.302 kernel booted in QEMU in CI (the **Live
  kernels** workflow), 75 tests pass and 8 skip, none fail. The skips are the
  probes reporting no `BPF_MAP_TYPE_RINGBUF` (5.8): the ring buffer tests and
  the phase 1 object loads, whose sample has a ring buffer map. Among the
  passes is the CO-RE load against 5.4's own BTF, going through the
  `bpf_probe_read_kernel` fallback on a kernel that really lacks the helper.
  The two kernels run on different architectures (6.8 arm64, 5.4 x86_64); the
  `.bpf.o` files are the same.

Also built, from [DESIGN.md §9](DESIGN.md#9-deployment-and-privileges): the
**RLIMIT_MEMLOCK bump** (`Nbpf.Core.MemlockLimit`). Before 5.11 the kernel charges
BPF maps and programs against that limit, 64 KiB by default. So, like libbpf, the
first map or program created raises it to unlimited, but only on kernels that
still charge it: they're the ones without `bpf_ktime_get_coarse_ns`, which arrived
with memcg accounting in 5.11. If the limit can't be raised, an `EPERM` says so
instead of blaming capabilities. Set `MemlockLimit.AutoRaise = false` first to
manage it yourself.

Phase 3 (attachment) has started, with XDP. So far only loading is done, not
attaching:

- `BpfObject.Load` recognizes XDP programs: `SEC("xdp")` exactly, or any
  `SEC("xdp/...")`. Look-alikes such as `xdp.frags`, which needs a load flag
  nBPF doesn't set yet, are rejected rather than loaded as plain XDP.
- The `xdp-drop.bpf.o` fixture drops and counts UDP traffic to one port. Its
  packet logic is checked through `BPF_PROG_TEST_RUN` with hand-built frames:
  - VLAN and QinQ tags
  - IPv4 options
  - fragments
  - truncated packets

  These tests pass on the 6.18 kernel under Apple `container`.

The fixture is compiled with `-mcpu=v2`, because clang 20 defaults to v3. On v3
the counter increment becomes an `atomic_fetch_add`, which only 5.12+ accepts.

Carried over from phase 2: the probes of
[DESIGN.md §4.5](DESIGN.md#45-feature-probes) that only matter once attachment
and kernel BTF loading exist (`bpf_link`, TCX, `kprobe_multi`, BTF kinds,
batch map ops), which land with that code. Extern resolution (kconfig, kfuncs)
from [DESIGN.md §4.4](DESIGN.md#44-relocations) is also still open. Not yet started: attachment beyond
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
`/sys/kernel/btf/vmlinux` is absent. Under it, the tests that need tracepoint
programs (the object loads, the probe_read fallback) and the two kernel-BTF
tests skip with the reason, while maps, ring buffers and hand-assembled
programs pass. CI's Ubuntu kernel runs the full suite.

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

The same works with `container-kernel-6.8.12` and `vmlinux-6.8.12-nbpf`, the 6.8
kernel phase 2's cross-kernel exit criterion boots.

Each kernel is Apple's default kernel config (`eng/kernel/kata-6.18.15.config`)
plus the BPF and tracing options in `eng/kernel/nbpf.config`, built from a pinned
kernel.org tarball by `eng/build-kernel.sh`. Kernels before 6.10 also
merge `eng/kernel/nbpf-pre-6.10.config`, which turns on module support: until
then, `BPF_JIT` and `KPROBES` depend on it. Prebuilt distro kernels
don't work here: they ship vsock, virtiofs and overlayfs as modules, and
`container` boots without an initramfs. Building takes a few GB of RAM, so it
runs in CI: the **Container kernel** workflow (`.github/workflows/container-kernel.yml`,
native arm64 runner) builds every pinned version on pushes to `main` that change
those files, or when run manually, and uploads each as a
`container-kernel-<version>` workflow artifact, as downloaded above. It doesn't run
on PRs: GitHub matches PR path filters against the whole PR, so every push would
rebuild every kernel. A manual run can name just the versions it needs:

```bash
gh workflow run container-kernel.yml -R aarani/nBPF -f kernels='["6.8.12"]'
```

Artifacts expire after 90 days; rerun the workflow from the Actions tab to get a
fresh one. To build locally anyway, run `eng/build-kernel.sh` (`KERNEL_VERSION`
picks the version; output in `artifacts/kernel/`, git-ignored). After editing a
fragment, `CONFIG_ONLY=1 eng/build-kernel.sh` checks in about a minute, without
compiling, that every option in it survives `make olddefconfig`.

### Older kernels, in QEMU (CI)

Apple's `container` can't run processes on kernels before 5.6: its in-VM agent
fails with `ENOSYS`, most likely on `openat2`. So the **Live kernels** workflow
(`.github/workflows/live-kernels.yml`) runs the Linux suite on those in QEMU/KVM
on a GitHub runner, on every push to `main` and every PR. It currently covers
5.4.302. Each kernel comes from `KERNEL_FLAVOR=qemu eng/build-kernel.sh`: an
x86_64 bzImage from the kernel's own defconfig and KVM guest config, plus
`eng/kernel/qemu-x86.config` and the same BPF fragments. 5.4 builds in a Debian
bullseye container (gcc 10, pahole 1.20) and fetches bullseye from
`archive.debian.org`, now that its security updates are gone from the regular
mirrors. The kernel is cached on the build script and fragments, so it's only
rebuilt when they change.

`eng/qemu-test.sh <bzImage>` boots it with no disk image. The guest's root
filesystem is the runner's own, shared read-only over 9p, so the same .NET SDK
and paths are there. The checkout is shared writable at its own path.
`eng/qemu-init.sh`, the guest's init, mounts `/proc`, `/sys`, `/dev` and tmpfs,
brings up loopback (`dotnet test` talks to its test host over localhost), runs
the prebuilt tests with `--no-build`, and powers off. The output is written to
`artifacts/qemu/output.log`, which the script prints, and the test exit code
becomes the script's.

Extra arguments are forwarded to `dotnet test`, e.g.:

```bash
eng/test-linux.sh --filter FullyQualifiedName~RingBufTests
```

## License

GPL-3.0 — see [LICENSE](LICENSE).
