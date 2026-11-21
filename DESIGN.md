# eBPF for .NET — Design Plan

> A managed eBPF loader and toolchain for C#, with a type-provider-style
> design-time surface generated from kernel BTF.

**Status:** the plan. Phases 0 and 1 are built — the ELF reader of
[§4.2](#42-elf-reader), the BTF parser of [§4.3](#43-btf), and the map /
global-data / subprogram relocations of [§4.4](#44-relocations) exist, so a
real clang tracepoint object loads end to end. Phase 2's CO-RE engine is
built: `.BTF.ext` parsing, the resolver, the instruction patcher, and vmlinux
BTF loading, wired into `BpfObject.Load` and verified end to end in the
container tests against a suite pinning libbpf's semantics. Its offline
cross-kernel check is in place: relocations resolve correctly against real
5.4 and 6.8 vmlinux BTF (see [§8.3](#83-co-re-portability-matrix-in-ci)). The live 6.8 half
passes too: the Linux suite, including CO-RE against the booted kernel's own
BTF, runs clean on 6.8.12 under Apple `container` (§8.4). Still open in phase 2:
the live 5.4 half, the probes of §4.5 that wait on attachment, and the extern
steps of §4.4. The feature probe module itself is built (§4.5).
Everything past that is still design. See the README for what actually works today.
**Target:** .NET 10+ (library), netstandard2.0 (generators), Linux 5.4+ (runtime).

---

## Table of contents

- [1. Goals and non-goals](#1-goals-and-non-goals)
- [2. The architectural bet: managed vs. libbpf](#2-the-architectural-bet-managed-vs-libbpf)
- [3. Target UX](#3-target-ux)
- [4. Loader architecture](#4-loader-architecture)
  - [4.1 Syscall layer](#41-syscall-layer)
  - [4.2 ELF reader](#42-elf-reader)
  - [4.3 BTF](#43-btf)
  - [4.4 Relocations](#44-relocations)
  - [4.5 Feature probes](#45-feature-probes)
  - [4.6 Attachment](#46-attachment)
- [5. C ↔ C# communication](#5-c--c-communication)
  - [5.1 Structs](#51-structs-generated-from-btf-never-hand-written)
  - [5.2 Ring buffer](#52-ring-buffer)
  - [5.3 Maps](#53-maps)
- [6. Design-time: the type-provider surfaces](#6-design-time-the-type-provider-surfaces)
  - [6.0 Why this framing](#60-why-this-framing)
  - [6.1 P1 — Skeleton from `.bpf.o`](#61-p1--skeleton-from-bpfo)
  - [6.2 P2 — The attach surface](#62-p2--the-attach-surface)
  - [6.3 P3 — Kernel types, demand-driven](#63-p3--kernel-types-demand-driven)
  - [6.4 P4 — The verifier as a design-time oracle](#64-p4--the-verifier-as-a-design-time-oracle)
  - [6.5 The design-time connection problem](#65-the-design-time-connection-problem)
  - [6.6 Generator engineering constraints](#66-generator-engineering-constraints)
- [7. Build UX](#7-build-ux)
- [8. Testing strategy](#8-testing-strategy)
- [9. Deployment and privileges](#9-deployment-and-privileges)
- [10. Package layout](#10-package-layout)
- [11. Phasing](#11-phasing)
- [12. Risks](#12-risks)
- [13. Out of scope (for now)](#13-out-of-scope-for-now)
- [Appendix A: prior art](#appendix-a-prior-art)
- [Appendix B: glossary](#appendix-b-glossary)

---

## 1. Goals and non-goals

### Goals

- **Zero native dependencies at runtime.** A NativeAOT'd single static binary with
  BPF programs embedded, running in a distroless container.
- **CO-RE by default.** One build artifact runs unmodified across kernel versions
  and distro configs.
- **No stringly-typed API.** Map names, program names, tracepoint names, and event
  struct layouts are all compile-time entities derived from BTF.
- **Errors move left.** Verifier rejections should surface as IDE squiggles, not as
  an `errno` at 3am.
- **Trim- and AOT-clean throughout.** No reflection, no dynamic codegen.

### Non-goals

- Writing the BPF program itself in C# (see [§13](#13-out-of-scope-for-now)).
- Windows support in v1 (but see the note in [§12](#12-risks) — keep the door open).
- Being a general-purpose ELF or BTF library. These are internal components with a
  public surface only where the toolchain needs one.

---

## 2. The architectural bet: managed vs. libbpf

Two viable architectures exist. Everything else follows from this choice.

**Option A — P/Invoke over libbpf.** Fast to stand up, inherits CO-RE for free. But
it drags in libbpf + libelf + zlib, ties you to a native ABI that churns, breaks
NativeAOT single-file deployment, and surfaces C error codes instead of C# exceptions.

**Option B — Pure managed loader.** Issue `bpf(2)` directly; parse ELF and BTF
yourself; implement CO-RE yourself. This is what [`cilium/ebpf`](https://github.com/cilium/ebpf)
did for Go, and it is a large part of why Go won the eBPF tooling space. Cost: CO-RE
is genuinely hard.

### Decision

**Option B, with Option A retained permanently as a differential-testing oracle.**

Phase 0 ships the libbpf backend to get end-to-end quickly and to have something to
diff against. The managed loader replaces it as the default. libbpf then stays in the
test suite *forever*, comparing relocated instruction streams byte-for-byte across the
whole portability matrix. See [§8](#8-testing-strategy).

---

## 3. Target UX

Everything below is in service of this being the entire program:

```csharp
// probe.bpf.c compiles and generates ExecSnoop as a partial class
using var probe = new ExecSnoop();

probe.Config.MinUid = 1000;          // -> .rodata, frozen at load
probe.Load();
using var _ = probe.Programs.HandleExec.Attach(Hooks.Tracepoint.Syscalls.SysEnterExecve);

await foreach (var e in probe.Events.ReadAllAsync(ct))
    Console.WriteLine($"{e.Pid} {e.Comm} {e.Filename}");
```

`ExecSnoop`, `Config`, `Programs.HandleExec`, `Events`, the `Event` struct, and the
`Hooks.*` tree are all generated from BTF. Nothing is stringly-typed. Nothing is
reflected over, so it AOTs.

---

## 4. Loader architecture

### 4.1 Syscall layer

Namespace: `Nbpf.Core.Native`.

`[LibraryImport]`-generated `syscall(long nr, int cmd, void* attr, uint size)`.
`__NR_bpf` is **321** on x86-64, **280** on aarch64/riscv64, **386** on arm — a small
arch table, not a compile-time constant.

**Do not** model `bpf_attr` as one giant explicit-layout union. Define one blittable
struct per command and pass `sizeof`. The kernel uses the size argument for version
negotiation and requires trailing bytes to be zero, so per-command structs are both
cleaner and forward-compatible.

Wrap every fd in a `SafeHandle` subclass: `BpfMapHandle`, `BpfProgHandle`,
`BpfLinkHandle`.

Map `errno` to typed exceptions with actionable messages:

| errno | Exception | Message should say |
|---|---|---|
| `EPERM` | `BpfPermissionException` | `setcap cap_bpf,cap_perfmon,cap_net_admin+ep` |
| `EACCES` | `BpfVerifierException` | full verifier log, source line via `line_info` |
| `E2BIG` | `BpfProgramTooLargeException` | instruction count vs. limit |
| `ENOTSUPP` / `EINVAL` on load | `BpfFeatureUnsupportedException` | which feature, minimum kernel |

Consider `[SuppressGCTransition]` for `MAP_LOOKUP_ELEM` / `MAP_UPDATE_ELEM` **only** —
they are sub-microsecond and non-blocking. Everything else keeps the normal transition.
Measure before committing.

### 4.2 ELF reader

A minimal managed ELF64 reader. Roughly 400 lines, not a general-purpose library.

Sections that matter:

- program sections (named by `SEC()`)
- `.maps` (BTF-defined maps)
- `.rodata`, `.data`, `.bss`, `.rodata.str1.1`
- `license`
- `.BTF`, `.BTF.ext`
- `.rel*` relocation sections

**Where it lives.** `Nbpf.Elf`, netstandard2.0 — *not* `Nbpf.Core` as
[§10](#10-package-layout) first sketched. The P1 generator reads a `.bpf.o` from
`AdditionalFiles` and parses the BTF inside it ([§7.1](#71-the-pipeline)), which means it
needs the ELF reader as well as the BTF parser, and a generator cannot reference a net10.0
assembly. Same constraint as [§6.6](#66-generator-engineering-constraints), same answer.

**Built.** Relocations are resolved back onto the section they apply to (via `sh_info`), so
callers never touch the `.rel*` sections directly. Two things the tests pin because they are
silent-corruption bugs otherwise: `.bss` is `SHT_NOBITS`, so its contents are empty while its
size is not — size the array map from the section header — and **section symbols are emitted
with `st_name == 0`**, so a subprogram-call relocation against `.text` resolves to an empty
name unless the reader substitutes the section's own name.

### 4.3 BTF

Full parser for the type graph:

```
INT, PTR, ARRAY, STRUCT, UNION, ENUM, ENUM64, FWD, TYPEDEF,
VOLATILE, CONST, RESTRICT, FUNC, FUNC_PROTO, VAR, DATASEC,
FLOAT, DECL_TAG, TYPE_TAG
```

This component is used **three times over** — for map definitions, for CO-RE, and for
C# codegen — so build it as a proper reusable library with a clean type-graph API, not
a parse-and-forget.

Also needed:

- **BTF sanitization** — strip kinds an older kernel rejects before `BPF_BTF_LOAD`.
- **vmlinux BTF loading** from `/sys/kernel/btf/vmlinux`, plus module BTF under
  `/sys/kernel/btf/*`.
- **A netstandard2.0-compatible slice** — the generator needs this parser and cannot
  reference a net10.0+ assembly. See [§6.6](#66-generator-engineering-constraints).
  Plan for this from the start; retrofitting it is painful.

**Built.** `Nbpf.Btf` implements the type graph above, targeting netstandard2.0 from the
outset so the slice never has to be retrofitted. Parsing is two-pass — decode records,
then resolve ids — because BTF ids may point forward. Void is modelled as a null
reference rather than a type entry, which is why `IBtfPtr.Pointee` and the qualifier
targets are nullable: `const void *` really does encode as PTR → CONST → void.
Sanitization and vmlinux/module BTF loading are still outstanding.

### 4.4 Relocations

Must be applied in dependency order.

**1. Maps.** `ld_imm64` with `src_reg == BPF_PSEUDO_MAP_FD (1)` — patch in the real fd.
`BPF_PSEUDO_MAP_VALUE (2)` is the global-variable case, where the second half of the
`imm64` carries the offset into the `.data`/`.rodata` array map.

**2. Global data.** `.rodata`, `.data`, and `.bss` each become a single-entry
`BPF_MAP_TYPE_ARRAY`. Note that clang emits `BTF_KIND_DATASEC` records with a **size of
zero** in an unlinked `.o` — the real section size lives in the ELF section header, and
the loader is expected to patch it in. Size these maps from the ELF, never from BTF.
Populate `.rodata` from the ELF contents *after* applying the
user's config assignments, then `BPF_MAP_FREEZE` it so the verifier treats the values
as constants and prunes dead branches. **This is the mechanism behind
`probe.Config.MinUid = 1000`** — it is not a runtime lookup, it is a compile-time
constant from the verifier's point of view.

**3. Subprograms.** `BPF_PSEUDO_CALL` requires appending each referenced subprogram to
the calling program's instruction stream and rewriting relative offsets. Static
linking, essentially.

**4. CO-RE.** Driven by `.BTF.ext`'s `core_relo` records. Each relocation is a "spec" —
an access string like `0:1:2` against a local type — re-resolved against target vmlinux
BTF by structural name matching, then patched into the instruction immediate.

Implement in this order:

1. field byte offset — covers the overwhelming majority of real programs
2. field-exists
3. enum-value
4. type-size / type-id
5. bitfield extraction — last, it is the fiddliest

**5. Externs.** `BPF_PSEUDO_BTF_ID` for kernel variables, `BPF_PSEUDO_KFUNC_CALL` for
kfuncs.

### 4.5 Feature probes

Kernels vary enormously. Build a probe module that answers ~25 questions by attempting
a tiny load and checking `errno`, cached per-process:

- ringbuf available?
- `bpf_link` available?
- TCX?
- `kprobe_multi`?
- `BTF_KIND_ENUM64` accepted?
- batch map ops?
- …

Every probe must have either a fallback path **or** a clear
`"your kernel is too old for X, minimum is Y"` error. A probe with neither is a bug.

**Built so far (phase 2):** `KernelFeatures.Running` (behind `IKernelFeatures`)
answers three generic questions, which cover most of the list above as
special cases:
- **Map type.** Create the smallest valid map of that type.
- **Program type.** Load `r0 = 0; exit` as that type.
- **Helper, per program type.** Load `call N; exit` and read the verifier log.
  The arguments are garbage, so the load usually fails; the helper is missing
  only if the verifier refuses it by id ("invalid func", "unknown func", or
  "program of this type cannot use helper", depending on kernel).

EPERM is never read as "unsupported": a probe that can't run says so.

- **Errors.** Map creation and program load consult the probes only after an
  `EINVAL` or a verifier rejection. They turn it into
  `BpfFeatureUnsupportedException` with the feature's name and the release that
  introduced it, from a small catalog. CO-RE's poison call is excluded, so it
  stays a verifier error.
- **First fallback.** `bpf_probe_read_{kernel,user}[_str]` (5.5) are rewritten
  to `bpf_probe_read[_str]` on kernels that lack them, as libbpf does. This is
  what lets clang output written against current headers load on 5.4.
- **Gaps.** Program types that need an attach target to load (`TRACING`, and
  later `LSM`, `EXT`, `STRUCT_OPS`) can't be probed blind. `bpf_link`, TCX,
  `kprobe_multi`, BTF kinds and batch ops wait on the attachment and BTF-loading
  code that would use them; each lands with its consumer, so every probe ships
  with its fallback or error.

### 4.6 Attachment

| Target | Mechanism | Fallback |
|---|---|---|
| kprobe / uprobe / tracepoint | `BPF_LINK_CREATE` | `perf_event_open` + `PERF_EVENT_IOC_SET_BPF` |
| kprobe_multi | `BPF_LINK_CREATE` (5.18+) | individual kprobes |
| fentry / fexit / LSM / iter | `BPF_LINK_CREATE` with `attach_btf_id` | `BPF_RAW_TRACEPOINT_OPEN` |
| XDP | `BPF_LINK_CREATE` | netlink `IFLA_XDP` |
| tc | TCX link (6.6+) | netlink `clsact` qdisc + filter |
| cgroup | `BPF_LINK_CREATE` with cgroup dirfd | `BPF_PROG_ATTACH` |

The netlink fallbacks are the unpleasant part. Get an `AF_NETLINK` socket by
P/Invoking `socket()` and wrapping the fd in `new Socket(SafeSocketHandle)` — .NET then
handles async I/O. **Budget real time for the tc/clsact message construction**; it is
fiddly and under-documented.

**Prefer `bpf_link` everywhere it exists.** Links are refcounted and auto-detach on
process death, which eliminates an entire class of "my program is stuck attached after
a crash" support tickets.

---

## 5. C ↔ C# communication

### 5.1 Structs: generated from BTF, never hand-written

Hand-written `[StructLayout]` mirrors of C structs are a permanent source of silent
corruption. BTF carries exact member byte offsets, sizes, and bitfield metadata, so
generate `LayoutKind.Explicit` with `[FieldOffset]` taken straight from BTF. Padding
and alignment mismatches become structurally impossible.

Mapping rules:

| C | C# |
|---|---|
| `char comm[16]` | `[InlineArray(16)] struct CommBuffer` + `ReadOnlySpan<byte>` accessor + NUL-stopping `ToString()` |
| bitfields | private backing integer + generated mask/shift properties |
| `enum` | C# enum with the correct underlying type |
| kernel pointer | `KPtr<T>` — a wrapper over `ulong`, deliberately not dereferenceable |
| nested struct | nested generated struct, same rules recursively |

**Emit a hash of the source BTF into the generated type and verify it at load time**,
so a stale pre-built `.bpf.o` fails loudly instead of misparsing.

### 5.2 Ring buffer

Consuming `BPF_MAP_TYPE_RINGBUF` means mmapping the consumer page RW and the producer
page + data area RO, with **the data area mapped twice** to make wraparound contiguous,
then `epoll` on the map fd.

Expose two APIs over the same machinery:

```csharp
// Ergonomic: copies out, allocation-free per item, cancellable
IAsyncEnumerable<TEvent> ReadAllAsync(CancellationToken ct);

// Zero-copy: ref points directly into mapped memory
delegate void RingBufferHandler<T>(scoped ref readonly T record) where T : unmanaged;
void Consume(RingBufferHandler<TEvent> handler, CancellationToken ct);
```

The `scoped` keyword is doing real work in the second signature — it makes it a
*compile error* for a handler to stash the ref beyond the callback, which is exactly the
lifetime bug this API would otherwise invite.

**Run the epoll loop on a dedicated thread**, not a thread-pool thread. A pool thread
blocked in `epoll_wait` is a pool thread you have stolen. Add an `eventfd` to the epoll
set for prompt cancellation.

Ship a **perf-buffer implementation** too (per-CPU mmap'd rings) for pre-5.8 kernels,
behind the same interface.

### 5.3 Maps

```csharp
public sealed class BpfMap<TKey, TValue>
    where TKey : unmanaged where TValue : unmanaged
{
    public bool TryGetValue(in TKey key, out TValue value);
    public TValue this[in TKey key] { get; set; }
    public void Update(in TKey key, in TValue value, MapUpdateFlags flags);
    public bool Delete(in TKey key);
    public IEnumerable<KeyValuePair<TKey, TValue>> Enumerate();   // GET_NEXT_KEY
    public int LookupBatch(Span<TKey> keys, Span<TValue> values); // BPF_MAP_LOOKUP_BATCH
}
```

Validate `sizeof(TValue)` against the map's actual `value_size` on construction.

**Per-CPU maps get their own type.** The value is really an array of `nr_cpus` entries,
each padded to 8 bytes, and every eBPF binding that papers over this produces confused
users:

```csharp
public sealed class PerCpuMap<TKey, TValue> // returns ReadOnlySpan<TValue>
{
    public ReadOnlySpan<TValue> this[in TKey key] { get; }
    public TValue Sum(in TKey key);
    public TAcc Aggregate<TAcc>(in TKey key, TAcc seed, Func<TAcc, TValue, TAcc> f);
}
```

**Batch ops matter more than they look.** Iterating a 100k-entry map one `GET_NEXT_KEY`
at a time is two syscalls per entry.

---

## 6. Design-time: the type-provider surfaces

### 6.0 Why this framing

The design here is deliberately modeled on **F# type providers**: a compile-time
mechanism that turns an external, machine-readable schema into first-class types.
eBPF is an unusually good fit, because the kernel exposes *enormous* amounts of exactly
that kind of schema — BTF, tracepoint format files, available attach points.

C# has no type providers. What it has is **Roslyn incremental source generators**
(`IIncrementalGenerator`, Roslyn 4.0 / .NET 6+), which cover most of the same ground.

The differences that matter here:

| | F# type provider | C# source generator |
|---|---|---|
| Output | Erased **or** generated types | Source text only — always real metadata |
| Laziness | Yes; unbounded type space, materialize on touch | No; everything emitted eagerly |
| Static parameters | `JsonProvider<"sample.json">` | No equivalent — config via MSBuild items or marker attributes |
| Design-time execution | Arbitrary code, can hit a live DB | Same in principle, but IO outside `AdditionalFiles` breaks incrementality |
| Can modify existing code | N/A | No, additive only |
| Assembly TFM | Normal | **Must** target netstandard2.0 |

**The gap that matters is erasure.** An F# SQL provider can expose a 10,000-table
database because untouched tables cost nothing. A C# generator exposing the same
database emits 10,000 real types into the assembly. For eBPF this is decisive: vmlinux
BTF for a modern kernel is roughly **100k types**, and naively generating it would
produce hundreds of megabytes of source and make the IDE unusable.

Two techniques partially recover it, and both are load-bearing in this design:

1. **Demand-driven syntactic scanning.** A generator can walk the user's syntax trees
   looking for `Vmlinux.task_struct` *before binding to anything* — it is just a
   `MemberAccessExpressionSyntax` on an identifier. Generate only what is referenced,
   plus a controlled closure. This is the standard approximation of laziness and it
   works well.
2. **Interceptors** (C# 12), which let a generator redirect a specific call site to
   generated code — the nearest thing to erasure C# has.
   ⚠️ Still gated behind `<InterceptorsNamespaces>` and went through a breaking
   redesign of `[InterceptsLocation]` (line/column → checksum-based) in the .NET 9
   cycle. **Verify current stability before building on it.**

Four provided surfaces follow. Note that the weakest one is the most obvious one —
"provide all of vmlinux" — because kernel struct field access happens in the **C**
program, not in C#.

### 6.1 P1 — Skeleton from `.bpf.o`

**Input:** the compiled object's BTF, via `AdditionalFiles`.
**Output:** the partial class, config struct, program handles, map wrappers, event
structs with `[FieldOffset]` from BTF.

This is the backbone. MSBuild item metadata is the static-parameter analogue:

```xml
<BpfProgram Include="probes/execsnoop.bpf.c"
            ClassName="ExecSnoop"
            Kernel="btf/6.8-generic.btf" />
```

### 6.2 P2 — The attach surface

**The best idea in this document.**

The kernel tells you, at design time, every place a program can attach and the exact
signature of each:

| Source | Provides |
|---|---|
| `/sys/kernel/tracing/events/**/format` | every tracepoint + its argument struct |
| vmlinux BTF `FUNC` entries | every fentry/fexit target with full prototypes |
| `/sys/kernel/btf/*` | kfuncs and their signatures |
| `available_filter_functions` | valid kprobe targets |

Today, attaching to a misspelled tracepoint — or to a handler whose signature does not
match the hook — fails at load time with an `errno`. Provide it instead:

```csharp
probe.Programs.HandleExec.Attach(Hooks.Tracepoint.Syscalls.SysEnterExecve);
probe.Programs.OnConnect.Attach(Hooks.Fentry.tcp_v4_connect);
//                                          ^ compile error if the C handler's
//                                            args don't match the kernel prototype
```

This is the surface that behaves most like a real type provider: large, machine-derived,
and located exactly where users make typos.

It is also where **demand-driven generation is mandatory** — there are ~50k kprobe
targets. Emit only the ones whose member-access expressions actually appear in source.

### 6.3 P3 — Kernel types, demand-driven

`Vmlinux.task_struct`, `Vmlinux.xdp_md`, `Vmlinux.__sk_buff`.

Syntactic scan for `Vmlinux.*` accesses; generate the transitive closure with
**pointer fields cut off** — a `struct task_struct *parent` becomes
`KPtr<task_struct>`, and `task_struct` is materialized only if separately referenced.

That single rule collapses the closure from thousands of types to a handful. It is the
difference between this surface being viable and not.

For something closer to true erasure: make the provided type an empty
`readonly ref struct` and put every field on generated **extension members** (C# 14
extension blocks), so the metadata cost is one near-empty type plus only the accessors
actually touched.

### 6.4 P4 — The verifier as a design-time oracle

The real payoff of thinking in type-provider terms. F# providers connect to a live
*database* at design time; the eBPF analogue is connecting to a live **kernel**.

Ship a Roslyn **analyzer** (not a generator) that:

1. loads each program with a scratch fd
2. reads the verifier log
3. uses BTF `line_info` to map rejections back to source lines
4. surfaces them as squiggles — **in the `.bpf.c` file, in the IDE, before
   `dotnet build` is ever run**

Nothing in any eBPF ecosystem does this today. Verifier rejection is the single worst
part of writing eBPF, and it currently happens at the latest possible moment.

**Friction to be honest about:** it needs `CAP_BPF` and a Linux kernel. Design it as an
out-of-process helper spoken to over a Unix socket, so a developer on Windows or macOS
points it at a VM or container and gets the same experience.

Off by default. Opt in via `<NbpfDesignTimeVerify>true</NbpfDesignTimeVerify>`.

### 6.5 The design-time connection problem

Type providers taught the ecosystem this lesson the hard way: a provider pointed at a
live database gives a delightful demo and a broken CI pipeline, because the schema is
not in source control.

Same trap here, and P2/P3 walk straight into it. So this is promoted from a build
detail to an architectural invariant:

> ### 🔒 Invariant
> **The kernel BTF used for generation is a file in the repository.**
> Never `/sys/kernel/btf/vmlinux` from whatever the build machine happens to be running.

```console
$ dotnet nbpf pin-kernel --from-running
wrote btf/6.8-generic.btf (4.2 MB)   # commit this
```

Live-kernel generation exists behind an explicit flag and prints a warning.

**P4 is the exception** — it is an analyzer producing diagnostics, not types, so a live
connection there is safe and in fact the whole point.

### 6.6 Generator engineering constraints

These bite hard and are worth planning for rather than discovering:

- **netstandard2.0.** The BTF parser lives in both the runtime library and the
  generator. Factor it as a source-only package or a netstandard2.0 slice — the
  generator cannot reference a net10.0+ `Nbpf.Core`. *Do not discover this in phase 4.*
- **No arbitrary NuGet references** in analyzers without ILMerge/ILRepack. Transitive
  dependency conflicts inside the Roslyn load context are a known misery. Keep the
  generator's dependency graph at **zero**.
- **All input through `AdditionalFiles`.** A generator that calls `File.ReadAllBytes`
  gets no change tracking, so the IDE will not re-run it and the incremental cache goes
  stale.
- **Cache on parsed BTF, not file bytes.** Structure the pipeline as
  `AdditionalTexts → ParsedBtf (IEquatable) → generated source`, with a real equality
  implementation on the intermediate — otherwise every keystroke re-parses a
  multi-megabyte blob.
- **Generator perf is IDE perf.** It runs in-process on every edit. Budget accordingly.

---

## 7. Build UX

### 7.1 The pipeline

```xml
<ItemGroup>
  <BpfProgram Include="probes/execsnoop.bpf.c" ClassName="ExecSnoop" />
</ItemGroup>
```

An MSBuild task then:

1. **Locates clang** (≥12); errors helpfully if absent.
2. **Resolves `vmlinux.h`** from the pinned BTF blob in the repo (see
   [§6.5](#65-the-design-time-connection-problem)). `--from-running-kernel` is an
   explicit opt-in.
3. **Compiles:** `clang -target bpf -O2 -g -D__TARGET_ARCH_x86 -c`.
   The `-g` is **mandatory** — no debug info means no BTF means no CO-RE and no codegen.
4. **Emits `compile_commands.json`** so clangd / VS Code gives IntelliSense *inside the
   `.bpf.c` files*. Small effort, disproportionate delight.
5. **Adds the `.bpf.o`** as both an `EmbeddedResource` and an `AdditionalFiles` entry.

The incremental source generator then reads the `.bpf.o` from `AdditionalFiles`, parses
its BTF, and emits the partial class. Generator rather than a plain task **because IDEs
re-run generators on file change** — you edit a struct in C and the C# type updates
without a rebuild.

### 7.2 `dotnet nbpf` global tool

| Command | Purpose |
|---|---|
| `verify` | load every program, close the fds, report verifier output. Works in CI with `CAP_BPF`. |
| `dump btf` | human-readable BTF type graph |
| `dump asm` | managed BPF disassembler — a weekend of work, pays for itself the first time someone asks "what did the verifier actually see?" |
| `explain` | pattern-match common verifier errors to explanations and fixes |
| `pin-kernel` | write a BTF blob into the repo |
| `new` | templates: `nbpf-tracepoint`, `nbpf-xdp`, `nbpf-tc` |

`explain` deserves emphasis. Verifier messages are the single biggest source of eBPF
frustration; mapping `"invalid mem access 'scalar'"` or
`"R1 type=inv expected=fp"` to a plain-English cause and fix is a genuine
differentiator.

---

## 8. Testing strategy

### 8.1 Unit tests via `BPF_PROG_TEST_RUN`

Makes XDP, TC, and socket programs testable with synthetic packets, and works for
fentry/raw_tp on recent kernels:

```csharp
[Fact]
public void DropsIcmpFromBlockedSubnet()
{
    using var p = new Firewall(); p.Load();
    p.BlockList[Ip("10.0.0.0/8")] = true;
    var r = p.Programs.XdpFilter.TestRun(PacketBuilder.Icmp(from: "10.1.2.3"));
    Assert.Equal(XdpAction.Drop, r.ReturnCode);
}
```

### 8.2 The libbpf differential oracle

For every test program, relocate with **both** the managed engine and the libbpf
backend, and assert **byte-identical instruction streams**. This is the primary defense
against the CO-RE risk in [§12](#12-risks) — "mostly working" CO-RE is
indistinguishable from "silently corrupting field reads on some kernels."

### 8.3 CO-RE portability matrix in CI

Pull BTF blobs from [BTFHub](https://github.com/aquasecurity/btfhub) for ~40 distro
kernels and, for each, resolve all relocations **without loading**.

You catch "this breaks on RHEL 8" at build time, on a GitHub runner, without booting a
single VM. Nothing else in the ecosystem makes this as easy as it could be here — lean
on it hard.

**Built so far (phase 2):** two kernels, Ubuntu 5.4.0-26 (BTFHub) and 6.8.0-31
(BTF cut from Ubuntu's own kernel package), resolved against
`core-kernels.bpf.c` in `Nbpf.Btf.Tests`. Rather than committing megabytes per
kernel, `eng/gen-kernel-btf.sh` minimizes each blob with `bpftool gen
min_core_btf` to just the types and members the object touches, a few hundred
bytes each. That minimization runs libbpf's own candidate matching, so it doubles as
a libbpf cross-check: on 5.4.0-26 it surfaced two identical `task_struct`
definitions (a pahole dedup leftover) that make `TYPE_ID_TARGET` on
`task_struct` genuinely ambiguous. Every field relocation still agrees across
both copies. Growing this to the ~40-kernel matrix means more pinned sources in
that script, plus probably a fixture per feature area instead of one object.

### 8.4 Live-kernel integration tests

A matrix of VMs (5.4, 5.10, 5.15, 6.1, 6.8) for the attach paths that
`PROG_TEST_RUN` cannot cover — XDP on a real NIC, tc/clsact, cgroup.
Slower and separate from the main CI loop.

**Built so far:** the kernel side of the local VM route.
`eng/build-container-kernel.sh` builds an arm64 kernel that Apple's `container`
boots per container (`container run -k`, wired through `CONTAINER_KERNEL` in
`eng/container-runtime.sh`): Apple's default kernel config plus a checked-in
BPF/tracing fragment, from a pinned kernel.org tarball, built by the *Container
kernel* workflow on a native arm64 runner and uploaded as a workflow artifact. It is keyed by kernel
version: a pinned sha256, a base config, and extra fragments per version. 6.18.64
is the everyday kernel. 6.8.12, the live 6.8 half of phase 2's exit criterion,
reuses the 6.18 base config plus `nbpf-pre-6.10.config`, which enables module
support because `BPF_JIT` and `KPROBES` depend on it before 6.10. The whole suite
passes on it. 5.4 is the open entry: it likely needs an older builder image
(current gcc and pahole don't target it cleanly), and Apple's in-VM init may use
syscalls that 5.4 lacks. Prebuilt distro kernels
are not an option here: they build vsock, virtiofs and overlayfs as modules, and
`container` boots without an initramfs.

---

## 9. Deployment and privileges

- **Preflight capability check** with actionable messages. `CAP_BPF` + `CAP_PERFMON`
  (5.8+), `CAP_NET_ADMIN` for network attach; `CAP_SYS_ADMIN` on older kernels.
- **Both memory-accounting regimes:** `RLIMIT_MEMLOCK` bumping pre-5.11, memcg after.
- **Split privilege model.** A small privileged loader pins programs and maps under
  `/sys/fs/bpf`, then the unprivileged C# service opens the pinned maps by path. Good
  security posture, and it makes rolling app restarts non-disruptive since the programs
  stay attached.
- **NativeAOT-clean throughout:** no reflection, no dynamic codegen, trim-safe.

---

## 10. Package layout

| Package | Contents | TFM |
|---|---|---|
| `Nbpf.Core` | syscalls, maps, links, ringbuf, relocation engine. Zero native deps. | net10.0+ |
| `Nbpf.Btf` | BTF parser, shared with generator. **Built.** | netstandard2.0 |
| `Nbpf.Elf` | ELF64 reader, shared with generator. **Built.** | netstandard2.0 |
| `Nbpf.Build` | MSBuild targets, clang orchestration, `vmlinux.h` | — |
| `Nbpf.SourceGen` | incremental generator — P1, P2, P3 | netstandard2.0 |
| `Nbpf.Analyzers` | design-time verifier — P4 | netstandard2.0 |
| `Nbpf.Testing` | `PROG_TEST_RUN`, packet builders, xunit helpers | net10.0+ |
| `Nbpf.Tool` | `dotnet nbpf` global tool | net10.0+ |
| `Nbpf.LibBpf` | libbpf P/Invoke backend — bootstrap, then permanent test oracle | net10.0+ |

---

## 11. Phasing

Phases 0–3 are the load-bearing runtime engineering and are unaffected by the
type-provider framing. Phase 4 is where it becomes something people actually want to
use — **resist the temptation to start there.**

| Phase | Scope | Exit criterion | Status |
|---|---|---|---|
| **0** | Syscall layer, map CRUD, hand-assembled program, ringbuf | A hand-written instruction array loads and emits events | ✅ done |
| **1** | ELF + BTF parse; map / global / subprog relocations | Real clang output for a tracepoint loads on the build kernel | ✅ done — `BpfObject.Load` passes the exit criterion in the container tests |
| **2** | CO-RE field relos, vmlinux BTF, feature probes | Same binary runs on 5.4 and 6.8 unmodified | 🚧 in progress — CO-RE engine done and resolves correctly against real 5.4/6.8 BTF offline; feature probes and the probe_read fallback done; live 6.8 passes; live 5.4 remains |
| **3** | Attachment breadth: XDP, TC/TCX, cgroup, fentry, netlink | XDP drop counter on a live NIC | — |
| **4** | **P1** skeleton generator + MSBuild + templates | The [§3](#3-target-ux) snippet is the complete program | — |
| **5** | **P4** design-time verifier analyzer | Verifier error appears as a squiggle on the right line of `.bpf.c` | — |
| **6** | **P2** attach surface, demand-driven | Typo'd tracepoint name is a compile error | — |
| **7** | **P3** kernel types + `PROG_TEST_RUN` contexts | `Vmlinux.xdp_md` test input; closure stays under 50 types | — |
| **8** | NativeAOT, perf hardening, BTFHub matrix, benchmarks | Single static binary; ringbuf throughput within 15% of `cilium/ebpf` | — |

**P4 is deliberately ahead of P2** — it is a smaller build and it changes day-to-day
experience more.

---

## 12. Risks

### CO-RE is the schedule risk

It is the one component where "mostly working" is indistinguishable from "silently
corrupting field reads on some kernels."

*Mitigation:* the libbpf differential oracle from day one
([§8.2](#82-the-libbpf-differential-oracle)) — relocate the same object with both
engines and assert byte-identical instruction streams across the whole BTFHub matrix.

*Fallback if it slips badly:* ship phases 1, 3, and 4 with build-time-pinned kernel
targets. Still useful for fleets running one kernel version.

### Kernel API surface is a treadmill

*Mitigation:* feature probes plus explicit minimum-version errors, and a standing policy
of preferring `bpf_link` over legacy attach everywhere.

### Verifier UX

*Mitigation:* BTF `line_info` maps a rejection back to a line of C. **Do this early.**
It changes the experience from "cryptic register dump" to
`line 42: possible NULL dereference, add a null check after bpf_map_lookup_elem`.

### Generator performance

A slow generator is a slow IDE, and it will be blamed on the whole library.
*Mitigation:* the equatable-intermediate caching discipline in
[§6.6](#66-generator-engineering-constraints), plus a benchmark in CI that fails on
regression.

### Windows

eBPF for Windows exposes a libbpf-compatible API. Not in scope, but **keep the loader
behind an interface** so a second backend is possible later — it is a meaningful
strategic option given where C# developers actually live.

---

## 13. Out of scope (for now)

### Writing the BPF program itself in C#

A restricted C# subset compiled to BPF bytecode, with kernel types provided natively.

This is the direction the whole design leans if you follow it far enough — and it is
the reason the type-provider question is a good one rather than a naive one. But it is
a genuinely large project: verifier-friendly codegen, no unbounded loops, no
allocation, stack under 512 bytes, no indirect calls.

Keep it firmly out of scope. Revisit after phase 8.

### An F# type provider over the same BTF parser

Worth considering as a *side* deliverable rather than out of scope entirely.
`Nbpf.Core` is a plain library; a type provider over the same BTF parser is a few
hundred lines and gets you erased types, real laziness, and the full vmlinux universe at
no metadata cost — the thing C# cannot do.

If the team has any F# tolerance, it is the better front end for
[P3](#63-p3--kernel-types-demand-driven) specifically.

---

## Appendix A: prior art

| Project | Language | Relevance |
|---|---|---|
| [`libbpf`](https://github.com/libbpf/libbpf) | C | The reference implementation. Read `libbpf.c` relocation code closely. |
| [`cilium/ebpf`](https://github.com/cilium/ebpf) | Go | The closest analogue to this plan; pure-native loader. Primary design reference. |
| [`aya`](https://github.com/aya-rs/aya) | Rust | Pure-Rust loader + BPF programs in Rust. Relevant to [§13](#13-out-of-scope-for-now). |
| [`bcc`](https://github.com/iovisor/bcc) | Python/C++ | Runtime compilation model — the thing CO-RE replaced. Instructive as a counterexample. |
| [`bpftool`](https://github.com/libbpf/bpftool) | C | Feature-probe logic and BTF dumping worth mirroring. |
| [BTFHub](https://github.com/aquasecurity/btfhub) | — | Distro BTF blobs for the CI matrix. |

## Appendix B: glossary

| Term | Meaning |
|---|---|
| **BTF** | BPF Type Format — debug-info-like type metadata embedded in BPF objects and the kernel |
| **CO-RE** | Compile Once, Run Everywhere — relocating field offsets at load time against the target kernel's BTF |
| **kfunc** | A kernel function explicitly exported for BPF programs to call |
| **fentry/fexit** | BTF-powered function entry/exit tracing; cheaper and more type-safe than kprobes |
| **TCX** | Newer, link-based tc attachment (6.6+), replacing netlink `clsact` |
| **ringbuf** | `BPF_MAP_TYPE_RINGBUF` — single shared MPSC ring, replaced per-CPU perf buffers in 5.8 |
| **`line_info`** | BTF section mapping BPF instructions back to source lines — the key to good verifier errors |
| **verifier** | The kernel's static analyzer that must prove a BPF program safe before load |

---

*This document is the plan, not the contract. Phases 0–3 should be treated as firm;
4–8 will move as the design-time surfaces meet reality.*
