# B3.5h: ARM64 userspace execution and physical-observation design audit

Source snapshot: `28e3708`, clean working tree at the start of this audit.
This document proposes a measurement lifecycle; it implements no executor,
instruction admission, observer, timer change or HTrace conversion.

**Decision:** retain the current fork-per-execution utility as the architectural
baseline. For a later physical prototype, prefer a **bounded measurement batch
inside one disposable, CPU-pinned child**, with stable private mappings during
the batch. First run the existing module-free M3 timer protocol. Do not start a
cache observer until its independent evidence gates pass.

## 1. Evidence and its limits

| Evidence level | Established | Not established |
| --- | --- | --- |
| Source inspection | Concrete instruction admission, fixed raw input subset, guarded allocations, RW-to-RX publication, ABI trampoline, child/result lifetime, model interfaces described below. | Actual target OS permissions, counter behavior, cache state, predictor state or timing accuracy. |
| Native AArch64 CI, user-reported through B3.5j | B3.5i: 45/45 tests, including 102 native architectural executions, 102 oracle/production sequential-Unicorn matches, and the new seq/cond typed-trace correspondence regressions. Five program images; Ubuntu AArch64 with 4096-byte pages (B3.5g reported `7.0.0-1017-azure`). | M3 Pro execution, 16-KiB execution, physical speculation, a physical observer or detection of leakage. The complete 2^32 MOVZ constant-pair family was not executed. |
| Existing software/model evidence | B3.4a-f model tests cover sequential and conditional-speculation traces, taints, boosting and rollback; B3.5g compares architectural state using `seq`, not `cond`. | A model misprediction is not evidence of a hardware misprediction. Successful taint boosting is not itself a physical input-equivalence test. |
| Required target evidence | Actual Fedora Asahi kernel/page size, M3 identity, allowed CPUs/core identities, architectural compatibility and timer/cache experiments. | None of these target results is inferred from macOS inventory, header compilation or the CI CPU. |

CI results above are user-supplied evidence, not a newly executed or independently
downloaded CI run. The [target runbook](README.m3-experiment-runbook.md) prepares
separate G1/G2 physical checks without changing their protocols. Existing workflow steps are
`.github/workflows/arm64-software-baseline.yml:155-163` (architectural tests) and
`:258-272` (host timer checks/native timer smoke). B3.5i's closure extends only the
architectural step's selected test modules.

The target inventory reports 128-byte lines, 64-KiB Sawtooth efficiency-core and
128-KiB Everest performance-core L1 D-caches. Treat these as **macOS-reported
inventory**, not Linux cache-indexing, associativity, eviction or timer evidence.
Efficiency-core-first work would narrow scope, not establish easier compatibility.

## 2. Current lifecycle: one program/input execution

The Python test controller is the integration example, not a production Executor.
See `tests/unit_arm64_userspace_execution.py`, especially
`make_sequential_model` (`:605-641`), `native_result` (`:668-715`) and the three
native tests (`:718-799`).

| Order | Actual operation and source | Meaning / measurement consequence |
| --- | --- | --- |
| 1 | `rvzr/code_generator.py:202-244`, `create_test_case_from_template`: real ARM64 template parsing, passes, assembly printing, GNU assembly and ELF metadata. Tests use the existing `tests/arm64/min_arm64.json`, one actor and no random macros. | The four additional images vary literal MOV constants in temporary templates. This is actual instruction-byte diversity, not random-program admission. |
| 2 | `tools/arm64_userspace_program.py:26-101`, `validate_program`, `_approved_section`, `export_approved_program`. | Bounded ELF64 little-endian AArch64 ET_REL, one main section, prescribed symbols/envelope, no nonempty relocations or extra allocated sections. Export actual `.data.main[12:44]` plus trusted RET. Legacy exact format remains strict; family varies only imm16 at native offsets 8/16. C independently checks bytes; ELF metadata is not a native execution interface. |
| 3 | `InputData` constructor (`rvzr/tc_components/test_case_data.py:86-88`) allocates storage; the tests explicitly zero it, then set main bytes/X0. `tools/arm64_userspace_input.py:21-38`, `encode_input`. | Constructor storage is not implicitly initialized. One 12288-byte fragment is returned unchanged; only main `[0,4096)` and X0 `[8192,8200)` may be nonzero. Faulty, remaining GPR/NZCV/SP, SIMD and padding bytes must be zero. This is raw InputData, not an RDBF container. |
| 4 | Python freezes program/input bytes and invokes a fresh binary via `subprocess.run` with a 10-second timeout (`native_result:679-681`). C `runner_main` (`tools/arm64_architectural_smoke.c:326-347`) selects an explicit format. | Default embedded reference, explicit exact generated image, or explicit MOVZ16 family. No program paths, entry offsets, general ELF loading or fallback substitution. |
| 5 | C `read_packet`, `decode_input`, `read_program_input` (`:203-263`) require exact length and EOF, bound a stalled stream and publish neither snapshot on rejection. | Input-only: 12288 bytes. Generated: 36 + 12288 bytes. Program/input snapshots are owned storage; positive short reads and excess bytes are handled before executable allocation. |
| 6 | `runner_main:348-379` obtains runtime page size/kernel release, allocates a shared result record, clears it, emits metadata and forks. | Accepts only runtime page sizes 4096/16384. Result storage is separate from private code/data mappings. Its clearing and all protocol/setup work are outside the fixture. No CPU affinity is selected or verified by this architectural utility. |
| 7 | Child checks `READ_IMPLIES_EXEC` without changing it, disables core dumps and calls `execute_fixed` (`:384-399`). `execute_fixed:135-162` rechecks the selected byte policy, then allocates private anonymous data/code regions. | Each reservation is three runtime pages: NONE guard / payload page / NONE guard. No borrowed mapping, MAP_FIXED or kernel PTE manipulation. Copy all 4096 main bytes into data; copy the actual received 36 bytes into RW code. Initialization touches target data before execution. |
| 8 | `execute_fixed:157-162` calls `__builtin___clear_cache`, then publishes code RX. | Code remains RX during invocation; data is RW. Publication is instruction-cache synchronization, not a calibrated data-cache eviction operation. Allocation, first touch, publication and permission syscalls can perturb caches/translations and execution history. |
| 9 | `tools/arm64_architectural_fixture.S:38-54`, `rvzr_arch_invoke`. | Saves FP/LR/X19/X20 in a 32-byte host stack frame; sets X19=result, X20=owned main, X16=entry; loads selector into X0, zeros X1-X7/NZCV, BLRs the admitted body. Trusted pointer/control registers are not InputData-controlled. |
| 10 | Admitted body (`.S:8-19`, and the matching generated bytes). | CMP X0, B.EQ, one selected MOVZ X1, fixed join, one 8-byte load at main, ADD, one 8-byte store at main, controlled RET X30. Constants cannot change control flow, addresses, ABI-critical registers or length. |
| 11 | Trampoline `.S:55-66` stores X0-X7/NZCV/SP modulo 16 and restores preserved registers. C `execute_fixed:168-176` copies all main bytes and checks bytes `[8,page_size)` for unintended changes. | Architectural capture is real. These writes/reads are **observer perturbations**: a future cache probe after full-main copying would see the copying too. Even immediate post-RET register spills can conflict with observed cache state. Their placement needs an explicit future observer boundary. |
| 12 | `region_close`, `execute_fixed:181-190`: attempt both releases, report cleanup errors. Child exits; `wait_bounded:266-302` waits up to its deadline, kills/reaps only its owned child on failure/timeout. | No continuation after a fault, no retry and no partially successful result. Child exit is a final mapping-lifetime backstop. Internal deadline is not a hard real-time guarantee for blocked OS operations/output; use an outer process-group timeout as documented. |
| 13 | Parent requires successful child exit, COMPLETE stage and no recorded error (`runner_main:401-410`); prints architectural state, releases shared result and prints final complete (`:412-426`). | Base addresses in output are historical and already unmapped, not handles for later access. Require exit zero and the final complete record. Output failure may leave partial JSONL. |
| 14 | `native_result` checks actual registers/flags/main against `expected_state` and a corresponding generated sequential model; repetitions compare complete reported architectural states, ignoring ASLR addresses. | Validates this architectural projection. It does not compare native C-traces or physical H-traces: neither is collected by the C utility. |

The runner does not set a scheduling policy, disable interrupts, claim a clean
predictor/cache, identify a core type, or time the fixture. Architectural reset
comes from fresh initialization and the trampoline, not an assumed benefit of
fork. Linux documents fork's address-space/COW semantics in
[fork(2)](https://man7.org/linux/man-pages/man2/fork.2.html); that interface supplies
no experiment-level promise of cold caches or a reset branch predictor.
There is no parent-death signal or process-group setup in this utility. If its
supervising parent is killed before cleanup, the internal child watchdog is lost;
the surrounding process-group timeout is therefore important. Ordinary
`subprocess.run(timeout=...)` kills its direct child, not an entire descendant
group. This is a source-derived lifetime limitation, not a reproduced orphan
failure, and a future batching implementation must address supervisor termination.

## 3. Lifecycle alternatives

| Requirement | Fresh child + new mappings per observation (current) | Persistent worker across programs/batches | Disposable child + bounded repeated batch (recommended proposal) |
| --- | --- | --- | --- |
| Architectural reset | Current full main copy/trampoline per observation; simple failure isolation. | Must explicitly restore every allowed input region, trusted register, flag and scratch state per repetition; previous stores otherwise persist. | Same explicit reset per repetition; retain isolation and reinitialize all mappings at batch boundaries. |
| Address stability | New allocation each observation; numerical reuse is possible but not guaranteed. New address is not necessarily a different cache set. | Stable VA possible while mappings live, but program changes/reallocation need explicit invalidation. Stable VA does not prove physical-line/index stability. | Stable VA within one program batch; discard/recalibrate across children rather than assume cross-batch equality. |
| Cache preparation | mmap/copy/publication/first touches are mixed into every trial history. Fresh does not imply cold. | Can move setup outside windows and apply a reproducible preparation protocol; long-lived contamination/drift remains. | Setup once; controlled preparation per trial after architectural reset. Preparation must be physically validated and confined to owned memory. |
| Predictor preparation | Fork/exec/setup/shim branches vary history; no existing training sequence. | Can repeat at the same branch PCs, but repetition alone neither proves a desired prediction nor a useful transient window. | May later host a fixed, bounded training schedule at stable PCs, followed by a measured trial. Training is not part of the initial cache pilot. |
| Scheduling/affinity | Currently none; external taskset can restrict placement without changing the binary. | Must pin/verify actual worker CPU and identify core; interruptions remain. | Pin worker before allocation/first touch, verify mask and start/end CPU; keep core types separate. This reduces one confound, not OS interference. |
| Error recovery | Child failure invalidates one trial; existing cleanup/watchdog applies. | Fault recovery can leave half-written memory, stale state or uncertain ownership; restarting a failed worker is safer than resuming it. | Any fault/timeout/state violation aborts and discards the batch; kill/reap child, never resume generated code or reuse uncertain mappings. |
| Trusted state | Existing trampoline covers this admitted family, not arbitrary native register effects. | Reset/capture code and any observer must preserve ABI/flags/pointers across calls; cannot rely on C caller-saved registers. | Same requirement within batch; process boundary limits lifetime but does not replace ABI review. |
| Cleanup/cost | Strongest existing evidence; repeated setup/teardown and JSON/process costs unsuitable as a cache latency metric. | Amortized setup, greater protocol/state/cleanup complexity and exposure to drift. | Amortized setup with finite samples/time/memory; more review than current runner, less cross-program lifetime than a global worker. |

**Recommendation is conditional, not a measured M3 optimization.** Keep the
current executable unchanged as a reference. A future worker would be a
single-threaded standalone executable, launched via exec from any threaded Python
controller; its own supervising parent may fork the disposable measurement child.
Do not transplant current post-fork C work into a multithreaded Python process:
[fork(2)](https://man7.org/linux/man-pages/man2/fork.2.html) restricts safe child
operations before exec in that case.

Proposed finite batch order:

1. Admit one immutable program image, finite input snapshots, selected CPU and
   sample bound. Allocate only privately owned data/code and bounded results.
2. Pin/verify the child; record CPU identity, actual page size, mappings, image
   hash, input identities and session identity. Prefault relevant child pages,
   result storage and stack; parent prefaulting alone does not rule out COW faults.
3. Publish code once using the existing RW-to-RX/cache-sync discipline. Never
   rewrite RX code during the batch or toggle permissions between trial windows.
4. For each trial: reset architectural data/registers; perform the independently
   validated observer preparation; execute/probe at defined boundaries; freeze raw
   observations; only then perform bulk architectural capture/validation. Buffer
   output until after the measured batch; no logging, allocation or process
   creation inside observation windows. The exact capture/observer ordering and
   register preservation require a separate review, not simply moving C calls.
5. Optional future training must have a separately specified history, input order,
   repetition bound and reset protocol. If training changes memory, restore it
   before measurement and account for the cache effect of restoration. Do not
   assume preparation/reset leaves training intact, or that a training input may
   depend on the supposedly hidden value.
6. Finish within a parent-enforced deadline; validate every trial/count/result and
   release owned mappings, or fail the entire batch explicitly. Retain failure
   records and discard successful-looking partial batches from relational use.

This is containment for **reviewed code**, not hostile-code isolation. Do not
broaden admission to make batching easier. No guarantee of cache/predictor reset
is obtained on child restart; each new batch needs its own controlled preparation.

## 4. Model/native correspondence

### 4.1 Explicit location mapping, with a deliberately limited domain

Let `Cm=model.layout.code_start()` and `Dm=model.layout.data_start()` for actor 0.
Current tests use `Cm=0x200000`, `Dm=0x109000`, so model main is `Dm+4096=0x10a000`.
Let `Cn` and `Dn` be the native RX entry and RW main payload of the **live child**.
They are not the guard reservation bases or the model actor base. Proposed
correspondence for this admitted family only:

```text
model body PC Cm+p,  p in {12,16,20,24,28,32,36,40}
    <-> native body PC Cn+(p-12)
model main byte Dm+4096+d,  0 <= d < 4096
    <-> native main byte Dn+d
```

Native PC normalization back into original model coordinates is
`p = native_pc - Cn + 12` **only for body instructions**. Main address normalization
is `m = native_address - Dn + 4096`. For an access width `w`, require the entire
half-open range `[d,d+w)` inside `[0,4096)`; do not normalize an unsupported pointer
and thereby declare it valid. The admitted load/store use exactly `d=0,w=8`.

| ELF/model section interval | Native representation | Correspondence limit |
| --- | --- | --- |
| `[0,12)` start measurement macro/placeholder sequence | Omitted | Logical start event, not three hardware instructions with shifted PCs. |
| `[12,44)` eight actual body instructions | `[0,32)` identical bytes | Relative branch displacements remain valid after uniform translation. Native targets are offsets 16 and 20. |
| `[44,56)` end measurement macro/placeholder sequence | Omitted | End event has no identical native instruction. |
| `[56,60)` model exit NOP | Native `[32,36)` RET X30 is appended | Same broad completion purpose, different instruction/control state. Do not equate RET's PC/branch-predictor effects with the model NOP or measurement-end event. |

Source: exporter `tools/arm64_userspace_program.py:42-99`; model tracing
`rvzr/model_unicorn/tracer.py:68-82`; normalization
`rvzr/sandbox.py:249-263`; macro handling
`rvzr/model_unicorn/interpreter.py:241-247` and dispatcher
`rvzr/model_unicorn/model.py:90-102`.

Important boundary detail: the existing sequential `ct` regression includes
`pc=44`, the first measurement-end macro PC, because tracing precedes interpreter
handling. It is not an exported body instruction. See
`tests/unit_arm64_contract_slice.py:47-51`. A proposed adapter must preserve the
original contract trace and record boundary events separately, not map every PC
by subtracting 12. Under speculation macro tracing/termination can differ;
validate selected-contract traces, not just the sequential example.

There is **no mapping** for the model's faulty/register/underflow/overflow regions,
model utility/macro space, host stack, trusted trampoline, observer scratch or
shared result record. The native prototype does not allocate a complete actor
sandbox. Reported native addresses after cleanup are unusable for model rebinding;
an eventual adapter needs live preparation identity/stability or an explicitly
validated relative mapping. Never fix this by changing only `model._bases`.

### 4.2 Initialization, page geometry and termination

| Aspect | Production ARM64 Unicorn | Current userspace experiment | Required interpretation |
| --- | --- | --- | --- |
| Data layout | Active `SandboxLayout` is still 4-KiB logical geometry, actor stride 16384; `rvzr/sandbox.py:18,72-91`. `_load_input` writes main, faulty, pads and register areas (`model.py:698-756`). | One 4096-byte main payload inside a runtime 4096/16384-byte RW page, plus guards. On 16K, `[main+4096,main+16384)` is accessible padding, not an immediate guard. | Main-only correspondence is sufficient for this fixed 8-byte access. It does not validate boundary accesses, faulty-page permissions or activate the passive 16K actor layout. Serialization remains 12288 bytes regardless of OS page size. |
| Input registers | Slots 0-5 initialize X0-X5, slot 6 NZCV (shifted into bits 31:28), slot 7 SP; SP then overwritten with model RSP_INIT, X20 with main (`target_desc.py:160-163`, `model.py:735-756`). | Only X0 may be nonzero in transport; trampoline initializes X1-X7 and NZCV to zero. SP is an aligned host frame; X19/X20/LR are trusted host values. | Comparable projection is the tested X0-X7/NZCV/main result and SP alignment, not equal absolute stacks or every architectural register. Model X6/X7 are not InputData slots 6/7. |
| Other registers/SIMD | ARM input loading does not initialize arbitrary X8-X30 or Q registers as a general full-context reset; `usable_simd128_registers=[]` (`target_desc.py:165`). | Trampoline preserves ABI state; it does not zero every register or SIMD register. | Family cannot read unspecified state; do not generalize correctness/reset to newly admitted instructions. |
| Repetitions | Per-input execution/state/tracer/speculator/taint reset (`model.py:83-88,375-399`) and input memory reload; arbitrary emulator registers need not all be cleared. | Fresh private data/code per execution; main initialized once, then the store commits. | A future batch must restore main every trial. Otherwise the next trial starts from the previous sum, not the input snapshot. Architectural reset necessarily touches memory and must precede calibrated cache preparation. |
| Completion | Generated section/macros and model exit predicate/state machine (`execution_context.py:64,85-88`, `model.py:308-325,401-465`). | Controlled RET to the trusted capture trampoline, then normal child exit. | No general PC/LR equivalence. Native return/capture is outside the modeled test body but inside its physical history. |
| Faults/speculation | Fault handling and speculative checkpoint/store-log/flag/taint rollback (`model.py:448-495`, `speculator_abc.py:96-120,174-187`). | OS signal, abnormal exit or timeout invalidates the experiment; no architectural recovery or software rollback. | Fault-driven contracts/native faults remain unsupported. Hardware transient effects are not emulated or rolled back by the utility. |

The MOVZ family only changes data constants. For `(a,b)` the committed marker is
`b` when X0 is zero, otherwise `a`; the result is `(initial_word+marker) mod 2^64`.
The current oracle compares the whole reported projection, including untouched
main bytes, not just the stored word. Unobserved register preservation is supported
by source review and the trampoline sentinel test
`test_trampoline_abi_in_unicorn_not_native_evidence`, not full native register capture.

### 4.3 Contract equivalence before physical comparison

For a fixed program `P`, input `I`, contract `C`, nesting/window/configuration `K`,
define `T_C(P,I;K)` as the complete **typed**, ordered production model trace.
Compare hardware only for inputs whose `T_C` values are equal, using the same
program, contract settings and controlled trial-history protocol. Do not combine
different MOVZ images into one equivalence class merely because their address
traces happen to match.

`seq+ct` observes executed PC and memory byte addresses, not loaded/stored values
(`tracer.py:194-201`). The original taken trace is:

```text
pc12, pc16, pc28, pc32, mem4096, pc36, pc40, mem4096, pc44
```

The not-taken trace adds `pc20,pc24` in place of `pc28`, then shares the join.
Same branch direction with different main words is therefore a possible `seq+ct`
equivalence class despite different committed sums. Opposite branch directions
are not `seq+ct` equivalent merely because both access main. Equal final results
do not establish equal observations; equal observations do not require equal
results under this contract. The existing tests compare architectural state,
not a native instruction/memory event trace.

For conditional speculation, use actual `trace_test_case_with_taints(inputs,
nesting)` or `trace_test_case` as appropriate (`model.py:280-304`), freeze the selected
clause/window/nesting, and independently retrace **every** chosen boosted input.
`ARM64CondSpeculator._speculate_instruction` (`speculators_basic.py:211-241`) forces
the wrong direction and checkpoints the architecturally correct continuation;
this is a contract policy, not a fitted M3 predictor. Do not infer `cond+ct`
equivalence from `seq+ct`, taint masks, final state or a guessed wrong-path list.
Existing B3.4b/f fixtures test speculation in software but are **not** admitted
native programs.

The production boosting/collection path is `rvzr/fuzzer.py:226-258`; fast reuse
can copy parent C-traces without retracing. For initial physical validation,
require independent retracing rather than that optimization. Also reapply the
userspace input-subset validator: general boosted inputs may contain forbidden
nonzero fields. No current userspace batching/boosting adapter handles this.

Preserve `tuple(trace.get_typed())` as evidence and compare it explicitly in pilot
tests. `CTrace` hashes untyped values and `__eq__` compares hashes
(`rvzr/traces.py:62-65,130-159`); diagnostic hashes alone are not independent
evidence of complete typed equality. Its `l1d` visualization uses bits [11:6]
(`:75-84`); it is not an M3 physical cache map.

Relational testing compares distributions of physical observations for
contract-equivalent inputs under controlled history. If training history varies
between those inputs, either fix it independently or define/model the expanded
history explicitly; the current single-input contract is not automatically a
model of arbitrary training sequences. Reproducible differences are candidate
contract violations pending confound checks, not automatically vulnerabilities.

### 4.4 B3.5i: software-only correspondence and equivalence regressions

Source snapshot for this addition: `a6d0c81` before the scoped B3.5i changes.
The passive policy in [arm64_userspace_correspondence.py](arm64_userspace_correspondence.py)
and [focused tests](../tests/unit_arm64_location_correspondence.py) now exercise
the restricted correspondence above. They are not connected to any executor.
The PC functions accept only normalized body offsets; macros, `pc44`, `pc56`,
native RET offset 32, unaligned/unknown offsets and absolute PCs raise ValueError.
Tests compare every mapped instruction against the real generated ELF and actual
exported native image, in both directions. Actual raw tracer addresses are checked
against the production normalized typed trace, rather than merely assuming the
coordinate origin.

`main_access_to_offset(address,size,main_base)` requires the entire nonempty
half-open access inside the declared 4096-byte main region, using unsigned 64-bit
values and representable interval ends. For normalized model memory entries the
base is **4096**, not the input-format main offset zero; for model absolute
addresses it is `layout.get_data_addr(DataArea.MAIN,0)`; for native coordinates it
is a synthetic/caller-supplied main base. Tests cover every byte, every contained
eight-byte starting offset, the whole payload, cross-end accesses, negative/
overflowing values, incorrect types and unsupported regions. They do not infer
mapping ownership, provenance, liveness or physical permissions from arithmetic;
numerically aliased coordinate systems cannot be distinguished automatically.
This range policy does not authorize instructions of other access widths.

One fixed program is generated through the production template/assembler/ELF
path: original B3.4a constants 11/22, exported by the unchanged exact-image policy.
Its 36-byte SHA-256 is
`e475be5271ab347616fa2a5d83c4184b82e62d6f344337bfe2b96f2f90c59441`.
No new image, MOVZ family expansion or native execution is introduced.

Both configurations explicitly freeze ARM64, Unicorn backend, normal trace mode,
one actor, `ct`, nesting **1**, maximum speculation window **32**, no handled
faults, and synthetic bases `(0x109000,0x200000)`. The execution clause alone is
selected separately as `seq` or `cond`; tests check the actual speculator type and
effective nesting/window values. InputData is explicitly zero-initialized; only
X0 and the first main word are set. Exact raw serialization and userspace input
admission are checked. Each input is actually retraced individually, then retraced
again in reverse order; no C-trace reuse, hash comparison or boosting is involved.

| Input | X0 / initial main word | Final X0,X1,X2,X3 under both configurations | Typed-trace class, independently computed per configuration |
| --- | --- | --- | --- |
| A | 0 / 7 | 0,22,7,29 | Taken |
| B | 0 / 19 | 0,22,19,41 | Taken |
| C | 1 / 7 | 1,11,7,18 | Not taken |
| D | 1 / 18 | 1,11,18,29 | Not taken |
| E | 2 / 7 | 2,11,7,18 | Not taken |
| F | 0 / 7, byte-identical to A | 0,22,7,29 | Taken |

For each configuration the complete typed equality classes are `{A,B,F}` and
`{C,D,E}`. The **contents** of seq and cond traces differ; equality classes are
not inferred from each other. A/B are equal-C with different serialized data and
architectural results. A/F are identical inputs with repeatable complete results.
C/E have equal-C despite differing X0. A/D have equal stored words and full main
memory but different registers and non-equal C-traces. No pair is claimed to have
equal complete architectural state merely because its stored result is equal.

Complete observed typed traces follow (`pcN` means `CTraceEntry("pc",N)`, `memN`
means `CTraceEntry("mem",N)`; these are ordered lists, not sets or bitmaps):

```text
seq, taken (A/B/F):
pc12 pc16 pc28 pc32 mem4096 pc36 pc40 mem4096 pc44

seq, not taken (C/D/E):
pc12 pc16 pc20 pc24 pc32 mem4096 pc36 pc40 mem4096 pc44

cond, taken (A/B/F):
pc12 pc16 pc20 pc24 pc32 mem4096 pc36 pc40 mem4096 pc44 pc56
pc28 pc32 mem4096 pc36 pc40 mem4096 pc44

cond, not taken (C/D/E):
pc12 pc16 pc28 pc32 mem4096 pc36 pc40 mem4096 pc44 pc56
pc20 pc24 pc32 mem4096 pc36 pc40 mem4096 pc44
```

The conditional trace retains the wrong-path join, measurement-end event and
model exit-NOP `pc56`, then the correct continuation after model rollback. This
is real production-model output, consistent with the audit's **limited** mapping
domain, not a contradiction of its body mapping. `pc56` must be rejected by the
body mapper; it is not native RET. The two `pc44` observations must not be silently
deduplicated. Compared X0-X3/NZCV/main agree between seq and cond and
reset correctly across repetitions; nesting and pending faults return to zero.
This is software contract behavior, not physical misprediction evidence.

Run on x86-64 WSL2 with cross-binutils (or native AArch64 with native binutils):

```bash
RVZR_ARM64_BINUTILS_PREFIX=aarch64-linux-gnu- \
  python -m unittest tests.unit_arm64_location_correspondence -v
```

On native ARM64 omit that environment override; no additional dependencies or
native-executor change are needed. The existing native userspace architectural
CI step now selects both modules (45 tests), retaining `RVZR_REQUIRE_NATIVE=1`
so all three native-execution tests must run rather than skip. B3.5i subsequently
passed this 45/45 native CI run, as reported by the user; target M3 validation remains pending.
Tests print JSON records containing actual full typed traces, effective
configuration, input identities/hashes, image hash and architectural results.
This supplies software equivalence evidence only: it creates no HTrace and does
not validate live native addresses, instruction retirement, page permissions,
cache-state equivalence, measurement boundary placement or M3 behavior.

Local WSL2 validation (Unicorn 1.0.3): all **9 new tests passed**, including 37
actual model executions in the focused module. The combined regression command
covering the new module, all existing B3.5d-g tests, B3.4a-f model tests and related
preparation/trace/serialization/geometry tests ran **270 tests: 267 passed, 3
native-only skips**. Seven separate ARM64 generator/ISA regressions also passed.
Flake8, strict mypy, Pylint and `git diff --check` passed. Subsequent user-reported
native CI with Unicorn 2.1.4 passed all 45 combined tests; no M3 execution is established.

## 5. Physical observation: evidence required

### 5.1 Available starting point and conceptual candidates

The existing calibration is separate from the architectural runner:

* `tools/arm64_timer_calibration.c:38-51`: `ISB; MRS CNTVCT_EL0; ISB` with compiler
  memory barriers; empty/buffer windows add `DSB ISH` before **each** timestamp.
  This conservative wrapper includes barrier overhead; it is not an optimized
  single-load observer or a measured M3 ordering implementation.
* `:54-104`: adjacent reads, empty windows, then load/checksum work on an owned
  512-byte buffer. Prior loads do not prove L1 residency; minimum positive observed
  increment does not prove intrinsic counter resolution.
* `:109-139,232-275`: independent CNTFRQ probe and calibration children, pinned
  affinity, start/end CPU checks, prefaulted result storage, explicit trap/errors.
  A null frequency can coexist with successful tick-domain measurements; never
  substitute macOS's reported 24 MHz or call counter ticks CPU cycles.
* `tools/verify_arm64_timer.py:68-188,191-212` validates the JSONL protocol, not timer
  accuracy. The CLI checks 32 samples/series and two loads; the existing M3 protocol
  uses its validator API for 128 samples and repeated workloads. Run_worker waits
  are not internally timed, so retain the protocol's external process-group bound.

Follow [B3.5c's existing M3 protocol](README.m3-timer-protocol.md), especially
its provenance/CPU selection, two sessions, rotated load counts, retained raw
measurements and decision gates (`:33-189,238-285`). Its replicate-range median
criterion for loads 128 versus 1 is only a coarse work-sensitivity pilot gate;
passing it does **not** establish single-access hit/miss discrimination. Synthetic
host tests verify failure/format paths; native timer smoke verifies only that
runner's accessibility/protocol. No M3 timer result is available here.

| Candidate, concept only | What it might observe | Prerequisites and limits |
| --- | --- | --- |
| Timer around the whole fixture | Aggregate elapsed ticks, including taken-path instruction-count differences and wrapper cost. | Requires suitable ordering/resolution and matched null windows. Never time subprocess/fork/JSON and interpret it as fixture latency. Different branch paths may be legitimately distinct C-traces; a time difference alone is not leakage. |
| Timed access to one owned probe location after controlled preparation | Operationally defined resident/absent timing distributions. | Best first cache pilot, separate from generated-code execution. Need validated state preparation, correct timestamp/load ordering and held-out discrimination. A probe perturbs its own state; repeated reads do not repeatedly observe the original miss. |
| Multi-location reload/eviction/set observations | Possible future cache bitmap or richer observation. | Requires physical geometry, congruence/eviction effectiveness, capacity, ordering and interference evidence. No eviction-set construction or unprivileged flush capability is demonstrated. No automatic Prime+Probe/Flush+Reload/Evict+Reload route follows from this audit. |

Do not change timer ordering to obtain prettier separations, silently substitute
a clock on a trap, or assume barriers/cache-publication operations create a
desired measurement cache state. Stop on unavailable facilities and diagnose.

### 5.2 Minimum cache-pilot validity protocol (future, separately authorized)

1. **Provenance and timer:** preserve source/binary hashes, actual M3/Linux/kernel/
   page identity, affinity and core evidence. Establish successful counter reads,
   advancing/ordered counts, wrapper overhead, quantization, work sensitivity and
   cross-session repeatability. Single-load resolution remains an open question
   even if larger loops separate. Unknown frequency requires tick-domain reporting.
2. **Independent state preparation:** define what absent means: L1-absent but
   lower-cache-resident is different from absent from all caches/DRAM access.
   Use only owned memory and an independently validated unprivileged method.
   Neither larger-than-cache allocation nor repeated warm loads prove the label.
   If physical ground truth cannot be justified, report operational preparation
   classes and their timing differences, not verified L1 hit/miss labels.
3. **Matched controls:** same target address, access width, input data, code,
   alignment and wrapper; differ only in intended preparation. Prefault/warm
   translations separately, account for prefetch/alias/lower-level effects, and
   preserve an explicit no-target-access/null condition. Observer metadata,
   result stores and reset loops must not themselves supply the classified signal.
4. **Sampling:** interleave/randomize preparation labels with a recorded seed,
   balance batches, retain ordered raw ticks and failures, and repeat independent
   sessions/mappings. Separate CPUs/core types and known session conditions. Do not
   call correlated consecutive samples independent or discard slow samples post hoc.
5. **Core/scheduling controls:** pin and verify worker affinity; record readable
   MIDR/topology/cache evidence as in B3.5c. Unknown Linux core identity stays
   unknown; do not infer it from CPU numbering. Record start/end CPU and available
   scheduling/fault diagnostics, with their attribution limits. Affinity restricts
   eligible CPUs; it does not disable other tasks or interrupts. See
   [sched_setaffinity(2)](https://man7.org/linux/man-pages/man2/sched_setaffinity.2.html).
6. **Calibration versus validation:** choose thresholds/encoding and an error
   budget using calibration data only, then freeze them before held-out sessions.
   Estimate false-resident/false-absent rates with denominators and confidence
   intervals at batch/session level; retain an inconclusive outcome if needed.
   AUC or a separated mean is not a replacement for held-out errors. With unknown
   true cache state, label errors relative to preparation classes, not proven L1
   ground truth. No numeric tick threshold or acceptable error rate is invented
   before measurements and a campaign false-alarm budget exist.
7. **Relational reliability:** identical-input/null pairs must agree within the
   declared error budget across order changes and repetitions; known preparation
   controls must remain distinguishable on held-out data. Correct for repeated
   comparisons, account for autocorrelation/history and revalidate after platform,
   mapping, core or observer changes. Overlap, drift, excessive false positives/
   negatives or a setup-dependent signal means inconclusive/no-go, not a new
   arbitrary threshold until it passes.

For a later code-associated probe, explicitly locate the observation window
relative to the native body, RET, trampoline result spills, full-main copy,
postcondition scans and cleanup. Capturing registers first can perturb a cache
probe; probing first can clobber registers/flags or change timing. A reviewed
combined shim must resolve this trade-off. Neither the current post-run JSON nor
the current full-main copy is an observation of untouched post-body cache state.

## 6. Requirements for a Revizor-compatible HTrace interface

Production `Executor.load_test_case` and `trace_test_case(inputs,n_reps)` are
kernel/sysfs-backed (`rvzr/executor.py:258-324`); `read_base_addresses` (`:360-373`)
also reads sysfs. Do not instantiate this adapter for the module-free pilot.
A future adapter would have to supply **one real HTrace per input**, containing
the declared repetitions, while preserving order/ignore-list/priming semantics
and failing explicitly on any incomplete execution. Current architectural JSONL
is a separate result type, not something to relabel as cache leakage.

Before registration, specify and test:

* Program image/hash, input identity, live mapping/batch identity, contract/config,
  CPU/session, trial/repetition/training order, status and complete raw measurements.
  Keep this provenance in an accompanying artifact; six numeric sample fields
  alone cannot carry it. Existing passive kernel-layout descriptors are not an
  automatically valid description of this main-only userspace allocation.
* Units and semantics: elapsed counter ticks, a classified probe bitmap, or another
  justified physical quantity; line/probe indices are not contract byte addresses.
  A 64-bit storage word does not establish 64 independent cache observations.
  At reported 128-byte granularity a 4-KiB payload spans 32 aligned line positions,
  conditional on that runtime line size/alignment; this says nothing about sets,
  associativity or eviction. Keep logical payload/page/encoding dimensions separate.
* `RawHTraceSample` has uint64 trace plus five uint64 PFC fields; `HTrace` currently
  accepts types cache/tsc/reg and treats all-zero trace samples as invalid
  (`rvzr/traces.py:174-224`). A legitimate empty bitmap or zero tick delta must not
  silently become a failed experiment. Define explicit validity/encoding before
  reuse. Do not fabricate PFC measurements; any reserved unused fields need stated
  absence semantics rather than a claim that zero was measured.
* Do not route raw CNTVCT ticks blindly through the legacy TSC path: it masks low
  four bits (`rvzr/executor.py:351-353`). Nor assume the legacy cache validity-bit
  convention, 64-position visualization or merged-bitmap analyser is suitable.
  Choose a physically justified representation and compare distributions with
  calibrated error handling before using existing analyser entry points.
* `EquivalenceAnalyserCommon.filter_violations` (`rvzr/analyser.py:90-149`) first
  groups by C-trace, discards empty/corrupt H-traces, then compares H distributions;
  bitmap/statistical subclasses impose further assumptions. These APIs are useful
  integration targets, not evidence that a new observer is statistically valid.

No HTrace is constructed from guessed timing, an oracle, Unicorn output or
architectural-state JSON in this milestone. Unsupported/noisy measurements remain
failed or inconclusive raw experiments, not synthetic success traces.

## 7. Spectre-v1 scope

The MOVZ16 family has a conditional branch, different instruction images and
different committed arithmetic results. Both paths rejoin before the same load
and store at main; X1 affects stored data, not a selected address. The selector
is supplied directly in X0. There is no implemented training history, delayed
checked access, secret-dependent probe address, information boundary or physical
observer. The unconditional architectural store itself touches the same target
line regardless of path. Observing that line later cannot by itself identify a
transient access to it.

A future controlled Spectre-v1-style study would need, conceptually, a conditional
check and measured incorrect transient direction; a memory dependency relevant
only transiently under the chosen information policy; an explicitly defined
protected-versus-public input boundary; and a measurable persistent physical
effect carrying information not allowed by the contract. All data can remain in
the experiment's own address space; a protected information boundary need not be
a kernel permission violation. Its definition and the allowed observations must
be explicit. These are distinct from successful architectural execution or a
forced software misprediction. The original
[Spectre paper](https://arxiv.org/abs/1801.01203) motivates the distinction between
discarded architectural effects and measurable side effects; it establishes no
specific M3 Pro behavior here.

No gadget, new instruction sequence or secret-extraction procedure is added.
Even a future reproducible equal-C/different-H result could be another form of
data-dependent timing, an inadequate contract or an experimental confound.
Spectre-v1 attribution requires separate causal controls showing dependence on
the transient branch behavior and excluding ordinary committed accesses.

## 8. Evidence gates and work placement

Gates are ordered for interpreting end-to-end results. The standalone timer
protocol can be run independently of generated-code authorization; passing it
does not bypass the architectural-compatibility gate.

| Gate | Required evidence / scope | Stop or inconclusive conditions | Still unsupported after passing | Where |
| --- | --- | --- | --- | --- |
| G0: architectural CI baseline | Existing 45 tests/102 executions, exact admitted images, oracle and corresponding seq-model agreement, failure admission and typed correspondence/equivalence regressions. Reported passed. | Any mismatch, missing native execution, unsafe publication or admission regression. | Target M3/16K compatibility and physical observations. | Host tests on WSL2; actual instruction execution on native AArch64 CI. |
| G1: actual Fedora Asahi architectural compatibility | Record actual OS/kernel/page size/M3 identity; compile and run existing approved architectural tests unprivileged, check all states/repeats/cleanup and actual 16384-byte geometry if present. | Signals, policy rejection, mismatch, unexpected page size or incomplete output; diagnose without disabling protections. | Timer precision, speculation or cache behavior. | Physical M3 Pro Fedora Asahi; generic 16K CI could supply additional, non-M3 evidence. |
| G2: M3 timer feasibility | Existing B3.5c protocol: raw JSONL, independent frequency result, CPU/core evidence, overhead/quantization/work sensitivity and repeated sessions. | Trap, backwards/nonadvancing run, CPU mismatch, incomplete output or inconclusive work sensitivity. | Single-load cache discrimination, L1 residency or leakage. | Prepare verifier/format checks on WSL2/CI; actual result only on target. |
| G3: controlled cache-state discrimination | Separate owned-memory pilot; justified preparation labels, matched controls, interleaving, frozen classifier, held-out errors and stated scope (e.g. operational residency, not automatically L1). | Unknown labels, quantization/noise overlap, excessive held-out errors, drift or observer contamination. | Generated-program observations or Spectre behavior. | Physical M3/core-specific; other ARM CPUs only development evidence. |
| G4: repeatable physical observation of a safe fixture | Later reviewed observer boundary and bounded hybrid batch, same admitted family; stable live mapping, explicit resets/history, raw samples plus architectural oracle, duplicate/null controls and independent sessions. | Architecture drift, reset/cleanup failure, stale identity, probe signal explained by capture/setup, inconsistent duplicates. | Contract violation: inputs may legitimately have different C-traces. | Host tests can verify protocol/reset/admission; native CI tests only its CPU; M3 measurements required. |
| G5: selected input C-equivalence | Same program and fixed contract/window/nesting; independently computed complete typed traces for every input/boost; userspace input admission and location mapping tests. | Changed configuration, traces differ, unsupported input fields/locations, inferred rather than computed equivalence. | Physical equivalence, or adequacy of a software speculation policy for M3. | WSL2 and native ARM64 software; no hardware needed to compute C-traces. |
| G6: compatible observation interface | Actual observations encoded without fake data, explicit validity/units/counts, tested per-input order and failure paths, live preparation correspondence, suitable analyser semantics and retained provenance. | Zero/invalid ambiguity, truncation, bit-capacity loss, inappropriate masking, missing repetitions or fabricated counters. | Statistical reliability outside calibrated sessions or detection of a vulnerability. | Host fixtures can test transport; actual integration validation requires target observations. |
| G7: bounded relational testing | Equal-C groups, repeated equal-input controls, randomized/balanced physical comparisons, held-out calibration and multiplicity/error controls, reproducible candidates and diagnosis. | Order/history/core confounds, exhausted false-alarm budget, failure treated as a trace or nonreproducible differences. | Universal contract compliance, absence of leaks, Spectre-v1 attribution or arbitrary-program safety. | Software preparation on WSL2/CI; genuine M3 H-trace comparisons on target. |

These gates do not reopen the unsafe native kernel route. Its mapping/PTE/fault
recovery blockers remain separate prerequisites for that executor, not problems
to bypass by calling it from the userspace experiment.

## 9. Smallest justified next step and open questions

**Next physical experiment:** collect the existing B3.5c timer protocol on the
actual native Fedora Asahi M3 Pro, as an ordinary user, preserving the entire
results directory, actual page size and CPU identity evidence. No generated code,
kernel module or new utility is needed. Keep any first architectural Fedora
compatibility run a separate G1 result; neither experiment proves the other.
If Linux is not yet available, report that dependency rather than substitute CI
timings or macOS measurements.

**B3.5i implemented and locally validated:** the passive correspondence policy and
nine software-only regressions cover body PCs, measurement boundaries, RET
exclusion, main-memory access ranges, unsupported locations and complete typed
`seq+ct`/`cond+ct` equivalence for the six-input matrix in section 4.4. No execution
engine, observer, runtime rebinding or new instruction admission was introduced.
The existing native ARM64 CI step passed both regression modules together:
45/45 tests, as reported by the user. This establishes software correspondence/
equivalence on that runner, not physical M3 Pro trace equivalence or
microarchitectural leakage. The remaining work is the physical G1/G2 evidence in
the [experiment runbook](README.m3-experiment-runbook.md).

Open questions that require evidence rather than further instruction expansion:

* Does the actual Fedora Asahi policy permit the current RX publication/return
  sequence without protection changes, and does the 16K native architecture matrix
  pass? Current page-arithmetic tests do not answer this.
* Can the M3 counter wrapper resolve the needed single-access signal, on which
  independently identified core, with what quantization/overhead/noise? The macOS
  timebase and larger-loop timing cannot answer this.
* Can permitted owned-memory preparation establish a repeatable physical contrast
  without assuming line size, set indexing, associativity or privileged flushing?
* Does the proposed capture/probe/reset sequence preserve the desired cache and
  predictor conditions? Stable addresses and a successful return are insufficient.
* What classifier/error budget remains reliable across batches, mappings and
  sessions, and can it support enough relational comparisons for the thesis?
* Would the chosen speculation contract permit or expose the measured behavior?
  Forced wrong-path Unicorn execution is not a measurement of an M3 predictor.

B3.5h added only this document; B3.5i adds the passive policy, focused software
tests, section 4.4 above and selection of the new module in the existing native
CI step. No timer, observer, model, executor, kernel or instruction-admission
behavior changes. No hardware execution was performed during local B3.5i work;
the existing native architectural tests remain enabled in CI.
