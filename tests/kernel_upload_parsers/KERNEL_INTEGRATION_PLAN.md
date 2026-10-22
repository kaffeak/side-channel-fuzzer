# B3.3d.4b: kernel integration decision and implementation gate

Design only, based on the current source. No device, ABI, cleanup guarantee or
16 KiB execution support is introduced by this document. Use **fail-closed
replacement**: never restore an older executable preparation after replacement
has begun. The selected path is a per-open misc-device interface, one global
preparation mutex, and explicit native ownership/retirement prerequisites.

The evidence baseline is [RESOURCE_OWNERSHIP.md](RESOURCE_OWNERSHIP.md),
[PREPARATION_PROTOCOL.md](PREPARATION_PROTOCOL.md),
[PREPARATION_STATE.md](PREPARATION_STATE.md), [PARSER_RESET.md](PARSER_RESET.md)
and [ATTEMPT_UPLOAD.md](ATTEMPT_UPLOAD.md). Reuse their state transitions and
actual parser/reset implementations, not the test adapter's fake resources.
The reported 59 host tests per configuration (58 passes, one expected failure)
establish adapter/parser behavior only. The legacy interrupted-RDBF defect
remains present; none of the proposals below repairs it today.

## 1. Transport decision

| Option | What it supplies | Remaining problem / decision |
| --- | --- | --- |
| Per-open character file, registered as one misc device | `open`, `write`, `unlocked_ioctl`, `read`, `release`, and kernel-owned `file->private_data` | Requires a small producer adapter and user-copy handling. **Selected**: expresses attempt lifetime and final-close abort directly. |
| Framed operations through existing sysfs stores | Every frame could carry an attempt token, expected offset and operation | Still needs framing, producer changes, locking and cleanup. Ordinary `store(kobject, attr, buf, count)` has no per-open context or close callback. It cannot supply the required close-abort semantics without another lifetime mechanism. Do not implement both transports. |

Linux documents the relevant [VFS file operations and per-file state](https://docs.kernel.org/filesystems/vfs.html#struct-file-operations),
[misc-device registration](https://docs.kernel.org/driver-api/misc_devices.html)
and [sysfs attribute callbacks](https://docs.kernel.org/filesystems/sysfs.html#attributes).
Misc registration initially supplies a miscdevice pointer as `private_data`;
custom `open` must replace it with an allocated handle. `release` concerns the
last reference to the open file description: `dup`/`fork` do not create distinct
attempts, and closing one duplicate must not abort a still-open attempt.
There is no committed device name, ioctl number or sysfs layout attribute here.

### Minimal handle contract

Control operations are BEGIN_TC, BEGIN_INPUT, COMPLETE, ABORT and GET_STATUS;
FEED is `write` of unchanged RCBF/RDBF bytes. Later EXECUTE and `read` cover trace
results. Use fixed-width control records (`__u32`, `__u64`, explicit reserved
fields), no native pointers/`long`/`size_t` in the UAPI, reject unknown flags and
nonzero reserved fields, and review compat handling before registration. Follow
the [kernel ioctl guidance](https://docs.kernel.org/driver-api/ioctl.html);
new incompatible operations need new command numbers, not reinterpretation.

| Handle event | Required kernel action |
| --- | --- |
| Open | Allocate an unbound context; do not reset parsers or invalidate preparation. Set file-operations module ownership and reject seeking. |
| BEGIN | Check expected instance/revision, kind, parent, declared length and global availability before mutation. Bind this handle **once** to the kernel-assigned attempt, kind, parent and length. A rejected BEGIN cannot disturb a newer preparation. Another active owner returns `-EBUSY`; stale snapshots return `-ESTALE`. |
| Accepted TC BEGIN | Withdraw TC/input eligibility, address snapshot and results first. Reserve attempt in CLEANING; retire old native resources, reset both real parsers, then acknowledge safe cleanup and allow TC_RX. Never acknowledge safety from counters/stubs. |
| Accepted input BEGIN | Require the named committed TC, withdraw input eligibility/results, reset the input parser before admitting INPUT_RX. The TC is retained only as the explicitly named parent. |
| FEED | Under the mutex check the bound attempt, instance, kind/parent and RX phase **before parser entry**. Identity alone does not authorize feeding VALIDATE/ALLOCATE/LOAD. Count only positive actual consumption. |
| COMPLETE | Require exact declared receipt and successful parser completion. A negative parser return wins over `finished=true`. Perform real validation/allocation/loading before TC commit; validate input length/metadata/association before input commit. Commit never follows merely from `!receiving`. |
| ABORT, accepted-attempt failure, final close while incomplete | Revoke the current attempt and entire preparation, including an input attempt's parent; invalidate results, retire owned resources and reset both parsers. A stale close/abort frees only its handle; it must not reset a newer parser. |
| Close after commit | Free handle only; do not undo committed TC/input state. Committed/aborted handles cannot be rebound. Retry uses a new open and fresh TC, then inputs. |

One mutable parser owner exists globally, not one parser per file. Do not allow
two files to interleave parser bytes. BEGIN identity checks, resets and native
cleanup form one serialized boundary; a concurrent FEED cannot observe the
temporary RX label before reset finishes. Obtain a fresh nonzero instance at
module construction, never reinitialize a live/terminal state to escape failure.
Keep checked revision/allocation-generation behavior from `rvzr_prep_*`.

### Byte transport and user-copy rules

- Use an aligned, kernel-owned bounce buffer, initially at most **4096 bytes per
  parser call**, independent of kernel PAGE_SIZE. Accept a larger `write` by
  returning a positive bounded short count. Initially require the first write to
  contain at least the complete 16-byte header; forward exactly that header, not
  an invented padded header. Smaller first writes return `-EINVAL` without parser
  entry. Document this producer requirement rather than silently losing bytes.
- `copy_from_user` must succeed for the proposed chunk before parsing. Its return
  is bytes not copied, not a parser return. Reject a failed copy with `-EFAULT`
  and no accepted bytes. Copy before taking the global mutex, then revalidate
  handle/phase/position under it. The open-file operation retains the context
  lifetime; user memory is never retained or passed directly to the parsers.
- Bound requests by remaining declared bytes using subtraction, check returned
  consumption is in `1..forwarded_count`, and advance only by that amount.
  A zero-length write is not COMPLETE. Producers retry only the unconsumed tail
  after positive short returns; they must serialize their writes on shared FDs.
- Early completion, exhausted length without completion, zero parser progress on
  nonempty input, extra bytes, or negative parser returns cannot commit. An
  accepted parser error fails the attempt; do not report the whole chunk as
  consumed. A parser may have mutated state before an error, so retry requires
  explicit failure retirement, not replay of the failed chunk.
- Return zero for successful control operations; expose IDs/status through
  GET_STATUS. Failed status copying cannot undo a committed preparation or cause
  the client to replay BEGIN on an already bound handle. No user-supplied token
  may overwrite the handle's immutable kernel binding.

User-copy can sleep; see [kernel user-access documentation](https://docs.kernel.org/kernel-hacking/hacking.html#routines-and-conventions).
This mechanism prevents obsolete operations entering parsers; it is not a
general validation/security proof for arbitrary uploaded instructions.

## 2. Exact native integration surface

All line references below describe the source at this assessment, not a proposed
new implementation.

| Source / functions | Resource or behavior the coordinator must control |
| --- | --- |
| [main.c:316](../../rvzr/executor_km/main.c#L316), `test_case_store`, `check_test_case_compat` at :291 | Withdraws both readiness flags/results; parses, then allocates and loads before setting `tc_ready`. No whole-preparation unwind. ARM compatibility currently adds no checks in this helper. New completion must call the real underlying work, not feed this unbound callback. |
| [main.c:364](../../rvzr/executor_km/main.c#L364), `inputs_store` | Withdraws input readiness/results, requires TC readiness, parses and publishes input readiness. No attempt/parent identity. |
| [test_case_parser.c:193](../../rvzr/executor_km/test_case_parser.c#L193), [input_parser.c:90](../../rvzr/executor_km/input_parser.c#L90) | Actual parser entry points; real resets at TC :357 / input :198; free functions at TC :382 / input :215. Parser-completion predicates at TC :308 / input :180 mean only idle. TC sets finished at :291 before validation at :293. |
| [sandbox_manager.c:174](../../rvzr/executor_km/sandbox_manager.c#L174), `allocate_sandbox` | Growth replaces utility/data and code, publishes aliases, zeroes data and caches PTEs. Same/decreased counts reuse storage but still mutate it. `old_n_actors` records last success, not actual surviving capacities. |
| [code_loader.c:39](../../rvzr/executor_km/code_loader.c#L39), `load_sandbox_code`, `load_section_main`, `load_section` | In-place code overwrite and macro expansion; entry/fault aliases can be published before all sections succeed. `free_code_loader` at :251 does nothing. |
| [page_tables_host.c:208](../../rvzr/executor_km/page_tables_host.c#L208), `cache_host_pteps`, `store_orig_host_permissions` at :255, restoration at :312 | Borrowed leaf-PTE pointers, snapshots and faulty-PTE scratch arrays. They need allocation identity, initialized extents and independent capacities. |
| [main.c:248](../../rvzr/executor_km/main.c#L248), `trace_show`; [measurement.c:324](../../rvzr/executor_km/measurement.c#L324), `trace_test_case` | Admission, real experiment, measurement allocation and global result cursor. `unfinished_call` remains true on trace error at main :263; clearing it without checking CPU restoration is not a repair. |
| [main.c:349](../../rvzr/executor_km/main.c#L349), `test_case_bin_read`; base reads :400/:405; debug reads :535/:560 | Read aliases/allocation contents without coherent preparation identity. Binary read replaces requested count with a PAGE_SIZE-derived count and uses the entry pointer as its origin. It needs independent offset/count/allocation bounds review, not just a mutex. |
| [main.c:667](../../rvzr/executor_km/main.c#L667), `executor_init`, `executor_exit` at :751 | Manager construction, interface registration, init-error unwind, admission shutdown and destruction. Current OR-combined initialization has no per-stage reverse unwind, and exit frees resources before removing the kobject. |

The passive state component is still absent from
[Kbuild's common source list](../../rvzr/executor_km/Makefile#L44).
Its `cleanup_done(true)`/commit calls are trusted attestations, not native checks.
Kernel integration must supply actual evidence for each call, with no fake-ledger
fallback. Avoid two independently writable readiness authorities: during eventual
cutover derive compatibility flags from the locked coordinator state, or remove
their use from protected admission entirely.

## 3. Native cleanup: prerequisites, not established recovery

The [ownership audit](RESOURCE_OWNERSHIP.md#ownership-and-release-matrix) remains
valid. Minimum production obligations are:

| Resource | Current acquire / mutation / release | Required change before retry can be certified |
| --- | --- | --- |
| Contiguous utility/data block, page array, unaligned vmap and aligned interior alias | `allocate_util_and_data` [sandbox_manager.c:85](../../rvzr/executor_km/sandbox_manager.c#L85); `safe_free_util_data` :32 | Record actual backing head/order, mapping extent and initialized ownership independently. Retire borrowed PTE references and exported aliases before unmapping. Free original map/block exactly once, not an aligned interior address. Clear ownership/capacity on every release/failure. |
| Code allocation and executable extent | `allocate_code` [sandbox_manager.c:139](../../rvzr/executor_km/sandbox_manager.c#L139); `safe_free_code` :48 | Record actual allocation/pages and permission-transition status; check X/NX returns (:148/:51 currently ignored). Do not free/reuse code on an unproven permission/retirement path. Check target-kernel executable-memory and instruction-cache synchronization requirements before admitting new code. |
| `sandbox_t` and data/util/code aliases | `init_sandbox_pointers` [sandbox_manager.c:59](../../rvzr/executor_km/sandbox_manager.c#L59); manager free :294 | Descriptor has no matching `kfree` today. Define its owner, clear all borrowed aliases on retirement, and free once at final teardown. Do not publish `loaded_test_case_entry=code` (:67) as executable readiness before loading. |
| Entry, fault handler and macro/prologue state | [code_loader.c:72](../../rvzr/executor_km/code_loader.c#L72), :81/:128/:155; [macro_expansion.c:22](../../rvzr/executor_km/macro_expansion.c#L22), setter :33; [arm64/macros.c:337](../../rvzr/executor_km/arm64/macros.c#L337) | Withdraw before any overwrite, clear on every failure, and publish the completed entry only after all sections succeed. Loader's continuing OR-error loop is not atomic publication. Track/clear auxiliary scalar state too. |
| PTE cache, original snapshots, faulty scratch | [page_tables_host.c:208](../../rvzr/executor_km/page_tables_host.c#L208), :255; init :440, free :466 | Separate capacity from last actor count and record valid entries/snapshot epoch. Restore only a known captured snapshot while its mapping is live. Invalidate borrowed pointers before backing release; never restore through stale PTEs. Partial array allocation/walk failure must leave a defined inert state. |
| Parsed TC, actors/symbols/sections and RDBF buffers | Actual parse/reset/free functions above | Retire native consumers before resetting metadata they may need. Check both resets; a missing root can require allocation and fail. Host allocation tracking does not test the kernel `-ENOMEM` branch. |
| Measurements and pagination | [measurement.c:348](../../rvzr/executor_km/measurement.c#L348), `alloc_measurements`; free :369; main cursor :247 | Record real capacity only after successful allocation; current counter advances before freeing/allocating. Withdraw result identity/cursor before mutation. No old results become visible after an accepted replacement, even if backing storage is retained. |
| Guest resources, vectors and CPU state | [arm64/page_tables_guest.c:23](../../rvzr/executor_km/arm64/page_tables_guest.c#L23); [arm64/fault_handler.c:51](../../rvzr/executor_km/arm64/fault_handler.c#L51); measurement pre/post/recovery | Initially reject unsupported guest/user execution rather than attest cleanup. ARM guest mapping is unimplemented. VBAR, IRQ/preemption state, special registers and PMU state require execution-path restoration review on the executing CPU; freeing upload buffers does not restore them. |

Retirement order under exclusion: withdraw eligibility/results and public aliases;
establish no active execution and completed CPU/PTE restoration; retire snapshots
and borrowed PTE references while mappings still exist; revoke executable access
with checked status; release code/mapping/page owners; reset parsers; acknowledge
clean state only when every applicable obligation is established. Keep private
owner addresses available for cleanup after public aliases are withdrawn.

**Current answer: arbitrary native allocation/load failure is not known safely
retryable.** A data growth failure may have destroyed old storage before alias
refresh; a later smaller request can skip rebuilding it. PTE cache/snapshot
high-water state and partial loading introduce additional retry windows. Neither
stub success nor a new preparation generation resolves those cases.

Use `UNRECOVERABLE` on unknown cleanup/restoration: revoke all IDs and results,
reject preparation/execution/resource reads, retain tracked objects in quarantine,
and permit only scalar status. Do not blindly call all destructors, restore the
old TC, or call `rvzr_prep_init` again. Ordinary module removal must be prevented
while native safety is unknown (for example, a deliberately tracked, single
quarantine module reference acquired before the relevant unsafe operation).
Review this lifetime mechanism before activation; a terminal enum alone cannot
prevent unload. Current `executor_exit` returning early is a void callback, not
a safe unload veto. Recovery then requires reboot or an independently validated
quiescence/cleanup procedure; **module unload/reload is not presumed safe**.

## 4. One synchronization boundary

Use one sleeping coordinator mutex, acquired in process context for every state,
parser, native resource, execution and result operation. Do not use a spinlock
around parsers, `vmalloc`, permission transitions or user copying. The
[kernel locking guidance](https://docs.kernel.org/kernel-hacking/locking.html)
distinguishes sleeping locks from atomic/interrupt contexts.

Initially keep synchronous execution under this mutex, including identity
validation, preflight, experiment and checked restoration. Releasing it between
check and execution would reintroduce the race the identity is meant to prevent.
Fault/vector/IRQ handlers must not acquire it or call sleeping coordinator code.
Low-level helpers called with it held must not recursively lock it. If a later
per-file lock is necessary, order **per-file lock -> coordinator**, never reverse;
the first implementation can serialize all operations with the global mutex.

- BEGIN/reset/feed/COMPLETE/ABORT/release all check owner and phase under the lock.
  Allocations and retirement occur only in its sleepable process-context portion.
- EXECUTE on a separate unbound handle checks the exact committed
  `(instance, tc_id, input_id, allocation_generation)` and supported layout, then
  binds that handle to a result sequence. Each execution gets a distinct checked
  result ID, even for the same preparation. Repeated reads paginate only that
  result; they do not implicitly execute again. A new BEGIN/execution invalidates
  prior result bindings before reusing measurements.
- Each result page rechecks preparation and result identity under the mutex.
  Initially format/copy one bounded page and advance its cursor only after
  successful user-copy, holding the mutex through the copy **after IRQs and
  preemption are restored**. This permits user faults to delay other operations;
  it is a simple serialization choice, not a bounded-latency guarantee. Do not
  release the lock around borrowed buffer reads without a separately designed
  pinned snapshot/lifetime mechanism. All control-output structures are fully
  initialized, including padding; failed copying must not publish readiness.
- Base/layout and optional code/debug reads need the same liveness/identity gate.
  Snapshot values are not allocation leases. Disable unsafe raw reads initially;
  do not carry forward the current `test_case_bin_read` bounds behavior.
- Teardown first marks stopping and revokes admission under the mutex, then drops
  it before deregistering/removing interfaces and waiting for callbacks. Otherwise
  kernfs removal could wait for a callback waiting for this mutex. Drain users,
  then reacquire exclusive ownership for validated retirement and reverse-order
  manager destruction. File operations need `.owner = THIS_MODULE`; registration
  removal alone does not release existing per-open contexts. Do not force unload.

### Execution blocker discovered in the current call graph

[measurement.c:143](../../rvzr/executor_km/measurement.c#L143) disables preemption;
:146 disables IRQs. `run_experiment` then calls `set_sandbox_page_tables` at :250,
which calls `store_orig_host_permissions`
([sandbox_manager.c:228](../../rvzr/executor_km/sandbox_manager.c#L228)). Its
[actor-growth branch](../../rvzr/executor_km/page_tables_host.c#L261) uses
`CHECKED_ZALLOC`/GFP_KERNEL. **A new mutex does not make that allocation safe in
the IRQ-off region.** Reserve all PTE/snapshot/scratch/measurement capacity before
`get_cpu`/IRQ disable; keep snapshot capture/restoration there only if allocation-
free and validated. No user-copy, mutex acquisition, sleeping allocation or
permission-allocation teardown may be added inside that atomic window.

Also `pfc_configure` runs at [measurement.c:134](../../rvzr/executor_km/measurement.c#L134),
before `get_cpu`; the mutex does not pin a CPU. Future execution must bind to and
verify an allowed CPU before per-CPU PMU/vector setup and preserve that association
through restoration. CPU hotplug and unsuccessful restoration are native gates,
not effects established by host tests.

## 5. Legacy-interface cutover must be atomic

[main.c:219](../../rvzr/executor_km/main.c#L219) registers the ordinary attribute
list; :239 registers binary attributes. In protected mode:

- Do not register legacy `test_case`, `inputs`, `trace` or `test_case_bin` routes.
  They otherwise bypass bound ownership, completion, result identity or bounds.
- Disable `print_data_base`, `print_code_base`, `dbg_dump_mode` and
  `dbg_guest_page_tables`, or replace their resource access with locked,
  readiness/identity-qualified snapshots. `inputs_show` is not a preparation token.
- Gate configuration stores too: `warmups`, `enable_ssbp_patch`,
  `enable_prefetcher`, `enable_pre_run_flush`, `enable_hpa_gpa_collisions`,
  `measurement_mode`, `enable_quick_and_dirty_mode`, `handled_faults` and
  `enable_dbg_gpr_mode` ([main.c:393](../../rvzr/executor_km/main.c#L393) onward).
  Initially allow changes only with no active attempt/committed preparation;
  return `-EBUSY` otherwise. A setting affecting loaded macros requires fresh TC
  preparation; it cannot silently mutate an execution identity.

An immutable module-load mode can retain the old interface for existing 4 KiB
users while the new mode is opt-in. Never switch modes live or register both
mutation paths. Legacy mode retains its known defect and must not be advertised
as protected. Protected registration, legacy gating, identity admission and
teardown must land together; exposing just the new upload endpoint is unsafe.

## 6. Production upload lengths and parser admission

Keep the serialized format unchanged. With A actors, S symbols and N serialized
inputs, actual structures give:

```text
RCBF = 16 + 48*A + 32*S + 24*A + sum(section_sizes)
RDBF = 16 + 16*A + 12288*A*N
```

Sources: [actor metadata](../../rvzr/executor_km/include/actor.h#L27),
[TC symbol/section metadata](../../rvzr/executor_km/include/test_case_parser.h#L24),
[input metadata/fragment](../../rvzr/executor_km/include/input_parser.h#L16)
and [fixed Python input format](../../rvzr/input_format.py).
For the intended limits A<=16, S<=128, each section<=4096, RCBF is at most
**70,800 bytes**. Existing TC header parsing checks A>0 but not A<=MAX_ACTORS
([test_case_parser.c:55](../../rvzr/executor_km/test_case_parser.c#L55)).
Enforce all limits and checked products before parser allocation, not after it.

`MAX_INPUTS=1048576` is not a sensible memory commitment: with sixteen actors,
the formula permits **206,158,430,480 bytes**. The current cast-to-int limit
([input_parser.c:56](../../rvzr/executor_km/input_parser.c#L56)) is not a sound
u64 bound, and its allocation product at :64 is unchecked.

The default 100 generated inputs ([cli.py:82](../../rvzr/cli.py#L82)), default
two-way boosting ([config.py:221](../../rvzr/config.py#L221),
[fuzzer.py:239](../../rvzr/fuzzer.py#L239)) and executor fivefold replication
when applicable ([executor.py:307](../../rvzr/executor.py#L307)) can produce
N=1000 on the wire. That needs **12,288,032 bytes** for one actor or
**196,608,272 bytes** for sixteen. The host 512 KiB bound fits only 42 one-actor
fragments and must not become the production limit.

Proposed initial policy: advertise a read-only **256 MiB RDBF wire-byte budget**
and the 70,800-byte RCBF ceiling, plus supported actor/feature limits. This is a
new explicit compatibility/resource limit, not a kernel allocation guarantee.
For RDBF enforce N<=MAX_INPUTS and
`N <= (budget - 16 - 16*A)/(12288*A)` after checked arithmetic and A validation.
At this budget the resulting maxima are 21,845 inputs for A=1 and 1,365 for A=16.
The first native milestone may support only A=1 host/kernel actors; larger
configurations then reject explicitly rather than pretending to be supported.

Check declared length against header-derived length before allocating RDBF data;
check every RCBF section size before copying that section. Use checked addition
and multiplication against u64, SIZE_MAX and allocation/index representation
limits. Reject zero/oversized sections and unsupported ARM instruction alignment;
validate metadata fragment sizes/reserved fields and symbol owners/targets before
dereferencing them. Put necessary narrow safety checks in the actual parser
boundaries, rather than writing a second general parser in the transport.
The uninitialized `has_start` at
[test_case_parser.c:119](../../rvzr/executor_km/test_case_parser.c#L119), read at
:156, is a separate known validator prerequisite; valid fixtures avoid it but do
not fix it. Actor-target indexing at :141-148 also needs bounds validation.

Account separately for parser buffers, expanded code, PTE arrays, utility/data
backing allocation order and measurements (56*N bytes in the current
[measurement_t](../../rvzr/executor_km/include/measurement.h#L25)). Avoid an
additional whole-upload transport allocation. Budget failure returns `-E2BIG`;
allocation failure remains `-ENOMEM` and follows checked retirement/terminal
policy. A client must not silently split input batches to evade limits: ordering
and repeated/priming inputs are part of the experiment.

## 7. ARM64 / Apple Silicon gates

The transport, identities, bounded copying and parser lengths can remain usable
on 16 KiB kernels. They do not activate the proposed layout. Current active
[actor structures](../../rvzr/executor_km/include/sandbox_manager.h#L43) have
16,384-byte data stride and 12,288-byte code stride; main/faulty/register offsets
are 4096/8192/12288. Linux mapping counts/page IDs still divide by 4096 in
[sandbox_constants.h:56](../../rvzr/executor_km/include/sandbox_constants.h#L56).
Allocation headroom/alignment are 0x1000/0x2000, and initialization asserts 8 KiB
main alignment ([sandbox_manager.c:93](../../rvzr/executor_km/sandbox_manager.c#L93),
:128/:270). Kernel page-table walking uses kernel page macros, but its consumers
still use these incompatible mapping counts/strides. Passive geometry does not
change any of them. Do not change logical 4096-byte payloads or ARM instruction
encodings merely because PAGE_SIZE differs.

Initial native execution is restricted to the explicitly supported legacy 4 KiB
ARM64 layout and validated host/kernel features. A 16 KiB build must reject
execution before measurement/PMU/PTE manipulation. Even nonexecuting device tests
on that kernel need a separate initialization path: current
[executor_init:690](../../rvzr/executor_km/main.c#L690) eagerly allocates the active
sandbox and initializes the page-table manager before registering interfaces.
A late trace guard cannot make that startup suitable for the candidate layout.
`init_perf_counters` itself is a no-op
([arm64/perf_counters.c:182](../../rvzr/executor_km/arm64/perf_counters.c#L182));
direct PMU configuration happens later in `pfc_configure`. Do not confuse those.

Other independent runtime blockers remain: resolution/availability of X/NX
helpers ([main.c:583](../../rvzr/executor_km/main.c#L583)); page-table assumptions;
PMU backend; cache-observation calibration and 128-byte granularity; per-core
geometry/affinity on M3 Pro. The
[Makefile:21](../../rvzr/executor_km/Makefile#L21) derives geometry from CPU0 at
build time, whereas execution uses the calling CPU. `VMBUILD` omits PMU setup
inside `pfc_configure`, not all tracing assembly. Neither successful builds nor
efficiency-core-first scope establish compatibility. No new M3 hardware claims
are made here.

## 8. Bounded implementation sequence and acceptance gates

| Stage | Production scope | Independent acceptance / refusal condition |
| --- | --- | --- |
| 1. Native ownership bookkeeping | Record actual sandbox backing/mapping/code ownership and capacities at acquisition/release; keep layout and live interfaces unchanged. | Build both ARM64 kernel configurations; existing parser/state regressions remain unchanged. Review every partial allocation branch against the ownership table. This is evidence of bookkeeping, not cleanup recovery. See the first milestone below. |
| 2. Checked retirement and sleepable preflight | Define real partial-init cleanup, alias/PTE retirement, checked X/NX and loader publication; fix capacity accounting and reserve execution scratch before IRQ-off. Repair narrow parser safety prerequisites. | Existing ordinary/ASan/UBSan parser tests plus focused tests for changed checks. Compile all affected architecture paths. Controlled native 4 KiB allocation/growth/shrink/release tests must establish real cleanup before certifying retry. Unknown cleanup stays terminal; do not expand the host fake allocator. |
| 3. Nonexecuting protected kernel transport | Build the real coordinator/state into Kbuild; implement per-open ops, user-copy, bounded parsing/reset, close-abort, locking, init unwind and legacy gating. Expose only when ready for native parser-only validation; refuse TC commit/EXECUTE while native stages remain unavailable. | Native open/short-write/close/dup/stale-FD/interleaving, exact-byte RCBF parsing, actual userspace copy failures, valid/incomplete/semantic-failure cases and teardown. No fake allocation/load success or executable commit. RDBF integration waits for a genuinely prepared parent in stage 4. Avoid eager unsupported sandbox/PTE initialization in this mode. |
| 4. Legacy-layout native preparation, then execution | Wire real retirement/allocation/loading and committed address snapshot, then trace admission and result IDs under the same mutex. Add the narrow Python transport adapter and reconstruction from completed TC addresses. | First native 4 KiB preparation without executing generated instructions; then separately authorized benign trace tests on a validated conventional ARM64 system. Concurrent replacement/read/trace and failure cases must reject obsolete identities without native diagnostics. Do not enable M3/16 KiB here. |
| 5. Return to target research | Integrate synchronized layout/model work and validate the observation backend on M3 Pro. | Atomically update active C/assembly/PTE/allocation/model geometry before 16 KiB activation; independently validate timer/cache/PMU observations. Compilation is not this gate. |

Within stage 4, native completion, checked cleanup, alias/PTE publication and
identity-qualified trace/result admission are one activation unit. They may be
reviewed in dormant pieces but cannot be enabled piecemeal. Stage 3 must return
an explicit unsupported-stage error at TC COMPLETE if real preparation is not
connected, fail the attempt and retire/reset it; a parser-only success cannot be
presented as TC_READY or used to authorize an input upload.

Existing compile-only references are the Ubuntu builds with/without VMBUILD in
[arm64-software-baseline.yml:56](../../.github/workflows/arm64-software-baseline.yml#L56)
and the [Asahi 16 KiB job:208](../../.github/workflows/arm64-software-baseline.yml#L208).
Use the job-selected configured kernel build tree, generated headers and
Module.symvers, not running-kernel headers by accident:
`make -C "$kernel_build" M="$PWD" ARCH=arm64 VMBUILD=1 modules` and the existing
clean non-VMBUILD variant. These are future checks, not commands run for this
assessment. Preserve current CI; new sources must eventually be in Kbuild to
receive those checks. Target API/symbol policy must be verified on the actual
installed kernel; its release is not assumed equal to the pinned build job.

WSL2 can retain existing host parser/state/serialization/descriptor/model
regressions and review/build pure code. It cannot verify native PTE ownership,
X/NX transitions, CPU restoration, kernel locking or module lifetime. Native
testing needs the matching module/kernel, controlled disposable environment,
diagnostic collection and explicit authorization; the initial task does none.
Lockdep/sleep-in-atomic/memory diagnostics, where available, supplement rather
than replace identity/byte-result assertions. Keep the legacy expected failure
as evidence until its path is disabled or actually fixed; never relabel it as
new-interface success.

Python work is deliberately deferred: current model-before-executor loading in
[fuzzer.py:136](../../rvzr/fuzzer.py#L136) and the architectural path at :382 can
capture stale addresses. The eventual sequence is completed TC allocation ->
validated identity/address snapshot -> fresh model/taint/tracer reconstruction ->
associated inputs -> exact-identity execution. Updating only `model._bases` or
reading independent legacy address files is insufficient. This remains separate
from the first production milestone.

**Stopping criterion:** once a single-actor legacy-layout vertical path uploads
RCBF/RDBF, rejects stale operations, retires/replaces safely (or demonstrably
quarantines failures), synchronizes model addresses and qualifies all result
pages, stop expanding the protocol framework. Return to ARM64/Unicorn and M3
observation feasibility. No async queue, multi-client ownership scheme, second
transport or exhaustive malformed-input campaign is a prerequisite. If a native
cleanup/atomic-context gate cannot be established, stop activation at the
nonexecuting milestone and report that blocker instead of claiming readiness.

## First production-code milestone: actual sandbox ownership bookkeeping only

The next coding task should be a small change to **sandbox_manager.c**, with a
header change only if needed: replace inferred ownership with an explicit private
record of the acquired backing head/order, page-array and vmap ownership, aligned
usable extent, actual actor/code capacities, and executable-transition outcome.
Populate/clear it at the existing real acquisition/release points, including
partial failures; do not derive surviving ownership from `old_n_actors` or a
future token. Preserve current layout and successful-path behavior. This is
native allocator bookkeeping, not a second passive protocol or fake ledger.

Do **not** register a device, wire the coordinator, acknowledge cleanup, publish
new executable readiness, change retry policy, or introduce a new execution path
in that milestone. Do not advertise this record as fixing stale aliases/PTEs or
ignored permission errors; stage 2 must consume the record in checked retirement
before protected activation. Acceptance is source review of every allocation
branch, unchanged existing host regressions and compile-only Ubuntu/Asahi builds
with existing flags. Native cleanup/retry remains unverified until tested
separately. This is the smallest concrete production prerequisite that advances
the audited resource problem without exposing a new unsafe live executor path.
