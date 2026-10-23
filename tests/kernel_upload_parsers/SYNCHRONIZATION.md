# B3.3d.5c–5d: serialized callbacks and terminal admission

B3.3d.5c adds a real kernel mutex to the legacy executor interface.
B3.3d.5d adds fail-closed admission after a returned trace-pipeline error. It does not
activate the [preparation protocol](KERNEL_INTEGRATION_PLAN.md), repair interrupted
uploads, implement published-resource retirement or enable 16 KiB execution.
The [ownership audit](NATIVE_OWNERSHIP.md) still governs native cleanup obligations.

## Boundary and participating callbacks

[main.c:109](../../rvzr/executor_km/main.c#L109) defines one private
`executor_mutex`. All 20 registered callbacks use outer wrappers defined at
[:115](../../rvzr/executor_km/main.c#L115). Each takes the mutex, rejects terminal state with `-EIO`, or calls
the existing body, now named `*_unlocked`, then unlocks and returns its result. Attribute names, permissions and original callback signatures remain
unchanged, including `bin_attr_t` kernel-version handling.

| Protected callbacks | Resources covered during that callback |
| --- | --- |
| `test_case_store`, `inputs_store` | Readiness checks/updates, real parser calls, allocation/growth, code loading, input backing and result invalidation. |
| `trace_show` | Admission, measurement allocation, the entire synchronous `trace_test_case()` call and its normal returned restoration path, formatting, pagination cursor and output-buffer writes. Pending pages take the same lock even when execution is skipped. |
| `test_case_bin_read` | Existing raw code read while other participating operations cannot replace storage. Its independent count/offset/readiness defects are unchanged. |
| `print_data_base_show`, `print_code_base_show`, `inputs_show` | Snapshot of current aliases/readiness, not a lease that survives callback return. |
| `dbg_dump_show`, `dbg_guest_page_tables_show` | Global/parser/guest-table inspection and logging. |
| `warmups_show`, `warmups_store`, `handled_faults_show`, `handled_faults_store` | Configuration inspection/mutation. |
| `enable_ssbp_patch_store`, `enable_prefetcher_store`, `enable_pre_run_flush_store`, `enable_hpa_gpa_collisions_store` | Execution-related configuration mutation. |
| `measurement_mode_store`, `enable_quick_and_dirty_mode`, `enable_dbg_gpr_mode` | Template/measurement-related configuration mutation. |

The inner bodies retain their behavior except trace-error metadata invalidation. In particular, an `ASSERT`
or `CHECK_ERR` returns from the inner function, not the lock-owning wrapper.
Both positive short returns and negative errors therefore pass through unlock.
No helper called from a locked body takes this mutex again. Original configuration
rules remain for nonterminal operation: stores can change settings between
callbacks. No new `-EBUSY`, attempt or generation rule is introduced.

The module resource initialization body is isolated in
[executor_init_resources:748](../../rvzr/executor_km/main.c#L748), called under
the mutex by `executor_init` at :792. Every initialization early return reaches
that caller's unlock. All managers finish before the first attribute is created.
Interface creation occurs outside the mutex; a registration failure removes and
drains already-created attributes outside it before dropping the kobject. The
pre-existing incomplete manager-init error unwind remains unresolved.

## Context and lock ordering

Sysfs callbacks and module initialization/removal run in sleepable process
context. The [Linux mutex documentation](https://docs.kernel.org/locking/mutex-design.html)
requires owner unlock and prohibits recursive and interrupt-context acquisition.
No new lock acquisition is added to a fault handler, assembly template, PTE
helper or IRQ/preemption-disabled execution window.

The outer trace callback owns the mutex across
[measurement.c:324](../../rvzr/executor_km/measurement.c#L324).
`pre_run` at :122 disables preemption/IRQs at :143/:146; `post_run` at :155
normally restores them at :161/:163 before the trace call returns and the wrapper
unlocks. Internal data loading, page permission changes, generated entry/exit
and fault recovery inherit exclusion without acquiring the mutex themselves.
They must not call a wrapped sysfs callback or acquire this sleeping mutex.

Existing problems inside that window remain: `set_sandbox_page_tables()` invokes
[store_orig_host_permissions:255](../../rvzr/executor_km/page_tables_host.c#L255),
whose actor-growth branch can allocate with GFP_KERNEL after IRQ disable.
The mutex does not make that allocation safe. PMU configuration before CPU
pinning and incomplete restoration/error propagation are also unchanged.

Ordering is **kernfs active callback -> executor mutex -> existing internal
operations**. Interface removal must never run with the executor mutex held;
removal may wait for an active callback that is waiting for the mutex. No new
per-file lock, spinlock, workqueue or asynchronous experiment is introduced.
No mutex operation is async-signal/fault recovery machinery.

## Terminal admission (B3.3d.5d)

All three wrapper macros check `unfinished_call` **after acquiring the same
mutex and before calling any inner body**. All 20 callbacks participate, including
uploads, trace execution/pagination, raw binary and base-address readers,
diagnostics, and configuration. Terminal rejection returns exactly `-EIO`, writes
no output and changes neither readiness, parser state, result cursor nor the
terminal flag. It does not call parsers, allocation, loading or tracing helpers.
There is no reset attribute or second recovery authority.

The existing flag has only three production assignments: initialization to false,
setting true after trace prechecks, and clearing after successful tracing (or
normal pagination). The mutex excludes other callbacks during the transient true
state. Thus a later callback acquiring the mutex with the flag still true follows
an unsuccessful trace call; it cannot reach the statement that clears the flag.
If execution never returns, this barrier cannot make progress or repair the CPU.

At [trace_show_unlocked:291](../../rvzr/executor_km/main.c#L291), any nonzero return
from `trace_test_case()` leaves the flag set, clears `tc_ready` and `inputs_ready`,
sets `next_measurement_id=-1`, and returns `-EIO` before formatting results.
Measurement storage remains allocated; it is neither freed nor published.
A seeded inconsistent state with readiness true and a pending cursor is also
rejected before any cursor change or output.

This policy conservatively includes measurement-allocation/preflight failures:
[measurement.c:324](../../rvzr/executor_km/measurement.c#L324) does not identify
which errors occurred before generated execution. By contrast, ordinary parser,
preparation and unready-trace rejections never set the flag and remain retryable.
The four trace prechecks run before the flag is set. Output-formatting errors
occur after it is cleared and are not treated as failed hardware experiments.

An error return, mutex unlock or callback completion does **not** attest to
CPU/vector/PTE restoration. `recover_orig_state()` at measurement.c:212 returns
void; [sandbox_manager.c:294](../../rvzr/executor_km/sandbox_manager.c#L294)
discards `restore_orig_host_permissions()`'s result. Measurement corruption at
measurement.c:300 deliberately does not set `err`. Unreported failures/zero
returns are not detected by this barrier. Native restoration and safety of
returning/unlocking after a real failure remain unverified.

The passive [state component](../../rvzr/executor_km/preparation_state.c) remains
outside live Kbuild/callbacks. Its `RVZR_PREP_UNRECOVERABLE` rejection and failed
cleanup transition are consistent with the chosen fail-closed policy, but are
not integrated and do not independently authorize recovery or retirement.

The raw binary reader's independent bounds/liveness defect remains: it replaces
caller `count` using `pos + PAGE_SIZE`, does not reject negative offsets or prove
backing capacity/readiness. Normal-state access is not made safe by this patch.
The terminal gate merely prevents reaching that body after a reported trace error.

## Teardown: callback draining, with explicit remaining limits

[remove_executor_interfaces:738](../../rvzr/executor_km/main.c#L738) removes all
ordinary and binary attributes. [executor_exit:846](../../rvzr/executor_km/main.c#L846)
calls it **before** taking the mutex and invoking the existing destructors;
final `kobject_put` follows unlock. Missing attributes
are tolerated, so the same remover is used on either registration failure.
Resource destruction is not performed while only some attributes are removed.

The basis for draining is the kernel implementation, not a host imitation:
[Linux v6.17 sysfs removal](https://github.com/torvalds/linux/blob/v6.17/fs/sysfs/file.c#L477)
routes to kernfs removal; [kernfs deactivation/removal](https://github.com/torvalds/linux/blob/v6.17/fs/kernfs/dir.c#L1387)
prevents new active usage and drains existing callbacks. Open FDs do not entitle
later operations to re-enter a removed callback. Actual target-kernel behavior
and lockdep checks still require native validation. No callback here removes
itself or explicitly breaks kernfs active protection.

Thus, after removal completes, registered interface callbacks have drained
before destructors access their resources. This addresses the prior interface-
after-free ordering and avoids waiting for callbacks while holding their mutex.
It is **not a general safe-unload guarantee**:

- `executor_exit` preserves the existing `unfinished_call` check and skipped
  destruction on failure, now reaching a shared unlock label. It is a void
  callback and cannot veto module removal; retained resources, pointers or
  unproven CPU state remain a blocker. Interface removal and final kobject drop
  still happen on that error path. No new published-resource destructor is added.
- The mutex does not repair failed execution, verify PTE/vector restoration or
  revoke aliases embedded in executable code. A stalled experiment may prevent
  callback draining indefinitely. Do not force unload or infer reload safety.
- Native destructor order, ignored X/NX results, descriptor ownership issues and
  absence of allocation-epoch validity for snapshots remain unchanged. No new
  published-resource cleanup helper is connected.

## What is established, and what remains separate

| Property | Conclusion |
| --- | --- |
| Participating callback serialization | One callback body at a time, including checks, all normal/error returns and result pagination, using the real kernel mutex. Runtime verification is still pending. |
| Experiment call-stack quiescence | After a normal successful synchronous trace callback returns, its experiment/recovery call stack has returned. A later lock owner cannot overlap another participating trace body. This is not a CPU-state attestation. |
| Verified CPU/vector/PTE restoration | Not established. Returns from restoration wrappers do not prove all state restored; the original-PTE wrapper discards a return, and fault paths need independent validity checks. |
| Borrowed PTE/alias retirement | Not implemented. Restoring values leaves cached pointers/snapshots present; ownership metadata alone cannot authorize free. |

Excluded from independent acquisition are internal parser/reset, allocator,
loader, data-loader, page-table, measurement and fault/assembly helpers: their
existing live interface callers hold the mutex, or they run in the serialized
init/exit resource phase. Fault handlers themselves never take it. Direct future
callers must honor this caller-held contract; the private mutex is not exported
as a new API. The passive preparation-state component and host attempt adapter
remain outside Kbuild/live callbacks.

Remaining logical/lifetime hazards across callback boundaries include unbound
legacy streams mixing client bytes; stale base-address snapshots retained by
Python; configuration changes after code preparation; global pagination shared
between readers; failed-growth retries; raw binary-read bounds/liveness; and
permission-snapshot validity. Callback serialization fixes none of those.
After a negative trace result, terminal admission now prevents further callback
body entry. This protects against subsequent participating operations, but does
not repair the failed execution or validate any restoration.

## Verification

The existing host extractor now compiles the actual inner callbacks and actual
production SHOW/STORE/BIN_READ wrapper macros. A small single-threaded instrumentation
stub detects nested acquisition, double/missing unlock and the acquisition count.
Real callback parser calls and counted preparation/trace stubs require the
boundary to be held; adapters require it released after every callback return.
This checks wrapper control flow, not Linux scheduling, contention or CPU recovery.
Binary-reader wiring is source-audited and its actual callback is host-tested
with owned backing, offset zero and a full-page destination; this is not native
kernel validation or coverage of its separate count/offset defects. No physical-page/vmap model or new protocol framework is added.

The original B3.3d.5c regressions audit all 20 attribute callback bindings, verify
interface-removal/destruction source order, and exercise a negative trace-stub
return. The latter preserves `unfinished_call=true`, returns `-EIO` and emits no
result bytes while the wrapper unlocks. It does not simulate a real failed
experiment or prove restoration.

Historical B3.3d.5c results on x86-64 WSL2 / GCC 13.3.0 (before 5d):

| Check | Result |
| --- | --- |
| Ordinary, separate ASan, separate UBSan parser/attempt suites | Each ran 62: 61 passed and the unchanged interrupted-RDBF expected failure. No sanitizer finding. |
| Passive preparation-state tests | 20 passed in each of those configurations. |
| Geometry/parity, input-format, descriptor, preparation/model/coverage/lifetime, test-case-component and trace regressions | 175 passed. |
| Flake8 (`--max-line-length=100`), strict mypy, Pylint on the changed Python test | Passed; Pylint 10.00/10. The repository-style line limit is explicit; default 79-column Flake8 reports existing long lines. |
| Whitespace/source checks | Passed. All 20 original callback bodies match after name normalization. The existing native destructor sequence is preserved; the failure branch now reaches unlock. Attribute/wrapper completeness and teardown ordering are regression-checked. |
| GCC `-fanalyzer` on the six host harness/parser/callback/adapter/state translation units | Compiled. Existing parser signedness, unused callback parameters and TC validator `has_start` uninitialized-use diagnostics remain. The last diagnostic uses an explicit warning-only exception; no wrapper diagnostic was reported. This is not whole-module analysis. |
| Ubuntu ARM64 VMBUILD, Ubuntu ARM64 non-VMBUILD, Fedora Asahi 16 KiB module builds | **Not run for this patch. Native verification pending.** No configured kernel tree or AArch64 compiler is installed locally. CI and Kbuild are unchanged. |

Before editing, the 79-test parser/state baseline had the same one expected
failure. The final total is 82 per ordinary/sanitizer run after adding three
regressions. ASan retains the existing documented `detect_leaks=0` WSL2 setting;
host allocation tracking remains enabled. Run:

```sh
python -m unittest -f tests.unit_kernel_upload_parsers tests.unit_preparation_state -v
RVZR_PARSER_SANITIZER=address RVZR_PREPARATION_SANITIZER=address \
  python -m unittest -f tests.unit_kernel_upload_parsers tests.unit_preparation_state -v
RVZR_PARSER_SANITIZER=undefined RVZR_PREPARATION_SANITIZER=undefined \
  python -m unittest -f tests.unit_kernel_upload_parsers tests.unit_preparation_state -v
```

The changed production file must pass all three existing native module builds
before this milestone is considered verified. Earlier CI builds of ownership
changes cannot validate these wrappers or teardown changes. Loaded-kernel
contention, sysfs draining and lockdep behavior remain untested. No kernel module
or generated test case was executed on hardware.

## B3.3d.5d verification

Before implementation, the 82-test parser/state baseline passed with one unchanged
expected failure. New regressions failed against the old production wrappers:
post-error requests reached inner bodies, and a seeded terminal/ready/pending
state emitted 29 bytes rather than returning `-EIO`. The successful-operation,
ordinary parser-error and unready-trace controls already passed.

Three focused tests add these sequences using actual extracted production
callbacks and wrapper macros:

- Real valid preparation, one negative trace-stub return, then two repetitions of
  test/input upload, retrace, readiness/base/code/binary reads and warmup mutation.
  All requests return `-EIO`; parser/preparation/trace/allocation counts, parser
  cursors and terminal metadata stay unchanged. Reader buffers stay untouched.
- A seeded terminal state with otherwise-ready metadata and pending results,
  proving that terminal admission takes priority over pagination.
- Successful trace, ordinary semantic parser error, or unready trace, followed
  by valid preparation/execution. Resource readers and configuration still work;
  only the failed trace is terminal. The invalid fixture omits an end marker;
  it does not depend on the separate uninitialized `has_start` issue.

The trace-error regression additionally checks readiness withdrawal. Existing
unready cases seeded with `unfinished_call=true` now expect the earlier terminal
rejection rather than an inner assertion diagnostic. Ordinary diagnostics,
successful output/pagination and interrupted-RDBF expected failure are unchanged.
The stub models no CPU/PTE restoration and the harness directly frees only its
owned parser fixtures at process end, not native potentially unsafe resources.

| Check | B3.3d.5d result |
| --- | --- |
| Ordinary parser/callback/attempt + passive state | 85 run: 84 passed, one unchanged expected failure (64 parser-suite passes + expected failure; 20 state passes). |
| Separate ASan and UBSan configurations | Same 85 outcomes each; no sanitizer findings. Existing WSL2 `detect_leaks=0` and independent allocation accounting retained. |
| Supporting geometry/parity, input-format, descriptor, lifecycle/preparation/model/coverage, components and traces | 175 passed. |
| Flake8 (100-column limit), strict mypy, Pylint | Passed; Pylint 10.00/10. |
| GCC `-fanalyzer`, six host translation units | Compiled with the existing warning-only exceptions for parser signedness, callback unused parameters and validator `has_start` uninitialized use. No new harness/wrapper findings. |
| `git diff --check` | Passed. |
| Three native ARM64 module-build configurations | Not run locally; configured kernel headers and AArch64 compiler unavailable. CI unchanged. Earlier 5b results do not validate 5c or this uncommitted patch. |

Safe unload is **not** established: the unchanged void module-exit callback cannot
veto removal, even when it skips destruction because `unfinished_call` is true.
No unload/reload recovery procedure is offered. Native destructors are unchanged.

## Next prerequisite proposed in B3.3d.5d

The B3.3d.5e inspection below identifies a recovery dependency that must be
resolved before activating this reservation/capture change.

First reserve original-PTE and faulty-page snapshot capacity under the existing
coordinator mutex in sleepable preparation context, before `pre_run()` disables
IRQs/preemption. Remove growth allocations from
[store_orig_host_permissions:255](../../rvzr/executor_km/page_tables_host.c#L255).
Track actual capacity separately from the latest actor count, and track capture
validity/count and association with the current mapping allocation. A failed or
partial capture must not authorize restoration from uncaptured entries.

Then propagate checked restoration failures and define a narrowly checked
retirement operation that refuses unproven restoration and does not itself free
sandbox backing. Only after those prerequisites and native verification can
published utility/data retirement be connected; never use a caller-set
`safe_to_free` flag. This patch implements none of those future changes.

## B3.3d.5e inspection: stopped at the capture/recovery dependency

**Reservation is not implemented or activated in this milestone.** The stopping
condition applies: adding a rejecting, allocation-free capture path is not enough
while its caller can restore snapshots that were never captured. Only this note
changes; no allocation site, native call sequence or capacity bookkeeping changes.
The sleep-in-atomic problem below therefore remains unresolved.

### Existing allocation and execution sequence

1. [init_page_table_manager:440](../../rvzr/executor_km/page_tables_host.c#L440)
   allocates the original-PTE container, one actor's data/code value arrays, the
   utility value array, cached-PTE pointer arrays and one faulty-PTE value. The
   page-walk self-test also uses `vmalloc`/`vfree`, during module initialization.
2. [allocate_sandbox:230](../../rvzr/executor_km/sandbox_manager.c#L230), called
   from the locked TC-upload callback, allocates/maps sandbox storage when it
   grows, then calls `cache_host_pteps()`. Its pointer-array growth at
   [page_tables_host.c:213](../../rvzr/executor_km/page_tables_host.c#L213) is in
   sleepable preparation context, not the measurement window. Both managers
   track the latest actor count rather than actual capacity; failed replacement
   can still leave inconsistent public aliases. Stage 5d does not quarantine
   preparation failures that never entered tracing.
3. The locked trace callback calls
   [trace_test_case:324](../../rvzr/executor_km/measurement.c#L324), which calls
   `alloc_measurements()` before `pre_run()`. `pre_run()` configures PMU state,
   calls `kernel_fpu_begin()` on x86, explicitly disables preemption at :143
   (`get_cpu`) and saves/disables local IRQs at :146. The proposed reservation
   would precede both architectures' setup, including the x86 FPU helper.
4. `run_experiment_outer()` calls `run_experiment()`, which calls
   `set_sandbox_page_tables()` at measurement.c:250. That immediately calls
   [store_orig_host_permissions:255](../../rvzr/executor_km/page_tables_host.c#L255).
   Growth at :261-269 frees old data/code/faulty arrays and calls
   `CHECKED_ZALLOC` three times. The macro expands to `kzalloc(..., GFP_KERNEL)`
   ([shortcuts.h:122](../../rvzr/executor_km/include/shortcuts.h#L122)). These
   potentially sleeping allocations occur with IRQs/preemption disabled.
   Partial allocation failure can also discard prior ownership/data.
5. Normal capture copies utility/data/code values, execution changes permissions,
   and normal/error cleanup calls `recover_orig_state()`. Only after the outer
   experiment returns does `post_run()` restore IRQs and call `put_cpu()`.

The snapshot growth variable decreases when actor count decreases, so an increase
within a formerly allocated extent can unnecessarily free/reallocate it. It is
not a capacity field. There are no checked snapshot byte-size products here.

One other explicit sleeping-allocation path remains in the inspected IRQ-off
call graph: Intel guest execution calls `set_execution_environment()` ->
`set_vmcs_state()`, whose growth branch uses `vfree`/`vmalloc` at
[x86/vmx.c:377](../../rvzr/executor_km/x86/vmx.c#L377). Guest-page-table/faulty
guest/EPT allocations in `map_sandbox_to_guest_memory()` instead run during
`allocate_sandbox()`; they are not called by `set_sandbox_page_tables()`.
ARM guest permission helpers are no-ops. No additional explicit allocator was
found in the inspected ARM data-loading, special-register, vector-management
or restore helpers. This is a source call-graph audit, not proof that the whole
window or external kernel helpers are allocation/sleep safe. No `GFP_ATOMIC`
workaround is proposed.

### Why capacity-only rejection cannot establish a safe capture path

- A failure from `set_sandbox_page_tables()` goes to `cleanup` at
  [measurement.c:250](../../rvzr/executor_km/measurement.c#L250), then calls
  `recover_orig_state()` at :315. That unconditionally calls faulty-page restore
  (:231) and original-page restore (:233). A new insufficient-capacity return
  from capture would inherit this error path if reached. Rejecting ordinary
  shortages before `pre_run()` avoids those particular entries into the window,
  but does not fix existing capture/setup failure recovery.
- `faulty_ptes` is first populated for the current run at
  [page_tables_host.c:394](../../rvzr/executor_km/page_tables_host.c#L394), through
  `set_faulty_page_permissions()` at measurement.c:276. Setup errors at :250 or
  :255 precede that capture. Nevertheless, restore at
  [page_tables_host.c:409](../../rvzr/executor_km/page_tables_host.c#L409) writes
  every `faulty_ptes[actor_id]` into a live PTE without a captured-entry check.
  After initial/growing zero allocation these can be zero values; after reuse
  they can describe an earlier capture. Original-PTE restore likewise has no
  completed-capture/count check. Reserving or preserving array contents does
  not make either snapshot current.
- Cached PTE arrays can contain a partially refreshed prefix after a failed walk
  and have no mapping-allocation association. The first-pointer assertions in
  `store_orig_host_permissions()` do not validate all referenced entries. Its
  copy loop can encounter an invalid later alias after copying a prefix.
  ARM outer exception recovery at
  [exception.S:249](../../rvzr/executor_km/arm64/exception.S#L249) does not call
  `recover_orig_state()` before returning; x86 fault handlers do call it, without
  capture validity. Neither path establishes valid partial-capture restoration.

These are conditional consequences established from source, not reproduced
kernel failures. Stage 5d rejects later callbacks only after the trace returns;
it cannot protect the earlier cleanup accesses. The unchanged void exit callback
still cannot veto unsafe unload. Neither limitation is resolved by this note.

### Proposed boundary and smallest next task (not implemented)

The intended reservation call belongs at the start of `trace_test_case()`, under
the caller-held coordinator mutex and before `pre_run()` or PMU/FPU setup.
Check positive bounded actor/input counts, actor-table/metadata sizes and input
fragment/data sizes with checked multiplication before allocating. Do not walk
sandbox/PTE aliases to infer capacity. These checks establish dimensions, not
backing liveness or semantic preparation identity.

Use actual allocated entry capacities for original data/code and faulty arrays,
independent of requested counts. Growth must acquire all replacement arrays
before publishing/freeing any old owner, preserve the old allocated prefix,
and leave owners/capacities unchanged on failure. Reuse must not shrink capacity.
Capture must check required extents before writing and contain no allocator.
Allocation/validation failure must return before the IRQ-off window and reach
the existing trace-error gate; reservation success must publish no validity flag.

Before activating that change, define and test **capture-qualified recovery**:
distinguish reserved capacity, entries actually captured, mappings actually
modified, and the mapping allocation to which they belong. Cleanup must not
restore uncaptured entries or dereference stale cached aliases; merely skipping
all cleanup on a mixed setup error is not a correct replacement. Check and
propagate restoration results, including the currently discarded result in
[sandbox_manager.c:294](../../rvzr/executor_km/sandbox_manager.c#L294). Keep that
prerequisite separate from published-resource retirement, with no new reset,
lock, transport or caller-supplied safety authority.

Capacity/growth/failure/overflow and preflight-order tests are deferred because
there is no new production reservation implementation to exercise. A synthetic
allocator/state machine would not establish this missing recovery contract.
The existing host regressions are retained; they do not execute native PTE
capture or restoration. Native build and runtime safety are not claimed.

Local verification after the inspection (x86-64 WSL2, GCC 13.3.0):

| Check | Result |
| --- | --- |
| Existing parser/callback/attempt + passive preparation-state suites, ordinary | 85 run: 84 passed and the unchanged interrupted-RDBF expected failure. |
| Separate ASan / UBSan runs of the same suites | Each has the same 85 outcomes; no sanitizer finding. Existing WSL2 `detect_leaks=0` setting and independent allocation accounting retained. |
| Supporting Python suites listed in the 5d results above | 175 passed. |
| Flake8 (100-column limit), strict mypy and Pylint on the existing parser/state test wrappers | Passed; Pylint 10.00/10. These do not analyze native capture/recovery. |
| `git diff --check` | Passed. Only this documentation file changed. |
| New reservation/growth/failure/overflow tests | Not added or run: production reservation/capacity changes stopped at the dependency above. |
| Kernel compilation / loaded-kernel checks | Not run. No production file changed; no configured native kernel build tree or AArch64 compiler is installed locally. Host tests compile only their existing extracted/shimmed sources. |

The task reports native Ubuntu VMBUILD, Ubuntu non-VMBUILD and Fedora Asahi
16 KiB compile-only success for **5c**. This inspection does not independently
verify those runs, and **5d still requires its own native CI verification**.
CI, parsers, active geometry, snapshot arrays and native destructors are unchanged.
No module, generated instruction stream, privileged register or hardware
measurement was executed. Failures during published sandbox preparation and
the inability of module exit to veto unsafe unloading both remain unresolved.
