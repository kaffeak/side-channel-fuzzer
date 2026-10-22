# B3.3d.5c: serialization of existing executor entry points

This adds a real kernel mutex to the legacy executor interface. It does not
activate the [preparation protocol](KERNEL_INTEGRATION_PLAN.md), repair interrupted
uploads, implement published-resource retirement or enable 16 KiB execution.
The [ownership audit](NATIVE_OWNERSHIP.md) still governs native cleanup obligations.

## Boundary and participating callbacks

[main.c:107](../../rvzr/executor_km/main.c#L107) defines one private
`executor_mutex`. All 20 registered callbacks use outer wrappers defined at
[:111](../../rvzr/executor_km/main.c#L111). Each takes the mutex before calling
the existing body, now named `*_unlocked`, saves its exact return value, unlocks
and returns. Attribute names, permissions and original callback signatures remain
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

The inner bodies are unchanged except their names. In particular, an `ASSERT`
or `CHECK_ERR` returns from the inner function, not the lock-owning wrapper.
Both positive short returns and negative errors therefore pass through unlock.
No helper called from a locked body takes this mutex again. Original configuration
rules remain: stores can change settings between callbacks; no new `-EBUSY`,
readiness, attempt or generation rule is introduced.

The module resource initialization body is isolated in
[executor_init_resources:738](../../rvzr/executor_km/main.c#L738), called under
the mutex by `executor_init` at :782. Every initialization early return reaches
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

## Teardown: callback draining, with explicit remaining limits

[remove_executor_interfaces:728](../../rvzr/executor_km/main.c#L728) removes all
ordinary and binary attributes. [executor_exit:836](../../rvzr/executor_km/main.c#L836)
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
After a negative trace result the wrapper unlocks without changing legacy
readiness or clearing `unfinished_call`. Subsequent callbacks are serialized,
but no failed-recovery admission gate is added or claimed.

## Verification

The existing host extractor now compiles the actual inner callbacks and actual
production SHOW/STORE wrapper macros. A small single-threaded instrumentation
stub detects nested acquisition, double/missing unlock and the acquisition count.
Real callback parser calls and counted preparation/trace stubs require the
boundary to be held; adapters require it released after every callback return.
This checks wrapper control flow, not Linux scheduling, contention or CPU recovery.
Binary-reader wiring is audited by source checks; it is not a native binary-read
test. No physical-page/vmap model or new protocol framework is added.

Three added regressions audit all 20 attribute callback bindings, verify
interface-removal/destruction source order, and exercise a negative trace-stub
return. The latter preserves `unfinished_call=true`, returns `-EIO` and emits no
result bytes while the wrapper unlocks. It does not simulate a real failed
experiment or prove restoration.

Recorded on x86-64 WSL2 / GCC 13.3.0:

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

## Smallest next prerequisite

Under the established caller-held boundary, add explicit validity/capacity and
allocation association for cached host PTE pointers, original snapshots and
faulty-page state. Provide a narrowly checked retirement operation that refuses
an unproven restoration state and does not free sandbox backing. Correct the
sleepable-capacity reservation before using growing snapshots in the IRQ-off
window. Only after those prerequisites and native verification can published
utility/data retirement be connected; never use a caller-set `safe_to_free` flag.
