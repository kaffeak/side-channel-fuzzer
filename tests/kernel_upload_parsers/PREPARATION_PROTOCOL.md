# B3.3d.1: preparation lifecycle and recovery protocol

**Design only.** This document proposes an ARM64 host-actor preparation protocol;
it implements no state, transport, reset, cleanup, locking or execution gate.
It does not authorize 16 KB execution. RCBF/RDBF bytes, logical payload sizes,
instruction semantics and measurement algorithms remain unchanged.

## 1. Evidence and scope

The [characterization README](README.md#b33c4a-interrupted-uploads-and-parser-error-recovery)
and [resource ownership audit](RESOURCE_OWNERSHIP.md) are the evidence baseline.
Their findings have different strengths:

| Classification | Established finding | Consequence for this proposal |
| --- | --- | --- |
| Demonstrated host defect, real parsers/callbacks | An interrupted RDBF at cursor 12312 accepts eight bytes of a fresh 16-byte header as its missing tail, completes at 12320, publishes input readiness and admits the measurement stub with mixed payload bytes. See [README results](README.md#bounded-retry-method-and-observed-results). | A restart must reset the parser at an explicit boundary; every continuation must identify its attempt. |
| Demonstrated host behavior | The corrected callbacks reject negative parser returns and simulated allocation/code-loader failures. Replacement invalidates readiness and pending results. Stub-success retries work. See [README failure results](README.md#b33c4b-preparation-failure-returns-and-ownership). | Keep those sequential guards. They establish neither native cleanup nor safe retries after real allocation failure. |
| Source-derived risk | Allocation frees old resources before replacement succeeds; aliases, PTE caches and loaded code can be partially updated on failure. See [ownership audit](RESOURCE_OWNERSHIP.md#verified-source-control-flow-and-failure-windows). | Use fail-closed replacement with explicit ownership accounting; never promise rollback. |
| Source-derived limitation | Global flags/cursor have no executor-wide synchronization or preparation identity. The trace guard covers execution and pagination but only checks Booleans. | Associate committed identities and enforce them under the same lock as execution and output. |
| Proposed design | The states, handles, tokens and errors below do not exist in the running interface. | Test them independently before integration; do not describe them as current kernel guarantees. |

Current source anchors:

- [main.c:248](../../rvzr/executor_km/main.c#L248): `trace_show()` checks
  readiness, may execute, then paginates a global measurement buffer/cursor.
  Its error return after `trace_test_case()` leaves `unfinished_call` set.
- [main.c:316](../../rvzr/executor_km/main.c#L316): `test_case_store()`
  invalidates both flags and the cursor on each write, parses, checks a negative
  return before completion, then allocates and loads code before setting `tc_ready`.
- [main.c:364](../../rvzr/executor_km/main.c#L364): `inputs_store()` invalidates
  input readiness/cursor, requires `tc_ready`, and publishes readiness on
  nonnegative completion. It does not identify the stream or its parent test case.
- [input_parser.c:22](../../rvzr/executor_km/input_parser.c#L22) and
  [:90](../../rvzr/executor_km/input_parser.c#L90): receiving/cursor state chooses
  header versus continuation. [TC parser:193](../../rvzr/executor_km/test_case_parser.c#L193)
  also has function-local static section state. Completion predicates at
  [input:180](../../rvzr/executor_km/input_parser.c#L180) and
  [TC:307](../../rvzr/executor_km/test_case_parser.c#L307) mean only not receiving.
- [TC parser:283](../../rvzr/executor_km/test_case_parser.c#L283) sets `finished`
  before semantic validation; a negative result with `finished=true` is an error.
  RDBF has no analogous final semantic validator; its future commit gate must
  check supported format, lengths and association rather than invent a claim of
  comprehensive semantic validation.

The unresolved [expected-failure safety test](../unit_kernel_upload_parsers.py#L560)
must remain visible until a real boundary/reset integration fixes that path.
This design does not turn that expected failure into a passing safety guarantee.

## 2. Replacement policy and identities

**Fail closed, with no restoration of the previous preparation.** An accepted
test-case BEGIN withdraws the old test case, inputs, address snapshot and results
before any shared resource is changed. An input BEGIN withdraws old inputs and
results but retains the explicitly named prepared test case as its parent.
That retention is a prerequisite for uploading inputs, not rollback.

For a deliberately conservative first implementation, any failure or abort of an
accepted attempt retires the entire preparation, including that parent test case.
Retry therefore starts with a fresh RCBF, then fresh RDBF. Retaining a test case
after an input error is a possible later optimization, not an initial guarantee.
Rejected requests that never begin an attempt must not destroy a newer preparation.

Proposed logical fields, not a wire ABI:

| Field | Meaning and lifetime |
| --- | --- |
| `executor_instance` | Opaque 128-bit instance identifier, newly assigned for each successfully initialized executor instance. Never use an address or PID as identity. |
| `state_revision` | Unsigned 64-bit, monotonically increasing on state transitions/invalidation/publication. Used for compare-and-begin, not as a substitute for chunk identity. |
| `active_attempt_id` | Optional unsigned 64-bit token assigned from the new revision at accepted BEGIN. Immutable on that attempt's handle; absent after terminal completion/abort/failure. TC and input attempts use the same non-reused token namespace. |
| `tc_id` | Optional committed test-case identity, assigned from the successful TC attempt token. Valid only while its parsed test case, allocation, code and bookkeeping remain committed. |
| `input_id`, `input_parent_tc_id` | Optional committed input-batch identity and its exact `tc_id`. Assigned only on successful input COMPLETE. Actor-count equality alone is insufficient. |
| `allocation_generation` | Unsigned 64-bit epoch used as `SandboxDescriptor.generation`. Assigned from a new revision **before** invalidating a test-case allocation/code snapshot, including same-address reuse or failed replacement. Stable across successful input replacement, which must not move sandbox allocations. |
| `result_id`, `result_preparation` | Non-reused measurement serial and immutable tuple `(executor_instance, tc_id, input_id, allocation_generation)` attached to a completed result batch. Every new measurement run has its own serial, even on unchanged inputs. |

`active_attempt_id` is never proof of committed readiness. Last successful
TC/input IDs may remain in diagnostic history, but invalid history must not be
used as active `tc_id`/`input_id`. Equal numerical values in different roles
(e.g. an attempt that later commits) do not make the roles interchangeable.
Generation zero is unready startup. Refuse before any counter wraps; no token
reuse within an instance. Instance uniqueness and overflow handling need tests.

## 3. States and allowed transitions

Flags below are derived compatibility views of authoritative state, not separately
published decisions. `T/I` means `tc_ready/inputs_ready`. All transitions and their
publication occur under the coordinator lock described in section 6.

| State | Valid state/resources | T/I | Allowed transition and preconditions |
| --- | --- | --- | --- |
| `EMPTY` | No committed TC/input/result; parsers reset; only documented inert control storage may remain. | 0/0 | Accepted TC BEGIN -> `CLEANING`, then `TC_RX` after successful retirement/reset. |
| `CLEANING` | All execution/read aliases withdrawn; old or partial resources privately owned by a cleanup ledger. No cursor/result. No parser feed. | 0/0 | For new TC BEGIN: cleanup/reset succeeds -> `TC_RX`. For failure/abort: succeeds -> `FAILED`. Any unprovable safety obligation -> `UNRECOVERABLE`. |
| `TC_RX` | One active TC attempt; reset TC parser receives only that handle's bytes. No accepted TC/input or visible bases. | 0/0 | Continuation stays here. Exact stream completion -> `TC_VALIDATE`. Error/abort/close -> `CLEANING`. |
| `TC_VALIDATE` | Complete candidate; successful parser outcome and final semantic/compatibility checks required. Still uncommitted. | 0/0 | Success -> `PREPARING`; failure -> `CLEANING`. |
| `PREPARING` | Private, possibly partial sandbox resources; phase is `ALLOCATING` or `LOADING_CODE`. PTE caches and entry/fault metadata are uncommitted. | 0/0 | All allocation, code, permission and bookkeeping checks succeed -> atomic TC commit -> `TC_READY`. Any error -> `CLEANING`. |
| `TC_READY` | Committed `tc_id` and allocation generation; live data/util/code, complete code and mapping bookkeeping. Both parsers idle. No committed input/result. | 1/0 | Matching input BEGIN -> reset/retire old input state -> `INPUT_RX`. TC replacement BEGIN -> `CLEANING`. Trace rejected. |
| `INPUT_RX` | Committed parent TC pinned; one input attempt, no accepted input/result. Parser bytes belong only to that attempt. | 1/0 | Continuation stays here. Exact completion and input checks -> atomic input commit -> `READY`. Error/abort/close -> `CLEANING`. |
| `READY` | TC and input IDs committed; input parent matches TC; allocations live, no active upload. Results may be absent or belong to this tuple. | 1/1 | Expected-tuple EXECUTE -> `RUNNING`; matching result READ stays here; input BEGIN -> `INPUT_RX`; TC BEGIN -> `CLEANING`. |
| `RUNNING` | One measurement operation owns the prepared tuple and all reachable resources. No upload, configuration mutation, resource cleanup or result overwrite by another caller. | 1/1 | Successful measurement **and restoration** -> publish result -> `READY`. Error -> revoke readiness/results -> `CLEANING`, or directly `UNRECOVERABLE` if restoration cannot be established. |
| `FAILED` | Terminal outcome `aborted` or `failed`, with stage/error diagnostics; cleanup completed and parsers fully reset. No committed resources/IDs/results. | 0/0 | Fresh TC BEGIN with current instance/revision -> `TC_RX` via the normal cleanup check. Never resume the old stream or restore old readiness. |
| `UNRECOVERABLE` | Ownership, permission restoration or execution state cannot be established safe. Quarantined resources may remain owned; their pointers are not exported or dereferenced by normal interfaces. | 0/0 | Reject BEGIN, feed, commit, trace and code reads. Only inert status diagnostics and a separately validated recovery path are permitted. No automatic retry/reset escape. |

`TC_VALIDATE` is a logical gate, not a demand to rewrite the parser algorithm.
The current final semantic validator runs inside the final parser call; that
subphase and its status must be accounted for before commit. A nonnegative return
and `finished=true` are both required, followed by compatibility checks. Merely
changing a status label after a negative final return cannot enter `PREPARING`.
The intermediate validation/allocation/loading phases can remain internal to one
locked call; no userspace polling or round trip is required for each phase.

Every accepted BEGIN clears result identity and cursors (`next_measurement_id=-1`
for the compatibility view). TC BEGIN additionally clears TC/input identities,
advances the allocation epoch and hides bases before retirement. Input BEGIN
clears input identity and retains only its named TC. A failure retiring that
input attempt also invalidates the TC epoch before full cleanup. Failing/aborted
attempts are revoked before cleanup; stale operations cannot publish afterward.
During a new TC BEGIN, the new token is reserved through old-resource retirement
but cannot receive bytes until cleanup/reset succeeds. Failure there revokes it.

## 4. Explicit upload boundaries and transport choice

Ordinary store callbacks provide only `buf/count`. Neither a plausible header,
`receiving=false`, a global generation nor a later status read identifies which
upload produced a particular write. A reset on **every** write would also destroy
valid multi-write streams.

| Mechanism | Benefit | Limitation / decision |
| --- | --- | --- |
| Global BEGIN/ABORT plus unchanged raw sysfs stores | Small API addition; unchanged serializers. | A delayed old write can still become the new attempt's bytes. A userspace lock does not bind writes in the kernel. Insufficient for the target invariant. |
| Token/offset/length on every framed write | Can reject stale chunks under a lock; RCBF/RDBF payload remains unchanged inside a transport envelope. | Requires a new bounded framing parser, atomic begin preconditions and producer changes on every write. Viable alternative, not to implement alongside a second protocol. |
| One upload attempt per open handle, with explicit BEGIN/COMPLETE/ABORT | Kernel retains immutable attempt binding; payload writes remain raw RCBF/RDBF. Close can abort unfinished work. | Needs a small file-backed interface and Python upload adapter; ordinary current store callbacks cannot provide this binding. **Preferred design**, subject to a focused feasibility check. |

Recommended future transport: one narrowly scoped device/file interface with
control operations and ordinary payload writes/reads. Its path, ioctl numbers,
wire structs and privilege policy are **not specified or committed here**. Retain
the current parsers/allocators behind the coordinator; this is an interface adapter,
not a new parser or measurement engine. Stop before expanding into a general
session framework. If file isolation proves disproportionate, choose the single
framed alternative explicitly rather than weakening delayed-chunk rejection.

Proposed operation semantics:

1. **BEGIN(kind, expected_instance, expected_revision, total_bytes, parent_tc_id).**
   Use an unused handle; accept at most one attempt over its entire lifetime.
   Under the lock, compare instance/revision, require no active upload/execution
   and an allowed state, and validate bounded total length without overflow.
   Input BEGIN additionally requires the current committed parent TC. On
   acceptance withdraw the old preparation as specified above, assign the token,
   perform required retirement/reset, and bind the handle. A busy/stale/invalid
   precondition rejection occurs before invalidation. A cleanup error after
   acceptance fails closed. Do not silently supersede another active uploader;
   abort/close it first. Delayed BEGIN requests fail their revision comparison.
2. **CONTINUE: write(bytes).** Under the same lock check handle token, instance,
   kind, active state and parent identity **before** calling a parser. Serialize
   concurrent calls on a shared/duplicated handle. Track accepted byte offset;
   no seek/replay on that handle. Return actual positive consumption and advance
   only by that amount; the producer resubmits the remainder, never the prefix.
   Zero progress on a nonempty write or an impossible return is an error. A
   negative parser return terminates the attempt even if `finished=true`.
   Do not feed bytes beyond the declared stream or start another object implicitly.
3. **Header/chunk contract.** Initially require the first parser feed to contain
   exactly the complete 16-byte header: current parsers assume it is available
   ([input:95](../../rvzr/executor_km/input_parser.c#L95),
   [TC:203](../../rvzr/executor_km/test_case_parser.c#L203)). The adapter coalesces
   serializer header writes rather than passing arbitrary short headers through.
   Continuations obey the supported parser consumption boundaries and bounded
   chunk size. Check declared total against checked header/metadata-derived size,
   allocation limits and final consumed count. Reject truncation, trailing data,
   early parser completion and arithmetic overflow; do not pad allocations.
   Existing chunking fixtures remain the initial supported baseline, not proof
   that every partition is safe.
4. **COMPLETE.** Require exact declared/derived length, successful parser result,
   actual structural completion and applicable validation. Completion is explicit;
   reaching a byte count alone does not publish readiness. TC completion performs
   allocation/code preparation and atomically commits `tc_id`; input completion
   atomically commits `input_id` and its parent. The handle becomes terminal.
   No additional feed is allowed after parser completion, even before COMPLETE.
5. **ABORT / unfinished close.** Match the still-active handle token under the
   lock, revoke it, invalidate readiness/identities/results and perform full cleanup
   and parser reset. Enter `FAILED` only after all required cleanup succeeds.
   Closing a successfully completed handle leaves its committed preparation intact.
   Repeated abort of a terminal handle is harmless or returns a terminal-status
   error; it must never revoke a newer attempt. A delayed write on an aborted old
   handle returns a stale/terminal error without touching either parser.

Automatic close-abort belongs to release of the last reference to the open
handle. Duplicated/inherited descriptors share the same attempt; closing one alias
does not imply that all aliases disappeared. Explicit ABORT revokes every alias.
Keep the Python handle non-inheritable and use explicit abort on exceptions;
do not infer a new session merely from a process ID or a reused descriptor number.

Proposed error categories: `-ESTALE` for identity/revision mismatch, `-EBUSY` for
an active operation, `-ENODATA` for no prepared data, `-EINVAL` for protocol misuse,
and the relevant allocation/validation error for a failed attempt. Unrecoverable
state returns an explicit fatal-status error (e.g. `-EIO`) with persistent status.
Exact errno choices need an ABI review; existing `ASSERT`/`CHECK_ERR` return -EIO
and some parsers return -1. Preserve diagnostics rather than imply these old
values already distinguish all categories. Never report a negative error as a
consumed count or infer validation from a not-receiving flag.

## 5. Ownership and partial-failure contracts

The coordinator needs an ownership ledger for the existing resources, not a
second set of allocations or a copy of the old test case for rollback. Record
actual acquired objects, extents, capacities, aliases and initialized stages.
Last-successful actor/input counts are not ownership records. Initially prefer
full retirement on replacement/failure over capacity reuse; retained inert
control buffers are allowed only with a proven capacity/lifetime contract.

Cleanup order is a dependency order: exclude users; revoke visibility/entry;
restore any temporary machine/PTE state while its mappings are still live;
retire PTE caches/snapshots; handle executable permissions and release backing;
release parser/results storage and reset contexts. Keep private cleanup pointers
until release succeeds; clearing an exported alias must not lose ownership.

| Resource / failure stage | Required obligation before recoverable failure or new TC reception |
| --- | --- |
| Utility/data pages, page-pointer array, vmap and aligned interior address | Track block order, actual acquired pages, mapping base and aligned borrowed alias separately. Unmap only the owning base; release the block/array exactly once. Clear all `sandbox->data/util` aliases before retirement. Page-array/vmap failures already have some local cleanup, but the outer failure path needs a complete contract. See [sandbox manager:32](../../rvzr/executor_km/sandbox_manager.c#L32), [:85](../../rvzr/executor_km/sandbox_manager.c#L85). |
| Code backing and X/NX changes | Track allocated size/page extent and results of permission operations. Revoke entry visibility before overwrite/release. Check X/NX errors; do not infer permissions from the requested operation. If safe revocation/release cannot be established, quarantine and enter `UNRECOVERABLE`, rather than free and retry speculatively. See [:48](../../rvzr/executor_km/sandbox_manager.c#L48), [:139](../../rvzr/executor_km/sandbox_manager.c#L139). |
| `sandbox_t` and exported aliases | Give the descriptor one owner and release policy. Null or replace borrowed aliases coherently; hide bases while uncommitted. Current [pointer setup:59](../../rvzr/executor_km/sandbox_manager.c#L59) can publish entry before loading, and [destructor:294](../../rvzr/executor_km/sandbox_manager.c#L294) does not free the descriptor. |
| Cached PTE pointers, original permission snapshots, faulty-PTE scratch | Record which mapping generation and entries are initialized. Restore only valid saved entries while their original mappings are live; invalidate all borrowed PTE pointers before unmapping. Partial cache fill/allocation must not be published. See [cache:208](../../rvzr/executor_km/page_tables_host.c#L208), [snapshot:255](../../rvzr/executor_km/page_tables_host.c#L255), [restore:312](../../rvzr/executor_km/page_tables_host.c#L312), [free:466](../../rvzr/executor_km/page_tables_host.c#L466). |
| Code entry, fault-handler alias and prologue metadata | Clear these on withdrawal and every loader failure, including errors before main initialization and after a successful main but failed secondary section. Publish only after **all** sections succeed. See [loader:39](../../rvzr/executor_km/code_loader.c#L39), [main:72](../../rvzr/executor_km/code_loader.c#L72), [entry:155](../../rvzr/executor_km/code_loader.c#L155), [prologue:22](../../rvzr/executor_km/macro_expansion.c#L22). |
| Parser buffers and stream state | Release each parser-owned buffer once; reset cursor, receiving/completion/error status, actor/symbol/input counts, section ID/start/end, aliases and capacity high-water marks to match actual retained storage. Reset must leave a valid initialized idle context, not a null root that current parsing dereferences. Reset both parsers on full failure/TC BEGIN; input BEGIN resets input state while retaining the committed TC. |
| Measurements and pagination | Withdraw result identity and cursor before reuse/free. Track actual buffer capacity separately from requested counts; do not advance a capacity high-water mark on failed allocation. Old result handles must fail before copying data. See [measurement allocator:348](../../rvzr/executor_km/measurement.c#L348). |

Existing free/init pairs are **not** the reset implementation: the TC section
statics at [parser:193](../../rvzr/executor_km/test_case_parser.c#L193) are not
reset by [init/free:336](../../rvzr/executor_km/test_case_parser.c#L336), and
input high-water counters at [input:24](../../rvzr/executor_km/input_parser.c#L24)
are not reset by [init/free:183](../../rvzr/executor_km/input_parser.c#L183).
Define explicit reset helpers and postconditions, including partial initialization.

Failure handling by stage:

- Receive/validation failure: revoke the attempt, retire its parser objects and
  any retained parent preparation, reset both contexts and end in clean `FAILED`.
  A parser that has corrupted ownership or exceeded proven bounds cannot be
  assumed recoverable merely because free functions return.
- Allocation/cache failure: unwind only recorded successful acquisitions, retire
  any installed aliases/cache entries and old resources, reset counts/capacities.
  No-growth retry must not reach the old allocator's `memset` on null/stale storage
  ([sandbox manager:174](../../rvzr/executor_km/sandbox_manager.c#L174)).
- Code-load failure: discard partial code and fault metadata, revoke execution,
  and retire all preparation resources. Never fall back to the prior code image;
  the [loader:45](../../rvzr/executor_km/code_loader.c#L45) overwrites it in place.
- Abort follows the same cleanup path as a failure, with an explicit reason.
  Cleanup is idempotent for known ledger stages and must not dereference retired
  mappings. Retry is allowed only after its postconditions and parser reset hold.
- Permission restoration, ownership or runtime cleanup uncertain: enter
  `UNRECOVERABLE`. Do not forcibly clear `unfinished_call` or make flags true.
  A later recovery mechanism must establish safe CPU/mapping/resource state;
  module reload is not a presumed cure. [Module init:689](../../rvzr/executor_km/main.c#L689)
  lacks an explicit local unwind there, and [exit:751](../../rvzr/executor_km/main.c#L751)
  explicitly warns against removal after an unfinished call. Recovery/unload
  safety requires separate review and validation, possibly a system restart.

## 6. Synchronization, execution and reads

Propose one sleepable executor-wide coordinator mutex; no per-resource lock
hierarchy initially. All upload/control callbacks, preparation-affecting settings,
descriptor/base/code reads, measurement admission and result access participate.
The lock protects state, ownership, identities, parser calls and publication as
one consistency domain. Access control is a separate concern; tokens are
consistency identities, not authentication secrets.

- Acquire in process context **before** allocation, parser mutation or entering
  the measurement path. Hold through a chunk call, then release while waiting
  for userspace; never hold across an upload's entire lifetime. On each subsequent
  call recheck its immutable binding under the lock. Do not add another handle
  lock unless necessary; if later needed, document a single consistent order.
- Hold the coordinator lock through allocation/loading/commit or failure cleanup.
  No interface may consume intermediate globals simply because a pointer is nonnull.
  No preparation-affecting configuration write may change code templates, actor
  interpretation, permissions or measurement settings mid-preparation. Initially
  allow such changes only in clean `EMPTY`/`FAILED`; otherwise reject, or explicitly
  retire the preparation through the same protocol. Define the concrete setter
  list before integration rather than cover only the two upload callbacks.
- EXECUTE must atomically compare the expected preparation tuple, require `READY`,
  no active upload, positive committed input count and supported layout, then
  claim the resources and enter `RUNNING`. Hold exclusion through the experiment
  **and restoration**, then publish a result identity and release. Another BEGIN
  waits or returns busy, never frees resources underneath execution. Take no
  sleepable lock after interrupts/preemption have been disabled and use no
  spinlock around allocations or the full experiment. Review all error exits of
  [trace_test_case():324](../../rvzr/executor_km/measurement.c#L324) before claiming
  runtime recovery; a host stub cannot prove CPU-state restoration.
- Do not require BEGIN/ABORT from userspace to release a lock needed by the
  executing thread. A close/abort cannot asynchronously free a running allocation.
  Native lock ordering and bounded execution remain validation requirements.
- Bind each result reader to `(result_id, result_preparation)` and its own cursor.
  Every page checks current eligibility and identity under the lock **before**
  copying. A new BEGIN immediately revokes all pending pages. A stale page must
  not trigger a fresh experiment or advance any cursor. Keep the existing six
  numeric columns and `done` ordering if a compatibility formatter is retained;
  execution authorization and result ownership belong outside that text format.
  Do not silently overwrite a still-owned batch with another reader's run;
  initially require it to be drained/closed or explicitly discarded first.
- [test_case_bin_read():349](../../rvzr/executor_km/main.c#L349) needs the same
  liveness/exclusion contract, a bound `tc_id`/allocation epoch and code-read
  bounds based on the owning allocation, requested count and checked offset.
  Its current `loaded_test_case_entry + pos`, actor-size limit and PAGE_SIZE-based
  copy are not a proof of that contract. Entry can be interior to its allocation;
  the future read must define whether it exports allocation bytes or entry-relative
  bytes and validate that exact range. Likewise, [base getters:400](../../rvzr/executor_km/main.c#L400)
  and other debug pointer readers must not expose/dereference withdrawn aliases.
  Returning an inert status is allowed in unready states; reading retired code is not.

A coherent snapshot is copied under the lock and serialized from that copy.
It is not a lease: a later BEGIN can invalidate it immediately. Kernel validation
of the expected tuple at EXECUTE and each result page supplies the actual gate.
A read-only descriptor or an atomic counter alone cannot do this.

Example: TC attempt A commits, then input attempt B is interrupted. ABORT(B)
revokes B and all committed eligibility, cleans resources and resets parsers.
Only after that succeeds can a fresh TC attempt C and input attempt D commit.
A delayed write or close on B must fail its handle/token check without feeding
the parser, altering D's cursor or revoking C/D. If cleanup of B fails, C cannot
begin at all. This is the key regression beyond ordinary Boolean readiness.

## 7. Descriptor and Python integration

Keep [SandboxDescriptor:14](../../rvzr/sandbox_descriptor.py#L14) semantics:
`ready` means allocations, bookkeeping and code are prepared, **not** input
readiness. A snapshot can be ready in `TC_READY` and remain allocation-identical
through input upload. Hide bases/report zero actors when that allocation is
withdrawn. `execution_enabled` describes supported executor/layout policy, not
authorization for a particular input batch. The kernel still requires `READY`
and the complete tuple to execute. Candidate 16 KB execution remains rejected,
regardless of producer flags or the kernel's compiled page size.

Use a separate versioned preparation-status/control envelope containing phase,
revision, attempt/committed IDs and result association alongside the existing
layout snapshot. Do not silently overload its single `generation` with input
batch identity or add unknown fields to the strict v1 descriptor parser.
`SandboxDescriptor.generation` maps to `allocation_generation` above. In this
protocol any change to reported layout/bases/code preparation requires a new
allocation epoch, even if addresses happen to be reused.

[prepare_unicorn_model():19](../../rvzr/model_unicorn/preparation.py#L19) is
currently isolated, validates legacy eligibility and builds a fresh model with
the descriptor's bases; it does no executor I/O or authorization. Its documented
eligibility check can support allocation-ready `TC_READY` without input readiness,
but the control tuple is still checked later by the kernel. Preserve that division;
never synthesize a descriptor from the passive 16 KB geometry and call it active.

Minimum future Python changes, with a compatible kernel protocol present:

1. Configure modes before BEGIN; upload RCBF on a single bound handle, with a
   complete header, correct short-write handling, explicit COMPLETE and an abort
   on exceptions. Obtain the committed TC/allocation snapshot afterward.
2. Construct/reconstruct the normal or architectural model from that completed
   allocation, then model the inputs. Check instance/allocation generation before
   reuse. Rebinding only `model._bases` does not reconstruct the engine, taint
   tracker or other address-dependent objects. Model failure aborts/discards the
   kernel preparation; do not trace with a half-prepared Python model.
3. Upload final/boosted inputs using input BEGIN bound to that TC; COMPLETE returns
   the input ID. Execute with the exact tuple and read all pages through the bound
   result handle. Input replacement must not relocate data/code; otherwise rebuild
   from a new TC preparation. A changed generation is an error/reprepare event,
   not permission to silently keep old contract traces.
4. Handle abort/close and stale/fatal status explicitly; never blindly resend a
   fresh header into an old handle or drain obsolete pages as if they were current.
   Normal and architectural executors share kernel globals today, so treat them
   as successive preparations, not independent simultaneously live allocations.

Current compatibility work is concrete:
[executor.load_test_case():258](../../rvzr/executor.py#L258) writes RCBF,
[trace_test_case():304](../../rvzr/executor.py#L304) then writes RDBF;
[RCBF serializer:136](../../rvzr/tc_components/test_case_binary.py#L136) and
[RDBF serializer:182](../../rvzr/tc_components/test_case_data.py#L182) open paths
internally. A small transport adapter can stage bounded serialized files or use
a later stream sink while preserving byte-for-byte serializer tests; no format
change is needed. Input batches can be large, so do not require unbounded RAM
materialization just to obtain a declared length.

[_read_trace():151](../../rvzr/executor.py#L151) currently opens a new `cat`
subprocess repeatedly, and [_rewind_km_output_to_end():195](../../rvzr/executor.py#L195)
does the same; both need the bound-result lifecycle. CPU affinity must apply to
the process/thread making the new EXECUTE call, replacing the current `taskset cat`
arrangement. [Fuzzer initialization:475](../../rvzr/fuzzer.py#L475) captures bases
before later TC loads; [normal load:136](../../rvzr/fuzzer.py#L136) and
[architectural load:382](../../rvzr/fuzzer.py#L382) load the model before hardware.
Future integration must reorder around completed TC preparation, retaining the
current input generation/boosting semantics and model coverage/lifetime contracts.

Backward compatibility means unchanged 4 KB layout, formats and successful
measurement meaning; it cannot mean unchanged unsafe upload transport *and* full
new guarantees. Initially keep the new implementation unavailable/inert until
complete. When enabling it, select one mode for the whole instance and disable
legacy mutating/trace bypasses in protocol mode. Old kernels can retain an explicitly
selected legacy client path, without claiming the new guarantees. Unsupported
new/old combinations fail clearly, never fall back silently after a protocol error.

## 8. Small implementation sequence and acceptance gates

These are future tasks, not changes made by this document. Keep each helper
independently tested while passive; live activation needs the atomic integration
listed below. Do not advertise intermediate passive tests as kernel enforcement.

1. **State invariants first (smallest next coding task).** Add a private, passive
   coordinator transition/identity representation with host tests and no live
   callback wiring. Test TC/input begin, validation/prepare phase order, commit,
   abort, failure, cleanup-success/failure and terminal unrecoverable rejection.
   Reject stale identities without mutating newer state; check no flags/cursors
   become valid early. Include a fake ownership ledger with explicit limits on
   what it proves. No parser, allocator or executor rewrite in this milestone.
2. **Reset and upload boundaries.** Add explicit parser reset postconditions and
   a minimal attempt-bound adapter, exercised against the real parsers in the
   existing bounded harness. Cover interrupted TC/input, old-handle delayed feed,
   duplicate completion/abort, fresh-header alignment and short returns. Keep
   the current legacy defect evidence until the integrated route actually rejects
   mixed admission; a passing fake-state test alone does not resolve it.
3. **Failure-safe resource cleanup.** Establish explicit acquisition/capacity
   accounting and cleanup contracts in the existing managers, one resource group
   at a time. Test failures after each acquisition/loading stage, repeated cleanup
   and no-growth retries. Host substitutes establish accounting only; separately
   validate real mappings, permission failures and restored execution state before
   enabling retry. Until a stage is proven recoverable, select `UNRECOVERABLE`.
4. **Association and atomic publication.** Wire TC/input identities, parent links,
   allocation snapshots and commit decisions under the coordinator mutex. Test
   that the last successful ID cannot authorize a failed replacement. No generation
   publication around an unchanged destructive allocator as a stand-alone safety fix.
5. **Execution, pagination and read enforcement.** Wire expected-tuple admission,
   running-resource exclusion, result ownership and protected code/base/status
   reads. Host callbacks with measurement stubs test rejection before side effects;
   controlled concurrent tests check interleavings. Native restoration/lock tests
   remain a distinct gate, never inferred from single-process stubs.
6. **Python and Unicorn.** Add the transport adapter and mocked integration tests
   for completed-TC snapshot -> model reconstruction -> final input upload -> bound
   execution/read. Cover normal, architectural, retries and model-construction
   failure. Preserve serialization and existing preparation/coverage/lifetime tests.

**Must change together at live activation:** attempt binding plus complete parser
reset; state/ownership cleanup plus all allocation/code publication paths;
TC/input commits plus trace/result/read gates under shared synchronization; and
the kernel transport contract plus its Python consumer/model ordering. These can
be developed as inert steps, but must not expose a partially enforced new route
beside unguarded legacy callbacks. Continue rejecting unsupported VM/user-actor
cases unless their resource lifetimes are separately covered.

Validation layers:

- **WSL2:** transition/token tests, real-parser boundary/reset regressions,
  real extracted callback admission tests, ownership accounting with bounded
  substitutes, separate ASan/UBSan, serialization/descriptor/model lifecycle suites.
  None proves real page ownership, PTE writes, X/NX or hardware restoration.
- **Native generic ARM64:** retain the existing [Ubuntu builds with/without
  VMBUILD](../../.github/workflows/arm64-software-baseline.yml#L56) and
  [Fedora Asahi 16 KB compile-only job](../../.github/workflows/arm64-software-baseline.yml#L193).
  Compilation establishes API/type integration only. Loaded-kernel lifecycle and
  concurrency validation, if later authorized, is a separate stage on a supported
  configuration; a generic ARM64 result is not M3 validation.
- **M3/Fedora Asahi:** eventual actual kernel/page configuration, cache observer,
  PMU/timer access, heterogeneous-core affinity, fault/PTE behavior and restoration
  require target validation. This lifecycle protocol neither activates candidate
  16 KB geometry nor resolves those hardware feasibility questions.

**Stopping criterion:** one bounded upload protocol; explicit reset; fail-closed,
accounted resource retirement; identity-bound commits/execution/results; coherent
reads; and Python/model agreement for the supported legacy 4 KB ARM64 scope.
Stop after these invariants have focused tests and stated native validation gates.
No multi-client scheduling, rollback images, generic fuzzing framework, cache
backend, format redesign or 16 KB activation belongs in B3.3d.

## 9. Open questions before integration

- Confirm that the proposed minimal file interface fits the module build/API
  constraints and available userspace deployment. Specify bounded control structs,
  error mapping, close semantics and exact length limits before committing an ABI.
- Inventory every mutable setting and pointer/debug read in `main.c` and direct
  users of globals; determine the precise code-export range, not just a readiness
  Boolean. Check other architecture paths separately rather than infer x86 safety.
- Define a checked idle parser reset despite function-local statics and root
  dereferences. The separate [uninitialized `has_start` concern](../../rvzr/executor_km/test_case_parser.c#L115)
  remains a validator issue; it is not fixed or used to justify readiness here.
- Validate code-permission, cache/PTE lifetime and execution-error restoration
  paths, including the measurement allocator's early capacity update. Decide which
  failures permit cleanup and which must remain terminal. Existing free/init pairs
  and module reload are not evidence of recovery.
- Verify lock compatibility with IRQ/preemption changes, execution CPU affinity,
  config mutation and module shutdown. Define safe handling of outstanding handles
  during shutdown; instance replacement must invalidate all old handles/snapshots.
- Preserve model resource lifetime and diagnostic coverage during eventual
  reconstruction. The isolated preparation helper starts fresh coverage; transfer
  policy is separate work, not an excuse to retain stale addresses.

This documentation-only stage changes no runtime behavior. Existing
characterization evidence remains authoritative until the proposed implementation
and its separate validation gates are completed.
