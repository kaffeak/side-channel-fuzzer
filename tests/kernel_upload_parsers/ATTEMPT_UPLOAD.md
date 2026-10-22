# B3.3d.4a: host-only attempt-bound upload integration

The [adapter](attempt_upload.c), [header](attempt_upload.h) and fixed
[scenarios](attempt_upload_scenarios.inc) link the **actual** production
`rvzr_prep_*` implementation, both parsers and both explicit reset functions.
They live under tests, outside Kbuild and all live callbacks. No production file
is changed. This is a single-threaded integration test, not a working transport,
kernel security gate, native cleanup implementation or 16 KB activation.

## Boundary sequence and identity

| Operation | Calls and required outcome |
| --- | --- |
| Fresh context | `rvzr_prep_init()` once with a test instance, after parser construction. Never used to escape a failed/fatal state. |
| TC BEGIN | `rvzr_prep_begin_tc()` withdraws previous eligibility and reserves an attempt in `CLEANING`. Simulate native-resource retirement, call both actual resets, verify private idle state and tracked ownership, then call `rvzr_prep_cleanup_done()`. Feed is possible only after successful transition to `TC_RX`. |
| Input BEGIN | `rvzr_prep_begin_input()` checks expected instance/revision and parent TC, withdraws old input identity, and enters `INPUT_RX`. Reset the actual input parser before returning. Retain only its named TC. |
| FEED | Check the actual active attempt, instance, bound kind, parent and receiving phase before a parser call. Reject validation/allocation/loading phases even when `rvzr_prep_check_attempt()` accepts the token. Call the actual parser once; count it through the existing GNU linker wrappers. |
| TC COMPLETE | Require successful structural receipt and exact declared byte position; acknowledge receive/semantic-validation stages through the state component, simulate allocation/loading, and call `rvzr_prep_commit_tc()`. |
| Input COMPLETE | Require exact successful receipt and the same parent, then call `rvzr_prep_commit_input()`. Only the state machine's resulting identity can pass logical execution eligibility. |
| ABORT / parser failure | Validate identity first, call `rvzr_prep_abort()`/`rvzr_prep_fail()`, retire fake resources, reset both actual parsers, verify tracked cleanup and acknowledge it. Clean failure ends in `FAILED`, unsafe cleanup in `UNRECOVERABLE`. No previous preparation is restored. |

A handle binds once to its instance/attempt, kind, parent and declared length;
subsequent BEGIN on that handle is rejected. Only its consumed position and
structural `received` fact change during feeding. These are kernel-handle-like
objects in a trusted C harness, not a wire ABI or tamper-resistant capability.
Tests use altered copies to exercise wrong-instance/kind/parent rejection.
There is no independently maintained readiness flag. Legacy callback readiness
globals are unused by the adapter; `rvzr_prep_check_execution()` is a read-only
logical check and never executes a test case.

Input ABORT/failure retires the TC too. The interrupted-input scenario therefore
requires a fresh valid TC between ABORT A and input BEGIN B. Attempting input
BEGIN immediately after the failure is rejected. This follows the conservative
fail-closed policy rather than silently retaining the old parent.

## Receipt and failure rules

Declared size is bounded to 16..524288 bytes; FEED is bounded to 4096 bytes and
the remaining declared size. A first call must supply at least 16 bytes; only its
complete 16-byte header is passed to the parser. No incomplete header is padded
or forwarded. Subsequent calls preserve positive parser short returns, advance
position only by actual consumption and require the producer to resubmit the
unconsumed tail. The scenario driver also bounds requests by the owned fixture.

Negative parser returns cause immediate withdrawal/cleanup, including RCBF's
`finished=true` semantic failure. Parser completion before the declared size
fails closed. Declared exhaustion without completion cannot commit. COMPLETE
before complete receipt also fails closed. Extra FEED after receipt returns
`-EALREADY`; operations after commit or abort are rejected by identity checks.
Neither case implicitly starts another stream.

Length/parent checks add boundary discipline, not a comprehensive format validator.
RCBF's existing final validator still runs in the final parser call. RDBF has
only its existing validation plus the adapter's association/length checks; no
new general metadata validator or malformed-input campaign is introduced.
Native CPU compatibility and supported hardware semantics are not established.

## Cleanup evidence and CHECKED_ZALLOC

Allocation/loading stages are simulated by counted actions and two fake ownership
bits. Successful fake cleanup explicitly clears these bits. A simulated cleanup
failure leaves them quarantined. Cleanup acknowledgment requires all of:

- Both real reset functions returned zero.
- Read-only observations confirm all their private idle-state postconditions.
- The host allocation registry contains exactly the two tracked empty roots,
  with no outstanding parser payload allocation.
- Fake resource retirement succeeded and no fake ownership bits remain.

These checks establish tracked host obligations only, not release of pages,
executable mappings, PTE caches, permissions, fault metadata or CPU state.
The failure scenario starts with a logically valid preparation and fake resources,
then fails replacement cleanup. It enters `UNRECOVERABLE`; further BEGIN, FEED,
COMPLETE, ABORT and logical execution admission are rejected without parser calls
or state changes. Parser roots are still freed at process teardown; this does
not claim that quarantined native resources could safely be freed or retried.

[CHECKED_ZALLOC](../../rvzr/executor_km/include/shortcuts.h#L122) is a GNU statement
expression containing `return -ENOMEM` when `kzalloc` returns NULL. In these two
reset functions that return exits the **reset function**, so the documented
allocation-error return is guaranteed for that branch under the existing GNU C
build semantics. It is needed only when the root is absent. Existing-root reset
performs no allocation. This is source-derived: `host_allocate()` fails the
process on unexpected allocation failure rather than returning NULL, so the
host scenarios do **not** execute or prove the reset `-ENOMEM` path. No allocator
failure injection or unrelated macro correction is added.

## Rejection and recovery evidence

The stale tests first interrupt A, abort it, start B and feed a known prefix of
B. They then present A's FEED, COMPLETE and ABORT to the adapter. Before/after
snapshots compare every preparation-state field, parser-call count, both parser
cursors, logical counts, root addresses, tracked allocation totals, cleanup/reset
and fake-preparation counts, B's handle position/receipt facts, and an initialized
payload prefix byte-for-byte. No uninitialized input-allocation tail is inspected.

Observed on x86-64 WSL2/GCC 13.3.0:

| Current B | Each rejected A operation | Production parser calls before/after | B prefix preserved | Final outcome |
| --- | --- | --- | --- | --- |
| RDBF | FEED, COMPLETE, ABORT each return `-ESTALE` (-116) | 18 / 18 | 4096 already-written bytes | B completes, all 12288 intended payload bytes match, state READY |
| RCBF | FEED, COMPLETE, ABORT each return `-ESTALE` (-116) | 10 / 10 | 16 already-written code bytes | B's complete 36-byte code payload matches; fresh inputs then produce READY |

Final payload checks reuse the independently bounded comparator from B3.3d.3,
against separate expected-byte files. Input B uses a serializer-generated pattern
different from A, including serialized padding. No hash alone stands in for exact
comparison. The old readiness defect's header-as-payload behavior cannot occur
through these rejected calls because the production parser is never entered.

Twelve new scenarios cover valid TC/input commitment and eligibility; both stale
upload types; wrong instance/kind/parent and stale BEGIN; premature and duplicate
COMPLETE; terminal FEED/ABORT; both parser-error paths; cleanup failure; three
abort/retry cycles per format; too-short/too-long declared lengths and incomplete
headers for **both** formats; and feed rejection in all three nonreceiving TC
phases. The last test deliberately advances the actual passive component to an
internal phase to model a paused coordinator; it is not evidence that those
incomplete bytes were semantically validated. Real-parser algorithm tests remain
in the same suite.

## Reproduction and results

```sh
python -m unittest -f tests.unit_kernel_upload_parsers -v
RVZR_PARSER_SANITIZER=address python -m unittest -f tests.unit_kernel_upload_parsers -v
RVZR_PARSER_SANITIZER=undefined python -m unittest -f tests.unit_kernel_upload_parsers -v
```

The same compiler fixture builds the actual `preparation_state.c` and test-only
adapter alongside the existing parsers, wrappers and extracted legacy callbacks.
The adapter, harness and state unit use `-D__KERNEL__` **only to select the real
state header's kernel `u64` spelling** through the existing mocked
`linux/types.h`. `compat.h` adds that one type alias, consistent with its existing
kernel-style `uint64_t`. This is host compilation with Linux dependencies shimmed,
not a kernel build or emulation of kernel behavior. The independent 20-state-test
suite still exercises its ordinary host-header branch.

Strict warnings remain enabled, with only the established production-parser
signedness and callback-unused-parameter exceptions. The existing bounds remain:
512 KiB per fixture, 2 MiB tracked parser storage, 128 tracked blocks, five seconds
per scenario and 30 seconds per compilation. Scenario loops and input sets are
fixed. Artifacts are temporary. No hardware, sysfs operation, privileged instruction
or generated-code execution occurs. Every scenario requires zero tracked parser
allocations at final teardown.

Results: **59 tests per ordinary/ASan/UBSan configuration: 58 passed and one
unchanged expected failure**. The 12 new integration tests and all preceding
parser/reset tests pass. All 148 supporting passive-state, geometry/parity,
input-format, descriptor and model-lifecycle regressions pass, including the
20 passive-state tests. Flake8, strict mypy and Pylint (10/10) pass. ASan retains
the documented WSL2 LeakSanitizer limitation; no LeakSanitizer claim is made.

GCC `-fanalyzer` reported no diagnostics for the adapter or state component.
It still reports the known production TC validator's uninitialized `has_start`
read, plus existing signedness/unused-parameter warnings. Those findings are not
hidden or fixed; semantic-failure fixtures include measurement start. Full local
diagnostics: `/tmp/rvzr-attempt-upload-analyzer.txt`. Clean bounded sanitizer runs
do not establish general parser safety. These new results are local WSL2 results,
not a native ARM64/kernel/M3 validation claim.

## Limits and next transport milestone

The existing untagged callbacks are unchanged and never invoke this adapter.
`test_recovery_interrupted_rdbf_safety_invariant` remains unchanged and expected
to fail. Adapter success is not a global fix for legacy mixed-input admission.
There is no synchronization, result-generation enforcement, descriptor publication,
real file lifetime, user-copy implementation or module-unload handling here.

The smallest kernel-transport milestone should first define a narrow kernel-facing
coordinator contract from this tested boundary sequence: immutable per-open
attempt binding, bounded user-copy/header rules, terminal close-to-abort behavior
and one shared synchronization boundary. Develop it without registering a live
endpoint or allowing execution. The fake cleanup/allocation/loading steps must
then be replaced by separately audited, failure-safe native ownership operations;
they cannot be copied into a live readiness path. Actual file operations may be
activated only with those cleanup contracts and consistent gating of legacy
mutators/readers. No rollback to an older preparation or reinitialization escape
from `UNRECOVERABLE` is justified by these tests.
