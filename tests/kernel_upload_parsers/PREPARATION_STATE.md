# B3.3d.2 passive preparation state

The implementation is [preparation_state.c](../../rvzr/executor_km/preparation_state.c)
with [its public header](../../rvzr/executor_km/include/preparation_state.h).
It is intentionally **absent from Kbuild and every live callback**. It is a
small executable subset of [the protocol design](PREPARATION_PROTOCOL.md), not
an implementation of the kernel preparation protocol. No parser, resource,
hardware, synchronization or descriptor operation takes place.

## Representation and caller contract

| Stored field | Invariant requiring it |
| --- | --- |
| 128-bit `instance` | An old module instance's token must not authorize work in a new instance, even if counters coincide. The caller assigns a fresh nonzero instance; this component does not generate random IDs. |
| `revision` | Compare-and-begin and cleanup acknowledgments must refer to the exact current state, rather than an earlier observation. Every accepted mutating transition advances it. Read-only checks do not. |
| `active_attempt` | A stale/aborted upload may not advance, fail or commit another upload. A TC BEGIN reserves it during old-resource cleanup; it is usable only after successful cleanup acknowledgment. Zero means no active attempt. |
| `tc_id` | The current committed test case must be distinct from an active replacement. It becomes the successful TC attempt's ID, and is cleared before TC replacement/failure. |
| `input_id` | Input receipt alone cannot authorize execution; only input commit assigns this ID. Input BEGIN clears the old ID immediately. |
| `allocation_generation` | Same-address replacement/failure still invalidates an allocation snapshot. This epoch changes before TC retirement and stays fixed across successful input replacement. |
| `phase` | Enforces receive -> validate -> allocate -> load -> TC commit order, cleanup gating, input association and terminal failure. Validation/allocation/loading are internal phases, not separate transport requests. |

There is no separately stored parent ID: input BEGIN checks the supplied parent
against `tc_id`, and no TC change is allowed in `INPUT_RX`. Input failure/abort
clears both IDs. This structurally associates an input commit with its parent.
There are no duplicated readiness Booleans, history IDs, result cursors, resource
pointers, capacities or diagnostic strings. `READY` plus an exact identity match
is **logical eligibility only**, not hardware admission. Running-state exclusion,
result identity/pagination, layout policy and real resource validation remain
future integration work. In particular, this component cannot enable 16 KB execution.

Snapshots/attempts/identities carry the instance. Attempt IDs are assigned from
BEGIN's new revision and never reused. A committed TC/input ID retains the value
of its successful attempt but has a different role. Snapshots are copied values,
not leases. Struct members are implementation state, not a serialization ABI;
callers must not modify them or race API calls. Initialization is a constructor
for fresh storage and a new instance only, not a reset/recovery escape from
`UNRECOVERABLE`. This is a C caller contract, not memory-tampering protection.

## Operations and transitions

```text
init -> EMPTY
TC BEGIN -> CLEANING [new token reserved, old TC/input identities withdrawn]
  cleanup_done(safe=true) -> TC_RX
  advance_tc -> TC_VALIDATE -> TC_ALLOCATE -> TC_LOAD
  commit_tc -> TC_READY [TC identity committed, no input]
input BEGIN(current parent) -> INPUT_RX [TC retained, old input withdrawn]
  commit_input -> READY [exact tuple becomes logically eligible]

active fail/abort -> CLEANING [all identities withdrawn, token revoked]
  cleanup_done(safe=true) -> FAILED -> fresh TC BEGIN
  cleanup_done(safe=false) -> UNRECOVERABLE
```

TC replacement is allowed from `TC_READY`/`READY` and first withdraws both
identities. Input replacement is allowed from `TC_READY`/`READY` and retains only
the named TC. There is one active attempt; callers cannot silently supersede it.
Input failure conservatively retires the TC too; a fresh RCBF is required.
An old cleanup ticket cannot affect a subsequent attempt or committed preparation.

`advance_tc` acknowledges successful completion of the current phase, not just
an arbitrary request to move forward. TC commit acknowledges successful loading
of all code. Input commit acknowledges complete, validated, parent-associated
input. These are trusted caller attestations; the component does not inspect
bytes or establish that these prerequisites really happened. `check_attempt`
checks identity across active phases; it is not permission to feed a parser in
validation/allocation/loading phases. A future transport must also require RX.
Input BEGIN likewise does not perform/reset a parser; the future caller must
reset it at the boundary or fail the accepted attempt.

`INVALID`, `STALE`, `BAD_STATE` and `FATAL` reject without changing state or output
arguments. `OK` means the requested state transition/report was accepted: for
example `cleanup_done(false)` accepts a report of unsafe cleanup and enters
`UNRECOVERABLE`; it does not mean cleanup succeeded. Abort/failure share one
withdrawal path; their diagnostic reasons belong with the caller.

`UINT64_MAX` is reserved as a terminal revision. If an otherwise valid transition
would consume it, `EXHAUSTED` performs a defined complete terminal transition:
revision saturates, active/committed IDs are revoked, allocation epoch changes
and state becomes `UNRECOVERABLE`. No counter wraps and no successful token uses
that value. This differs deliberately from an invalid-operation rejection.
It **does not free resources**: future callers must quarantine them and reject
execution. Subsequent operations return `FATAL` without further mutation.

## Cleanup accounting and limits

The only production bookkeeping is a revision-bound cleanup acknowledgment.
`safe=true` attests required ownership retirement **and complete parser reset**;
it permits the reserved TC attempt to receive, or ends a failed attempt in clean
`FAILED`. Unknown safety enters `UNRECOVERABLE`, with no automatic recovery API.

The [test-only fake ledger](preparation_state_test.c) has an outstanding-resource
bitmask and a parser-reset flag. Tests report safe only when both obligations are
satisfied. They exercise control flow, not resource releases. A false attestation
would fool this passive component; native acquisition-stage accounting and
permission/alias cleanup must be implemented separately as required by
[RESOURCE_OWNERSHIP.md](RESOURCE_OWNERSHIP.md). No claim is made about pages, PTEs,
X/NX changes, counter restoration or reset of the real parsers. No constructor or
cleanup acknowledgment is evidence that module reload is safe.

## Host verification

```sh
python -m unittest -f tests.unit_preparation_state -v
RVZR_PREPARATION_SANITIZER=address python -m unittest -f tests.unit_preparation_state -v
RVZR_PREPARATION_SANITIZER=undefined python -m unittest -f tests.unit_preparation_state -v
```

The runner compiles the actual standalone C source and the fixed C scenarios with
`cc -std=c11 -pedantic-errors -O2 -g -Wall -Wextra -Werror -I rvzr/executor_km/include`,
then runs each scenario in a separate process. `CC` may select a native compiler.
Compilation has a 30-second timeout; scenarios have five seconds, bounded loops
and no dynamic allocations. Build files are temporary. Sanitizers add the named
`-fsanitize`, `-fno-sanitize-recover=all`, `-fno-omit-frame-pointer` and `-no-pie`.
ASan uses the parser harness's documented WSL2 setting `detect_leaks=0`; bounds
checks remain enabled. This is not a LeakSanitizer result. Diagnostics or crashes
fail explicitly rather than being skipped.

The 20 scenarios cover ordinary progression; premature/duplicate commits; failure
at every TC phase; whole-preparation invalidation on input failure; both abort
types; stale/delayed attempts and cleanup tickets; safe retry; unsafe resource or
parser-reset reports; fatal-state rejection; 32 consecutive preparations with
monotonic identities; every mutator at the revision boundary; uncommitted inputs;
newer-state preservation; wrong instance/TC/input/epoch; replacement; and invalid
operations. Rejection tests compare all state fields (not struct padding) and
check output-token preservation. Overflow tests seed the boundary directly;
they do not try to force wrap by running an unbounded workload.

Recorded on x86-64 WSL2 with GCC 13.3.0: **20 ordinary, 20 ASan and 20 UBSan
tests passed**. Existing parser tests: **33 per configuration, 32 passed and the
original mixed-RDBF expected failure**, in each ordinary/ASan/UBSan run. The 128
geometry, C/Python parity, input-format, descriptor, preparation, coverage and
model-lifetime regressions passed. These results do not validate kernel concurrency
or actual resource cleanup. Both C translation units also compiled with GCC
`-fanalyzer` without diagnostics; Flake8, strict mypy, Pylint (10.00/10) and
whitespace checks passed. Native ARM64 execution/compilation was unavailable
locally; no ARM64 compiler/kernel tree was found. The same host runner is portable
to native ARM64 Linux, but no CI changes or remote build were performed.

## File-bound transport feasibility (review only)

Linux documents `open`, `write`, `unlocked_ioctl` and `release` file operations,
and `private_data` for per-open state; `release` occurs at the last reference.
These support a bound attempt context, control operations, raw payload writes
and final-close abort. Shared descriptors still need coordinator serialization;
file operations supply no preparation lock. See the primary
[VFS documentation](https://docs.kernel.org/filesystems/vfs.html#struct-file-operations).
This is an API feasibility assessment, not target-kernel validation.

A small misc device is a plausible registration mechanism. Its default
`file->private_data` points to the miscdevice, so a custom open path would have
to install a separate attempt context; registration alone does not provide
per-attempt ownership. See
[Linux miscellaneous-device documentation](https://docs.kernel.org/driver-api/misc_devices.html).
No device, path or ioctl ABI is created here.

Repository integration is the substantial cost: current
[callbacks](../../rvzr/executor_km/main.c#L316) have no open-file attempt context;
[module setup](../../rvzr/executor_km/main.c#L708) creates sysfs files.
[Serializers](../../rvzr/tc_components/test_case_data.py#L182) open paths internally,
and [trace collection](../../rvzr/executor.py#L151) repeatedly opens `taskset cat`.
A device route needs a small Python sink/control adapter, bounded user-copy and
header handling, partial-write rules, descriptor lifetime/unload policy,
permissions, affinity at the executing call and consistent locking. If using
ioctls, fixed-width control records and compat handling need ABI review. Raw
RCBF/RDBF bytes need not change. None of these changes is implemented now.

An explicitly framed write protocol could stay closer to sysfs but needs an
attempt token, offset/length checks on **every** write and atomic begin conditions.
It adds a framing parser and producer adaptation while still requiring the same
reset/cleanup/locking work. Plain BEGIN plus untagged legacy writes remains
insufficient. Keep the file-bound option provisionally preferred for lifetime
binding; choose one transport after a bounded adapter review rather than build
both. Stop if this requires broad executor redesign.

## Smallest next task

Implement explicit **real parser reset helpers**, without live callback/protocol
integration. Move the TC function-local section cursor state into resettable
private state; reset receiving/cursor/section indices, object aliases and logical
counts, and reconcile capacities with actually owned buffers. Specify a valid
idle root so reset does not create null dereferences on the next header. Input
reset must also account for its backing buffers and high-water counters. Existing
free/init pairs are not sufficient reset APIs.

Extend the real-parser harness to interrupt each stream, explicitly reset, then
parse a fresh valid fixture, checking exact payload bytes/consumption under ASan
and UBSan. This proves reset behavior only. Keep the legacy raw-callback expected
failure until an integrated boundary actually prevents mixed-input readiness;
reset helper tests alone do not fix untagged delayed writes. Resource cleanup,
locking, result generations and actual execution admission remain later stages.
