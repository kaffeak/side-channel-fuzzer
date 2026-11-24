# M1-G3-P0 Phase 3 — independent single-session supervisor

**Implementation and synthetic software validation only. No native P0 execution,
emulation or physical M1 measurements. Independent deployment review and explicit
execution approval remain required.** Phase 1's [protocol/schema](README.m1-g3-p0.md)
and Phase 2's [worker](README.m1-g3-p0-worker.md) are unchanged. G1/G2 and earlier
physical evidence are untouched. This is not a cache observer or Revizor backend.

## Modes and execution boundary

`m1_g3_p0_supervisor.py` has three separate modes:

* `self-test`: builds only `worker.c` plus `tests/m1_g3_p0/host.c`, runs that synthetic
  backend once, and checks its output using the existing validator. No `probe.S` or
  native identity backend is linked. Synthetic packets cannot enable the native worker.
* `preflight`: saves plans, source diagnostics, build/approval verification, OS/device/
  MIDR identity and before/after environmental snapshots. **Never executes the worker.**
* `execute`: explicit `--approve-native-single-session` required, one external physical
  plan, one direct worker child. No calibration campaign, held-out auto-start, warmup,
  retry, alternate CPU or replacement launch. `RVZR_SOFTWARE_TEST_ONLY=1` denies native
  execution even with that flag. Tests always set this variable and never run a native
  positive path; the orchestration boundary is explicitly mocked where necessary.

Requires Python 3.11+, Linux with pidfds, `resource.prlimit()` and `/proc/self/fd`,
Git and ordinary-user
permission to create the fixed output directory. Self-test additionally requires a host
C compiler. No root, modules, PMU, timer measurements, settings changes or privileged
instructions are requested. Normal per-child limits/affinity affect only the child.

The prospective native gate requires AArch64 little-endian Linux, Fedora Asahi Remix
45 (`ID=fedora-asahi-remix`, `ID_LIKE` includes `fedora`), 16384-byte runtime pages,
DT `apple,t8103`, matching running kernel release and the protocol's CPU0/CPU4 MIDRs.
Selected CPU must be allowed; the other core is identified but need not be allowed for
this separate session. Preflight checks pidfd availability without creating a worker.
Actual singleton affinity is set and read back by the parent while the worker is held
before plan decoding, and independently rechecked
by the unchanged C worker. Endpoint checks do not prove uninterrupted core residency.

## Provenance and approved executable

The launch plan is independently supplied in the exact Phase 1 schema, not inferred
from worker output. Source commit must equal the current clean committed checkout and
the build's commit. Status and both staged/unstaged binary patches are saved **before**
dirty-tree rejection. Required worker, validator, supervisor, collector, documentation
and test sources are compared directly with HEAD and snapshotted. Untracked files block
physical execution; preserve/review/commit or relocate them deliberately, never delete
`Zone.Identifier` or documentation blindly.

The existing Phase 2 development build records `dirty_checkout=true` and is deliberately
**ineligible**. After code review and an independently authorized commit, produce a new
clean build through the unchanged passive builder; independently review that exact
binary and disassembly. Do not edit an old build manifest to make it eligible.

Supply a separate reviewer-approved artifact identity JSON (`--approval`). Its exact
keys are `schema_version=1`, `protocol="m1-g3-p0-exclusive-v1"`, `source_commit`,
`source_sha256`, `binary_sha256`, `disassembly_sha256`, `build_manifest_sha256`.
These values must equal the independently planned build. This is a supplementary
review artifact, **not** a change to the worker/plan schema. Canonical JSON bytes mean
sorted keys, compact separators, ASCII escaping, no floats/NaN, one final LF.

The supervisor independently checks the complete build checksum inventory, canonical
source manifest and every snapshot, exact binary/disassembly/build hashes, clean build
record, command arrays, strict compiler flags, command success records, tool versions,
and re-runs the passive complete-function ELF/disassembly verifier. It checks the saved
assembly verification report against recomputation. Compiler warnings are preserved,
never hidden. It does not rebuild or run a binary during verification.

Verified artifacts are copied into the new session, checked again, then the saved worker
is opened read-only, hashed again through that descriptor and compared to the plan,
then executed via that held `/proc/self/fd` descriptor. This prevents
path replacement from selecting a different inode. Binary hashes are checked again after
execution. Read-only snapshot modes deter accidents; they do not defend against a
hostile same-UID writer, root, a compromised toolchain, Python runtime or OS. Approval
JSON is an explicit local trust anchor, not a cryptographic reviewer signature.

The launch plan, original plan bytes, deterministic schedule and encoded input packet
are preserved independently. The encoder validates the existing plan; the runner checks
packet equality before spawning. Worker-reported provenance is never its own trust anchor.

## Supervision and failure rules

One single-threaded Python supervisor launches one direct worker with a fresh process
session; its actual PID equals `metadata.worker_pid`. No GNU timeout/taskset wrapper
interposes another PID. Stdin is the bounded saved packet; stdout/stderr go directly to
regular files. No output parsing, polling collector, telemetry process or file reads
occur while the worker is awaited. A blocking pidfd readiness wait observes exit only.
An initially empty input pipe keeps the C worker in plan decoding until the supervisor
has saved the actual PID and command. Only then is the bounded packet written and EOF
published; no exclusive trial can precede that release. Single-threaded operation is
checked, and no Python `preexec_fn` runs in the child.
Default SIGCHLD handling is required so another reaper cannot release the owned PID
before parent configuration. Nondefault Python SIGCHLD handling is rejected.

Startup signal handling stays active throughout construction, PID acquisition, parent
configuration and release. `OwnedProcess` registers the Popen object before calling its
base constructor, so an interrupted constructor's visible PID can still be recovered and
reaped. If a startup operation is interrupted before a PID becomes observable, the
supervisor cannot exclude a partially created child: it records `STARTUP_UNKNOWN`,
leaves ownership unresolved, and blocks subsequent sessions. It never guesses a PID,
assumes no child exists merely because Popen did not return, or retries startup.

The parent applies CPU, output-file and core-dump ceilings with `prlimit(child_pid, ...)`
and reads them back. Native child affinity is set with `sched_setaffinity(child_pid, ...)`
and checked with `sched_getaffinity(child_pid)`. All configuration must succeed before
the packet is released. No child is reaped and then used for PID-based configuration;
an exit detected before release ends initialization. Initial libc/C startup can run
before these parent operations, but the reviewed C worker cannot begin trials without
the complete packet and EOF. Its own early CPU/core limits and alarm remain unchanged.

Child CPU limit is at most 2 seconds, output file limit 1 MiB per stream and core dumps
disabled; tighter inherited limits remain tighter. The worker retains its own limits.
Supervisor deadline: 10 seconds. Cleanup sends TERM and waits at most 2 seconds, then
KILL and waits at most 2 seconds. A separate parent SIGALRM deadline of 20 seconds spans
spawn/wait/cleanup, independent of the pidfd wait and the worker's own alarm. A pidfd
acquisition failure uses bounded cleanup only. No retries or extra worker executions.
If the child has not yet established its new process group, cleanup falls back to the
same signal on its known, unreaped PID and records that fallback; no PID is guessed.
Before signalling during recovery, a non-reaping `waitid(..., WNOWAIT)` check confirms
that the PID is still waitable by this parent. If interrupted failure/reaping left a
stale PID, ownership remains unknown instead of risking a signal to a reused PID.

Signals INT/TERM/HUP and outer-deadline expiry are recorded. Cleanup and sealing defer
further signal exceptions only during cleanup/preservation, never during startup. Every
parent signal is retained, and watchdog expiry stays latched even if another signal
arrives during cleanup. Actual signed return
code, terminating signal, PID and monotonic elapsed time are saved using the unchanged
execution schema; richer timing/error/ownership details are separate. Cleanup signal
requests, send errors and reaping outcomes are recorded individually in `supervision.json`.
`initialized.json` records verified settings before release; `supervision.json` records
startup/release state, including a null `packet_released` if a signal interrupts the
write's outcome recording. A signal racing a completed packet write can coincide with
trials already beginning; that run is interrupted/unsuccessful, never silently accepted.
No elapsed time is clamped or fabricated. A kernel stall can exceed a userspace deadline;
an overrun is retained as failed evidence even outside the validator's normal bounds.

An exclusive advisory supervisor lock prevents cooperating overlapping sessions. Permanent
session-ID and cohort/core/phase/seed claims prevent silent replacement. Launch-order
admission checks successful, sealed predecessors in the frozen order:
calibration `(4,101), (0,101), (0,102), (4,102)`, then held-out `(4,201), (0,201),
(0,202), (4,202)`. Missing/failed/incompatible predecessors block; none is automatically
started. This is inventory/order verification, not statistical pooling across cores.
Before spawning, an active-ownership marker is created outside the evidence tree.
It is moved to ownership history only after known reaping or a failure known to precede
any spawn attempt.
Unknown termination leaves
the marker in place, blocks subsequent sessions, skips the after-snapshot and **does not
seal an archive while a possible writer remains alive**. Manual investigation is needed;
there is no automatic clear/resume command. Locking is not protection against unrelated
programs or hostile users. SIGKILL, power loss and uninterruptible kernel waits cannot
be made transactionally safe by Python; retained markers conservatively block reuse.

## Environmental evidence and artifacts

The reviewed `experimental_environment.snapshot()` runs synchronously only before and
after measurement, never as a concurrent worker. Its cooperative two-second budget,
OS_REPORTED/DERIVED/UNAVAILABLE meanings and optional-interface limitations are retained.
Snapshot UTC/monotonic duration records are separate from worker timing. Blocking sysfs
I/O is not a hard real-time guarantee. Missing optional telemetry is recorded, not turned
into invented temperatures or cache truth. Essential target identity failures block.

Native output location is fixed (no CLI override):

```text
/home/safelab/MasterThesis/output/G3/M1-G3-P0/
  .supervisor.lock, .active-worker.json             # ownership/admission control
  .claims/, .ownership-history/
  <run_id>/                                       # execute; mkdir must succeed once
    evidence/
      plan/launch.json, launch.original.json, schedule.json, input.bin
      plan/frozen-calibration-manifest.json        # held-out only
      software/build/                             # complete exact build copy
      software/supervisor/, prepared/, after/      # Git diagnostics/source snapshots
      software/approval.json
      metadata/identity-before.json, operator-before.json, operator-after.json
      metadata/environment-{before,after}.json, *-timing.json
      raw/input.bin, stdout.jsonl, stderr.txt, execution.json, supervision.json
      raw/execution-started.json, spawn.json       # retained if parent is interrupted
      raw/initialized.json                        # verified policy, before packet release
      analysis/validation.json                    # or failure.json
      session.json, SHA256SUMS
    evidence.tar.gz, evidence.tar.gz.sha256
    receipt.json, receipt.json.sha256
    seal-failure.json                             # failure only, outside sealed set
  preflight-<run_id>/                              # separate, non-measurement container
```

Run IDs are not automatically regenerated. Existing containers/claims cause rejection.
Malformed plans rejected before an identity can be trusted produce CLI failure rather
than a fictitious measurement session. Preserve the invoking terminal log as well.

Operator `--note` is timestamped pre-session text. Post-session observation is explicitly
UNAVAILABLE unless separately supplied later as a hashed addendum; the supervisor does
not pretend a prewritten note describes later events. No prompt/collector runs during
trials. Do not edit sealed notes to add observations.

All success/failure session files are sealed when no child can still write. The manifest
excludes itself; the archive is outside evidence, verified member-by-member without
extracting, then separately hashed. Receipt/checksum and seal-failure diagnostics are
outside the sealed set. Original failures and partial archives are never deleted or
overwritten. Evidence is bounded to 256 files, 24 MiB total and 8 MiB per artifact;
raw streams retain the stricter 1 MiB limit. Interrupted, malformed, incomplete, nonzero
or unknown-status output cannot become validated evidence.

## Frozen calibration admission

There is no freeze/campaign launcher. A reviewer creates and independently hashes a
canonical frozen-manifest JSON after inspecting the two completed calibration sessions
for **one core only**, and before the first held-out launch. Its exact supplementary
fields are:

* `schema_version=1`, `protocol`, `phase="calibration"`, `cpu`, `cohort_id`, `target_id`,
  `kernel_release`,
  `blocks`, `provenance` (the five approval identity fields excluding schema/protocol).
* `supervisor_sources_sha256`, `approval_sha256`, `frozen_utc` (timezone-aware UTC),
  `decision="REVIEWED_PROCEED"` — an explicit review record, not automatic G3 acceptance.
* `calibration`: two objects `{run_id, evidence_manifest_sha256, receipt_sha256,
  archive_sha256}`, referencing existing containers under the fixed root.
* `held_out`: two prospective objects `{run_id, session_id, seed}`, seeds 201/202.
  The enclosing core/geometry/provenance fields bind both; omitting the freeze digest
  here avoids a self-hash cycle.

The supervisor verifies the external freeze digest against the held-out plan, canonical
bytes, cohort/core/target/software/approval identity, receipt and archive hashes, complete
calibration raw output, existing cohort validator, two distinct calibration seeds and
session/run IDs, observed architectural controls, and `calibration end < freeze < launch`.
Held-out identity must appear prospectively. No core/phase pooling. Clock chronology
is consistency of recorded OS timestamps, not an independent secure timestamp service.
No rate/error threshold or cache hit/miss labels are introduced. A failed/inconclusive
calibration cannot automatically authorize continuation.

## Review-only commands

Desktop software-only validation:

```bash
RVZR_SOFTWARE_TEST_ONLY=1 PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest \
  tests.unit_m1_g3_p0_supervisor tests.unit_m1_g3_p0_worker tests.unit_m1_g3_p0 \
  tests.unit_hwmon_investigation tests.unit_experimental_environment \
  tests.unit_m1_g2_launcher tests.unit_arm64_timer_calibration -v
python3 -B tools/m1_g3_p0_supervisor.py self-test --output /tmp/p0-new-synthetic-review
```

**Later independent M1 preflight only — not executed during implementation:** after
deployment approval, clean committed source, a new clean approved build and a saved
external physical plan/approval, an ordinary user may run:

```bash
python3 -B tools/m1_g3_p0_supervisor.py preflight \
  --plan /saved/plans/m1-cpu0-calibration-101.json \
  --build /saved/approved-clean-build/evidence \
  --approval /saved/reviewed-artifact-approval.json \
  --note 'Non-measurement preflight; physical P0 execution not authorized'
```

Repeat explicitly for CPU4 only with its separately saved plan if approved. Preflight
never proves exclusive-monitor behavior. No physical execution command is prescribed
here; review this implementation and its tests first. G3 remains unaccepted.

Startup regressions are software-only: accelerated watchdogs interrupt simulated stalled
constructors, including after a real synthetic child is created; synchronized fixtures
exercise TERM/KILL escalation, configuration failures, early exit and release ordering.
Elapsed recovery bounds are asserted, not just timeout flags. Unknown-PID tests cannot
reproduce every kernel process-creation window; they deliberately preserve uncertainty.
Userspace signal handlers cannot promise hard real-time interruption of arbitrary kernel
stalls. The 20-second signal watchdog is not a separate process immune to parent SIGKILL.
