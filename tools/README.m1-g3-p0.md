# M1-G3-P0 — exclusive-reservation feasibility, protocol v1

**Software preparation only. No exclusive-instruction implementation, native launcher,
hardware result, cache observer or Revizor integration is supplied.** The proposed native
step requires separate source/disassembly review before deployment. Target: original
M1/T8103, Fedora Asahi Remix 45, AArch64 little-endian, 16 KiB kernel pages. CPU 0/MIDR
`0x00000000611f0221` is Icestorm; CPU 4/`0x00000000611f0231` is Firestorm, based on the
supplied target evidence. Their results remain separate.

G1/G2 and environmental preflight acceptance are user-supplied context. G2's 24 MHz
counter/work sensitivity does not establish cache discrimination. P0 does not read
CNTVCT, CNTFRQ or PMU registers. Supervisor wall time is a resource check, not the
observation. Earlier M3 G3a/G3b work is preserved and supplies no M1 cache ground truth.

## 1. Source review and research boundary

Local source review: commit `139637303a90b1fa916a0d6ef75b798924eff845`.

| Existing source/interface | Reuse decision |
| --- | --- |
| [G2 target()](rvzr_m1_g2.sh#L140) | Reuse the identity method: actual OS/device-tree/MIDR, allowed CPUs, runtime page size. No importing/executing the launcher. |
| [G2 logged()/run_trial()](rvzr_m1_g2.sh#L247), [provenance()/seal()](rvzr_m1_g2.sh#L83) | Reuse preservation principles: actual child status, bounded cleanup, partial streams, clean committed source, snapshots, verified manifests, archive and separate receipt. A P0 launcher/packager is **not** implemented here. |
| [Timer calibrate()/run_worker()](arm64_timer_calibration.c#L62) | Owned initialized memory, prefaulted results, isolated worker and post-worker output are useful patterns. Its counter windows, frequency probe, loops, schedule and validator remain unchanged and are not P0 observations. |
| [G1 region_open()/execute_fixed()](arm64_architectural_smoke.c#L116) | Reuse ownership, cleanup and guard concepts. Do not reuse the fixed-program ABI or executable mappings/publication: P0 needs only statically compiled code and writable data. |
| [G1 validate_output()](verify_arm64_architectural_output.py#L57), [G2 validate_output()](verify_arm64_timer.py#L68) | Strict saved-artifact/independent-expectation checks are useful patterns, not compatible schemas. Neither accepts exclusive-status evidence. |
| [G3a protocol](cacheObservation/protocol.py#L114), [Linux affinity adapter](cacheObservation/platform_linux.c#L6) | Reuse recorded deterministic ordering and exact singleton-mask verification conceptually. Keep G3a files, hashing, data and analysis unchanged. |
| [Environment snapshot](experimental_environment.py), [evidence policy](README.m1-evidence.md) | Before/after only, with manual notes, optional-interface errors, source hashes. No concurrent metadata worker. No new sensor-to-core interpretation. |
| [Executor.load_test_case()/trace_test_case()](../rvzr/executor.py#L258), [HTrace](../rvzr/traces.py#L188) | Existing production path uses the kernel executor and existing trace formats. A reservation status is not that interface; no Executor subclass, synthetic HTrace or program admission is added. |
| [Historical G3b design §5](README.g3b-cache-observation-design.md#L144) | Proposed interference study is a later level. P0 deliberately omits its sweep and speculative amplification. |

**S2C evidence:** [Yu et al., §3.2–3.3](https://www.usenix.org/system/files/usenixsecurity23-yu-jiyong.pdf#page=5)
correlated exclusive-store failures with reload timing on M1, testing P/E cores using
QoS and a custom cycle-counter kernel extension. The full attack evaluation (§7) used
an M1 Mac Mini on Asahi Linux 6.1.0; multi-set monitoring required additional mapping,
eviction and race constructions. Those results motivate P0 but do not validate our
MacBook/kernel or provide present cache labels. The publication's ERG/cache geometry
must not be imported as a property of this target.

[The Gates of Time, §3/§5](https://www.usenix.org/system/files/usenixsecurity23-katzman.pdf)
uses transient cache-state gates and amplification followed by timing. Its principal
amplification evaluation used Intel hardware; some gates were also demonstrated on M1.
It is a different mechanism, not an explanation for a P0 status difference.

[Arm synchronization guide §3.1–3.2](https://documentation-service.arm.com/static/68c223238a337a2bc6645c0a)
describes load-exclusive monitoring, CLREX/exception-return clearing and ERG. These are
not promises that every isolated one-shot store-exclusive succeeds. The
[Arm A-profile usage restrictions](https://support.arm.com/documentation/ddi0487/mb/-Part-B-The-AArch64-Application-Level-Architecture/-Chapter-B2-The-AArch64-Application-Level-Memory-Model/-B2-12-Synchronization-and-semaphores/-B2-12-5-Load-Exclusive-and-Store-Exclusive-instruction-usage-restrictions)
permit monitor clearing without an application cause, subject to qualified forward
progress rules for suitable loops. P0 performs no retry loop and claims no such guarantee.

[Arm Instruction Set Reference, D3.130 STXR](https://documentation-service.arm.com/static/6245c734b059dc5ff9a8bdab)
specifies a 32-bit status: 0 means stored; 1 means no store. Matching address/width and
natural alignment matter. The [A64 CLREX definition](https://documentation-service.arm.com/static/69402f1f6efc1635355c6f24)
clears the local monitor. Invalid other status values are capture/implementation errors,
not additional hardware-observation categories. No instruction/register is accessed by
the Python module.

## 2. Proposed minimal native trial — not implemented

A future ordinary-user supervisor launches one fresh, single-thread worker per selected
core/session. No root, modules, altered governor/priority/security settings, PMU changes,
cache-maintenance instructions, huge pages, executable allocation, victim or shared
**target**. A private initialized/prefaulted normal R/W target page contains one fixed
8-byte-aligned target at page offset 8192. Adjacent canaries are at target−8/target+8.
Result storage is on separate pages; do not assume a cache/ERG relationship from that.

Public constants:

* Initial target A = `0x1122334455667788`, decimal `1234605616436508552`.
* Attempted store B = `0x8877665544332211`, decimal `9833440827789222417`.
* Canary values = `0x13579bdf2468ace0` / `0xfedcba9876543210`.

Changing A to B intentionally permits an independent architectural memory/status check.
This differs from an eventual same-value survival observer; the store and reset perturb
cache/coherence state. Do not transfer a P0 result to that later observer without review.

Outside each exclusive interval: clear any old reservation, reset A, verify canaries,
prepare B and pointers in distinct registers, apply the same reviewed reset-ordering
sequence, and obtain CPU-before. Every target/result/required stack page is initialized
and prefaulted before the first trial. No unrecorded exclusive-instruction warmups.

| Labels | Operational interval | Expected architectural result |
| --- | --- | --- |
| `adjacent_a`, `adjacent_b` | One 64-bit load-exclusive, immediately followed by one matching store-exclusive of B | Loaded A; status 0 => target B; status 1 => target A. Individual failures remain observations. |
| `clear_a`, `clear_b` | Same pair with one explicit CLREX between them | Status 1, target A. Any reported successful store is a stop condition. |
| `sham_a`, `sham_b` | Same pair with one NOP between them | Same permitted results as adjacent. This matches inserted instruction count, not duration. |

The duplicated labels are identical-operation null comparisons and interleaved repeats.
Each operation occurs twice per block; labels have no secret/data-dependent meaning.
Use separately reviewed static assembly entries, with dispatch before the interval and
status captured from a distinct W register. No overlap with address/data registers, no
calls, spills, result stores, syscalls, timers, allocation, logging or loop inside the
pair. No retry on status 1. Review full compiler output for all three entries.

After STXR, perform the same reviewed completion/readback sequence outside the interval,
then obtain memory-after, canaries and CPU-after and publish the complete result record.
A bounded shared **results** mapping can preserve a completed prefix after worker failure;
the supervisor waits rather than monitoring. Prefill statuses with an invalid sentinel,
publish a completed-record count last, and never serialize unexecuted/default-zero slots.
A signal halfway through a record leaves that slot incomplete, not a successful attempt.

Affinity is mandatory: establish selected CPU is allowed, set and re-read a singleton
mask, verify MIDR/device/OS identity outside collection, record endpoint CPUs per trial,
and verify final singleton mask/CPU. Endpoint checks cannot prove uninterrupted execution
or exclude temporary externally induced affinity changes. Leave IRQs enabled. An
unavailable core blocks its planned run; it does not justify substitution or pooling.

## 3. Ordering, resource bounds and freeze

`m1_g3_p0.schedule()` uses unsigned 32-bit xorshift (13 left, 17 right, 5 left), then
Fisher-Yates swaps index 5 down to 1 using state modulo index+1. Restart the generator
once per launch; consume its state continuously across blocks. It is reproducible,
not cryptographic. Small modulo bias is not a claim of perfectly uniform sampling.
Record the seed and complete schedule before collection.

* Default 32 balanced blocks = 192 single attempts per launch; hard cap 64 = 384.
* Two independent calibration launches/core, seeds 101/102; two held-out launches/core,
  seeds 201/202. Eight launches total; default 1536 attempts (hard maximum 3072).
* For each phase, seed 1 of that phase: CPU 4 then CPU 0; seed 2: CPU 0 then CPU 4.
  Here "seed 1" means 101 or 201, not the integer 1. Every core run is a separate worker.
* Owned experimental allocations/reservations ≤1 MiB, excluding ordinary executable/
  library RSS. Prefault 64 KiB required stack; target page 16 KiB. Result allocation is
  `round_up(128 + trials*128, 16384)` bytes: at most 64 KiB, including a 128-byte header.
  Future C must assert header/record capacity before use; count guard reservations too.
* Proposed worker CPU limit 2 seconds, supervisor wall timeout 10 seconds, kill/reap
  guard 2 seconds, independent outer watchdog 20 seconds. These are ceilings, not
  expected runtimes. They are not enforced by the passive Python validator.
* Raw stdout ≤1 MiB, lines ≤8192 bytes, ≤386 records. Saved plan/execution JSON ≤4096
  bytes each. No automatic retry, replacement, extra exploratory native loops or timer.

Freeze source, compiler/build/disassembly, public constants, protocol/schedule version,
blocks, planned identities/seeds, CPU cohorts, analysis and proposed exclusions after
calibration and **before** held-out collection. Archive a canonical manifest covering
those files, selected calibration evidence and the planned held-out launches; independently
hash it. Held-out plans require its digest. Changing it requires a prospective amendment,
new cohort identity and fresh held-out sessions, preserving the original attempt inventory.
The parser checks digest consistency, not the manifest's existence or chronology.

## 4. Strict saved-evidence schema

Executable schema: `tools/m1_g3_p0.py`. All objects have exactly the fields below; unknown,
missing or duplicate keys are rejected. UTF-8 JSON only; no floats/NaN/Infinity. Integers
exclude booleans; stated bounds apply. Unsigned words use canonical decimal strings
(no signs/leading zeros), checked through 2^64−1. Addresses use `0x` plus sixteen lowercase
hex digits. The validator compares an independently preserved plan/execution record to
raw worker output, never learns expectations from that output.

### Plan JSON, also echoed as metadata.plan

| Fields | Types and rules |
| --- | --- |
| `schema_version`, `protocol`, `schedule_version` | Integer 1; `m1-g3-p0-exclusive-v1`; `xorshift32-fy6-v1`. |
| `run_id`, `session_id`, `cohort_id`, `target_id` | Nonempty `[A-Za-z0-9_-]` tokens, ≤64 bytes. Run = unique attempt; session = planned launch; target = local asset label, not a serial number. |
| `evidence_kind`, `phase` | `synthetic`/`physical`; `calibration`/`held_out`. Producer labels do not attest origin. |
| `cpu`, `seed`, `blocks` | CPU 0/4; phase-appropriate seed from §3; blocks 1–64 (initial plan 32). |
| `kernel_release` | Nonempty printable UTF-8 ≤128 bytes, independently observed. |
| `source_commit` | Forty lowercase hexadecimal digits. |
| `source_sha256`, `binary_sha256`, `disassembly_sha256`, `build_manifest_sha256` | Sixty-four lowercase hex digits each. Source = hash of canonical source-file manifest; build manifest includes exact compiler, flags, commands and tool versions. |
| `frozen_calibration_sha256` | Null for calibration, required SHA-256 for held-out. |

Hash definitions are prospective and must match the archived files: `source_sha256`
is SHA-256 of a UTF-8, LF-terminated source manifest with sorted lines
`<file-sha256>  <relative-POSIX-path>\n` (no absolute paths, symlinks or duplicate names).
Binary and full-disassembly digests cover exact saved bytes. Build and frozen-calibration
manifests use UTF-8 JSON with sorted keys, compact separators, ASCII escaping, no NaN and
one final LF; their digests cover those exact bytes. Preserve the manifests, not just
hash strings. Reuse the frozen approved binary/build/disassembly for held-out launches;
a rebuild or changed parameters require review and a newly frozen cohort.

### Independent supervisor execution JSON

Exactly `returncode` (integer −127…255 or null for unknown), `timed_out` (Boolean),
`signal` (integer 0…127), `worker_pid` (positive integer ≤2^31−1, or null on spawn failure),
`wall_ns` (integer 0…20,000,000,000). Success eligibility requires returncode 0, false
timeout, signal 0, known PID and wall_ns ≤10,000,000,000. Unknown/nonzero/signal/timeout
records are preserved but rejected; no fake samples are generated to complete them.

### Raw JSONL

Exactly one metadata record, `6*blocks` sample records in scheduled order, and one
complete record, with a final newline. A failure may instead leave a prefix/error;
that remains unsuccessful evidence and must not be padded.

| Record | Exact fields and semantics |
| --- | --- |
| Metadata | `kind="metadata"`, `plan` (above), `architecture="aarch64"`, `system="Linux"`, `byte_order="little"`, `page_size=16384`, observed `kernel_release` matching plan, `os_id="fedora-asahi-remix"`, `os_version="45"`, `os_id_like` (unique list of 1–16 bounded strings containing `fedora`), `compatible` (same list rules, containing `apple,t8103`), `midr` (canonical CPU-specific value in introduction). |
| Metadata CPU/process | `allowed_cpus` (nonempty sorted unique integer CPU IDs 0–1023, containing selected CPU), `affinity_start=[cpu]`, `cpu_start=cpu`, `worker_pid` matching supervisor. |
| Metadata allocation | `target_page` and `results_base` (nonzero page-aligned addresses); `target_address=target_page+8192`; `results_bytes` as §3; `owned_bytes` integer between target+result+64 KiB stack minimum and 1 MiB. Half-open target/result ranges must not overlap or overflow uint64 arithmetic. Reported geometry is not ownership attestation. |
| Sample identity | `kind="sample"`, `index` (integer 0…trials−1), `block=index//6`, `condition` (scheduled label), `operation` (`adjacent`/`clear`/`sham`, matching label). |
| Sample observation | `stxr_status` (integer 0 or 1), `store_succeeded` (Boolean exactly status==0), `memory_before=A`, `loaded_value=A`, `attempted_value=B`, `memory_after` (B on success, A on failure). All memory values are uint64 decimal strings. |
| Sample controls | `canaries_before`, `canaries_after` (two-word decimal-string arrays matching constants); `cpu_before`, `cpu_after` (integer selected CPU), obtained outside interval. |
| Complete | `kind="complete"`, `status="ok"`, `samples_emitted=trials`, `cpu_end=cpu`, `affinity_end=[cpu]`, `worker_pid` matching supervisor, `canaries` (same two-word array). Counts/CPUs are integers. |
| Error, never accepted | `kind="error"`, `stage` (nonempty text ≤64 bytes), `message` (≤256 bytes), `errno` (integer 0…4095), `signal` (0…127), `samples_emitted` (completed prefix count). A trapping worker may emit no error record; supervisor diagnostics remain authoritative. |

`validate_output()` returns per-label success/failure counts and an architectural
assessment. If no adjacent success or no sham success was seen, it returns an explicit
INCONCLUSIVE assessment. Otherwise it reports CONTROLS_OBSERVED_REVIEW_REQUIRED; there
is **no rate-accuracy acceptance**. CLREX success, wrong memory/canary/CPU, malformed or
incomplete evidence raises `VerificationError`. `validate_cohort()` requires exactly two
unique launches/sessions/seeds for one phase/core, matching source/target/kernel/blocks/
frozen provenance; mixing calibration/held-out, cores or target identities is rejected.

Every successful validation explicitly returns `physical_execution_attested=false` and
`g3_accepted=false`, including for producer-labelled physical data. A read-only parser
cannot prove native execution, mapping ownership, an unchanged mask throughout an
interval, source/binary identity, truthful metadata or independently launched processes.
Those require the separately reviewed supervisor, preserved files and physical audit.

## 5. Evidence preservation and commands

Proposed new hierarchy (no directories or native runs are created by this phase):

```text
/home/safelab/MasterThesis/output/G3/M1-G3-P0/<unique-run-id>/
  evidence/
    raw/stdout.jsonl, stderr.txt, execution.json
    plan/launch.json, schedule.json, frozen-calibration-manifest.json
    software/sources/, binary, full-disassembly.txt, build.json, git-status-and-patches
    metadata/identity.json, environment-before.json, environment-after.json, operator-notes
    analysis/validation.json, session-counts.json
    SHA256SUMS
  evidence.tar.gz
  evidence.tar.gz.sha256
  receipt.json
  receipt.json.sha256
  seal-failure.json                 # if needed; separately hashed
```

Future supervisor: require clean committed source before physical execution, preserve
Git diagnostics before blocking, snapshot/hash source/build/binary/full disassembly and
all plans, record UTC launch/end times and actual exits/signals/timeouts, and preserve
failed/partial/unattempted inventory. Capture environmental snapshots synchronously
before/after the measurement loop only, after reaping workers. Manual observations are
timestamped and explicit about unknowns. Verify internal manifest/archive contents;
archive outside evidence, receipt outside the sealed set, and hash separately. No
cleanup of failed runs, no silently renamed replacement sessions, no edits to sealed
notes: use timestamped hashed addenda. Existing G1/G2 archives remain untouched.

Software-only commands, on desktop or ordinary AArch64 CI; no native execution:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest tests.unit_m1_g3_p0 -v
python3 -B tools/m1_g3_p0.py schedule --seed 101 --blocks 32
python3 -B tools/m1_g3_p0.py validate \
  --raw '/saved/evidence/raw/stdout.jsonl' \
  --execution '/saved/evidence/raw/execution.json' \
  --plan '/saved/evidence/plan/launch.json'
```

CLI validation reads bounded saved files only and prints a report; on failure it emits
NOT VALIDATED and exits nonzero, without modifying any inputs. No binary invocation,
real-evidence fixture generation, cohort launcher, archive writer or model training is
implemented. Future artifact packaging must not mistake these stdout reports for receipts.

## 6. Evaluation levels, stop rules and threats to validity

1. **Architectural capability:** correct loads/status/value/CLREX/canary checks, at
   least one adjacent and sham success, known per-core placement, complete preserved
   evidence. This witnesses basic capability, not reliable success rates.
2. **Operational reservation sensitivity:** requires a new prospectively frozen,
   balanced interference protocol with null/sham/duration controls and independent
   repeat sessions. P0 does not implement those conditions or establish this level.
3. **Cache-state discrimination:** requires orthogonal evidence independently validated
   on this platform, using separate freshly prepared trials because readout changes
   state. G2 is not that discriminator. Agreement between two reservation variants is
   not independent cache ground truth.
4. **Revizor HTrace suitability:** needs a validated observation-to-contract mapping,
   destructive-read/reset analysis, cost and relational false-alarm/error budgets.
   A scalar status has neither bitmap/set semantics nor an HTrace validity marker.

Stop and preserve on instruction traps, signal/timeout, unknown exit, allocation/affinity/
identity failure, malformed/incomplete output, canary/value mismatch, CLREX success or
provenance mismatch. Do not use a privileged workaround. No baseline/sham successes,
unstable null/repeat results, drift or cross-session disagreement are inconclusive;
do not extend loops automatically to obtain a desired result. Calibration may stop
held-out collection. An early stop preserves planned but unattempted launch identities.

Report exact per-label counts/fractions, chronological outcomes and per-session null
and sham differences. Trials in a block/session are correlated; two launches per
phase/core support only a small feasibility replication, not precise population error
bounds. Do not treat 1536 attempts as independent sessions or declare significance a
usable observer. Future numeric tolerances for baseline failure, null/repeat drift,
interference sensitivity, directional error and cost require prospective justification
and a frozen statistical plan before held-out cache evaluation. For later relational
fuzzing, derive a per-comparison error budget from campaign size and tolerated campaign
false alarms; no numerical accuracy target is invented here.

Alternative explanations include IRQ/exception return, scheduling/context switches,
monitor clearing policy, instruction/data faults, copy-on-write/translation/TLB effects,
compiler register overlap or inserted accesses, cache/coherence sharing with the OS,
fixed-address layout/history/prefetching, result/reset operations, and power/frequency
changes affecting interruption opportunity. Affinity does not prevent these. Before/
after telemetry cannot prove constant conditions. Both successful stores and resets
perturb the state; a status failure is not by itself evidence of cache eviction.

Later proposed owned-memory controls, **not implemented**: bounded register delay vs
matched sham; hot small-buffer vs larger-buffer loads inside the reservation interval;
and matched operation counts with order moved before the reservation. Keep the same
owned target and fixed addresses per run, never assume congruence or eviction, add
identical-operation labels, and independently review each new instruction sequence and
load budget. Do not introduce aliasing/mismatched-address exclusives, huge pages,
eviction sets, speculative gadgets, cross-process victims or secret extraction.

**Next minimum implementation:** separately review one static C/AArch64 assembly worker
for only the three P0 operations, with host-tested lifecycle/error capture and full
cross/native disassembly verification. First establish bounded ISA/status/memory capture
on the M1 per core; preserve all failures. No kernel executor changes, no observer
integration, and no claim of physical feasibility until actual artifacts are audited.
