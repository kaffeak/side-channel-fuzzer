# B3.5l / G3b: cache amplification and timerless observation design audit

Design only, reviewed against published sources on 2026-10-29. No new observer,
gadget, measurement, executor integration or G3 acceptance is implemented here.

**Recommendation:** first investigate a single-address, S2C-inspired exclusive-
reservation survival channel using private memory. It is a smaller unprivileged
capability experiment than a speculative amplification tree or replacement-policy
observer. It is **not a drop-in post-execution cache-state reader**. If it cannot
separate owned-memory interference from reservation lifetime/noise, stop that
route. The fallback is a separately reviewed, small Gates-style amplification
feasibility study, not a port of the complete SLAP/FLOP attacks.

## 1. Evidence boundary and preservation of G3a

Project-reported physical results, supplied for this task: G1/G2 passed on the
M3 Pro; G3a completed six native macOS sessions, 3072 observations, calibration
medians of one tick for both operational conditions, a null frozen classifier,
and an inconclusive held-out result. G3 remains unaccepted. These session files
were not supplied to this audit; this is not another independent artifact audit.
At the reported 24 MHz frequency, one counter period is approximately 41.67 ns
(arithmetic), not a demonstrated effective single-load resolution. Equal medians
neither prove identical full distributions nor prove that preparation failed.
Do not refit G3a, reinterpret its held-out set as new calibration, or overwrite
its source, outputs, model, report, hashes or archive.

Repository inspected: `7a34feef80b64d31937c2d0bc7e1117e90e74b0d`.
The inspected G3a package aggregate SHA-256, computed by its existing helper, is
`fa50efe4243b3c8269baa5e8475b77f8674c4dfb4d08bdfbf1637c1c541e3fbe`.
These identify this source review, not the physical runs' revision or binary.
This document is outside `tools/cacheObservation/`: its `manage.py:30-36` hashes
all source/document files in that directory, so even adding a design file there
would change G3a provenance. No local PDF/BibTeX thesis library was found in the
searched thesis tree; the primary publications and artifact documentation below
were consulted online. No third-party experiment/install scripts were executed.

Verified existing interfaces and limits:

| Repository source | What is established by source inspection |
| --- | --- |
| [G3a probe.S:12-25](cacheObservation/probe.S#L12), [:28-40](cacheObservation/probe.S#L28) | Single eight-byte LDR and empty reference; conservative DSB ISH / ISB / CNTVCT / ISB timestamps; results stored after the second timestamp. |
| [probe.S:43-57](cacheObservation/probe.S#L43) | Same sweep/target loads in opposite orders, then the identical probe. Repeating the target load alone would warm it; it would not replicate its original state. |
| [pilot.c:90-145](cacheObservation/pilot.c#L90) | Owned initialized/prefaulted memory, finite worker, buffered capture. Source does not establish eviction or L1 residency. |
| [analyze.py:74-87](cacheObservation/analyze.py#L74), [:102-170](cacheObservation/analyze.py#L102) | Calibration-only median threshold; equal centers produce no classifier. Session-level uncertainty and no G3 acceptance. A binary reservation-status observer needs a separate schema/analysis, not fake tick records. |
| [protocol.py:114-213](cacheObservation/protocol.py#L114) | Strict counts/order/provenance/arithmetic; failures excluded from analysis but preserved. Validation is not physical attestation. |
| [platform_linux.c:6-20](cacheObservation/platform_linux.c#L6), [platform_macos.c:4-9](cacheObservation/platform_macos.c#L4) | Linux self-affinity and endpoint CPUs; macOS rejects CPU selection and reports identity/migration unknown. No QoS-as-pinning claim. |
| [G3a protocol](cacheObservation/README.md), [G2 protocol](README.m3-timer-protocol.md), [observer design §2/§3](README.arm64-userspace-observation-design.md) | Reuse provenance, ownership, watchdog and capture-boundary principles. Existing G1 architectural capture itself perturbs memory; attaching an observer after bulk capture would observe that too. |

G3a's older prose says physical collection is pending; it is intentionally not
edited in this preservation task. The project-reported result above supersedes
that status for this design only.

## 2. What the publications actually measure

**Published** below means demonstrated on the cited setup. **Hypothesis** means
an untested inference for our M3 Pro/macOS 26.1 or future Fedora deployment.
SLAP/FLOP are data-speculation attacks, not names for general-purpose timerless
cache observers. Their cache receivers must be considered separately.

| Candidate | Physical mechanism and final observation | Published hardware / transfer limit |
| --- | --- | --- |
| Gates of Time, §3/§5 | Input latency changes when a transient window closes. Cache-state logic gates write derived states into other owned lines; fan-out/trees enlarge an eventual aggregate timing difference. Still timer-based at readout. Input evaluation is destructive. [Paper](https://www.usenix.org/system/files/usenixsecurity23-katzman.pdf#page=5). | Selected gates: Intel, AMD Ryzen 5 3500U, Apple M1 MacBook Air, Exynos 2100. The major amplification evaluation is Intel i5-8250U, not M3. [§3.7/§5.4](https://www.usenix.org/system/files/usenixsecurity23-katzman.pdf#page=7). |
| SLAP receiver, Appendix C | Adapts Gates' NOT-based amplification; it is distinct from SLAP's load-address-prediction encoder. Observe amplified elapsed time. [Appendix C](https://predictors.fail/files/SLAP.pdf#page=17). | The receiver table is **M2** native/WASM, not M3 Pro. LAP studies include M1/M2/M3 and A-series devices; predictor presence does not validate the receiver on every device. [Table 1 / Appendix C](https://predictors.fail/files/SLAP.pdf). |
| FLOP Safari receiver, Appendix C | Replacement-policy amplification adapted from leaky.page: a prior set access changes a maintained access pattern into repeated L1 misses rather than repeated hits. Observe aggregate elapsed time. [Appendix C](https://predictors.fail/files/FLOP.pdf#page=19), [original explanation](https://leaky.page/plru.html). | FLOP studies include M3 MacBook Pro A2918, M4 iPad and A17 Pro; its M3 test device is not our M3 Pro. No published association/replacement constants should be copied to our core types. [Table 1](https://predictors.fail/files/FLOP.pdf#page=4). |
| FLOP Chrome receiver, Appendix D | Separately uses Gates-style speculation-window amplification, not the Safari replacement-policy mechanism. [Appendix D](https://predictors.fail/files/FLOP.pdf#page=19). | Browser demonstrations do not attest a native receiver on macOS 26.1 or Linux. |
| S2C, §3/§5/§6 | On tested M1 hardware, eviction of a reserved line from L1 can make store-exclusive fail. Observe architectural success/failure, without timing. L2/multiple-set monitoring adds placement and out-of-order races; it is more than a bare exclusive pair. [Paper](https://www.cs.ucr.edu/~trentj/papers/usenix23.pdf#page=4). | Full evaluation: M1 Mac Mini, Asahi Linux 6.1; up to 11 L2 sets via a constructed OR channel, not 11 independently returned bits. macOS lacked their huge-page prerequisite for the full construction. M3 behavior is unestablished. [§7](https://www.cs.ucr.edu/~trentj/papers/usenix23.pdf#page=11). |

The original replacement-policy explanation assumes a tree-PLRU pattern and a
maintained competing entry; simply reading the target repeatedly is different.
Its published x86 example latencies are not M3 timings. [leaky.page](https://leaky.page/plru.html).

## 3. Privileges: mechanism versus published evaluation harness

| Candidate | Required by the observation idea | Published setup / restriction relevant to us |
| --- | --- | --- |
| Gates | Ordinary loads, transient behavior and a coarse timer; assumes usable initial output states. No inherent requirement for a privileged timer or direct flush. | Circuit evaluation used isolated cores/huge pages; artifact amplification used Ubuntu/Chromium and a performance governor. [Artifact appendix A.2](https://www.usenix.org/system/files/usenixsecurity23-appendix-katzman.pdf#page=2), [paper §4/§5.4](https://www.usenix.org/system/files/usenixsecurity23-katzman.pdf). Those environmental interventions are not authorized for G3b. An untouched/fresh address is not independently proven uncached. |
| SLAP | Its Appendix C amplification need not use LAP or access foreign memory. | Native reverse-engineering artifact requires a patched development kernel for cycles and a cache-flush kext on macOS 14.5/23F79. [Artifact README](https://github.com/slap-flop/slap-artifacts#readme). Patch instructions explicitly weaken boot security/SIP; they are **not** a G3b prerequisite or an approved procedure. [Patch documentation](https://github.com/slap-flop/slap-artifacts/tree/main/pacmanpatcher), [flush-kext documentation](https://github.com/slap-flop/slap-artifacts/tree/main/enable-dc-civac). Paper §4.3 also used controlled Asahi/M2 experiments. |
| FLOP | Receiver amplification can conceptually use ordinary memory accesses and a coarse clock. It does not require implementing LVP-based type confusion. | Precise characterization used macOS 14.5 KDK development kernel, affinity support, kernel patches/extensions exposing a core-cycle register and `dc civac`. Browser threat model used normal settings. These are different evidence layers. [§3/§4.1/Appendix A](https://predictors.fail/files/FLOP.pdf). |
| S2C | The local exclusive pair itself requires no timer, flush, kext, huge page or special entitlement. Whether its status tracks M3 eviction is empirical. | Artifact has a Linux PMC driver for characterization, says attack PoCs can omit it, and routes basic macOS experiments through a PMC kext. Full L2 setup needs huge pages/derived mapping. [Artifact README](https://raw.githubusercontent.com/FPSG-UIUC/S2C/master/README.md), [init_macos.sh](https://github.com/FPSG-UIUC/S2C/blob/master/init_macos.sh). Do not run its setup scripts as an unprivileged drop-in pilot. |

No candidate is justified by assuming the same OS protections in 2026 as the
papers' earlier builds. Special entitlements are not needed for the proposed
owned-memory, static non-JIT binary; this is a design requirement, not a claim
that the complete published browser/kext artifacts meet it. No SIP changes,
custom kernels, `dc civac`, PMU configuration, frequency/governor changes, kernel
modules or forced predictor/security-bit changes belong in the proposed pilot.
The authors' [current disclosure page](https://predictors.fail/) discusses
software mitigations; old predictor measurements cannot establish present behavior.

The FLOP Zenodo artifact is [version 1, 2025-01-17](https://zenodo.org/records/14680908).
Its 2.2-GB package was not downloaded/source-audited here. Claims above rely on
its paper and published metadata, not an asserted inspection of all its code.
Gates' artifact appendix pins revision
[`5bac7ece92f61025b7c1942c59b95e8a999ec231`](https://github.com/0xADE1A1DE/GoT/tree/5bac7ece92f61025b7c1942c59b95e8a999ec231).
Any future code reuse needs an exact revision, license review and bounded source
inspection; a link to a moving branch is not a reproducible implementation pin.

## 4. Portability, disturbance and cost

These are engineering implications/hypotheses unless a measured number is cited.

| Candidate | Shared macOS/Linux core? | Disturbance and expected collection cost |
| --- | --- | --- |
| Gates / SLAP NOT receiver | A static AArch64 gate and CNTVCT readout could be shared; speculation delays, initialization and scheduling require platform/core-specific calibration. x86 gates cannot be copied instruction-for-instruction. | Consumes input state and populates output/scratch lines. Fan-out compounds capacity pressure and errors. Published Gates hyper-tree differences exceed 100 ms on Intel, not a required minimum or M3 forecast. [§5.4](https://www.usenix.org/system/files/usenixsecurity23-katzman.pdf#page=11). |
| SLAP's measured receiver | Same portability hypothesis; no evidence of an unchanged macOS-26.1 or Linux port. | M2 native means: 5.12 versus 9.40 ms; WASM: 7.54 versus 11.87 ms. These are **means**, not our medians or expected M3 costs. [Appendix C Table 3](https://predictors.fail/files/SLAP.pdf#page=17). A full tree is an unattractive first per-probe collector. |
| FLOP replacement-policy receiver | Load loops can be shared; required congruence/replacement behavior cannot. MacOS/Linux allocation and page mappings differ. | Deliberately rewrites replacement state and sustains additional misses. Cost grows with repetitions and preparation. Without validated congruent lines and policy, it may measure only its own access pattern. Native M3 Pro cost unknown. |
| S2C local primitive | Static AArch64 exclusive instructions could be shared; runtime allocation, supervision, CPU evidence and ABI wrappers stay platform-specific. | Load-exclusive fetches the target and establishes a reservation. Store-exclusive consumes it and, on success, writes the same value, perturbing coherence even if bytes do not change. One live reservation per thread is not a snapshot of 64 sets. Cost is small in instruction count but interruption/noise and priming costs are unknown on M3. |

For all candidates, readout changes what later probes see. Re-reading one saved
state is not independent replication. Destructive multi-bit observations may
require separate reset/prepare/program runs or a validated copy mechanism.
For K independently reconstructed bits and R repetitions, budget at least
`K * R * (reset + preparation + execution + observation)` plus capture overhead;
measure every term. Do not equate a binary status with Revizor's current bitmap,
validity bit, trace bit order or contract-address semantics. No HTrace changes
are proposed. Full architectural capture must follow the future observation
boundary, not precede it; see the existing observer design cited in §1.

Independent checks to require before attributing each candidate's result to caches
(proposals, not completed validations):

| Candidate | Controls beyond observing two timing/status clusters |
| --- | --- |
| Gates / SLAP NOT receiver | Fixed public data; identical-preparation label-null; gate-disabled/untrained control; independently prepared output-touch/no-touch controls; calibration-only delay/fan-out study. Verify changed output behavior on fresh re-prepared trials, not by rereading the consumed input. Architectural output touches validate the capture path, not transient gate fidelity or a verified miss. |
| FLOP Safari replacement receiver | Establish candidate congruence and persistent replacement behavior independently; compare owned insertion/no-insertion with matched sham activity and null labels. Measure whether separation persists across bounded repetition counts without repeated re-encoding. Constant rereads merely getting faster do not demonstrate replacement amplification. |
| FLOP Chrome receiver | Same gate/output controls as Gates; independently establish the chosen native AArch64 variant rather than infer it from a browser demo. |
| S2C | Explicit-clear/sham and value checks first, then interval/footprint controls and a separate orthogonal cache observation. A status bit alone cannot distinguish eviction from other causes of monitor loss. |

All need allocation/TLB, prefetch, ordering, scheduler and core-type controls.
Without an independently validated cache-sensitive reference, describe evidence
as preparation-dependent timing or monitor status. Do not bootstrap cache truth
by using the new observer's own classifier to label its calibration data.

**macOS 26.1:** actual M3 Pro G2 access is evidence for that counter on that OS,
not for gates, replacement policy, reservation behavior, or a specific core.
QoS cannot establish pinning; unknown Everest/Sawtooth placement remains unknown.
Separate known core types; report an uncontrolled mixed-core cohort as such.
**Fedora Asahi:** independently establish kernel/page size, allowed affinity,
core identification, timer access and all observer behavior. Asahi's current
[M3 status](https://asahilinux.org/docs/platform/feature-support/m3/) lists PMU as
WIP; it is not needed by the proposed local primitive. Neither that page nor the
project's compile-only kernel builds attest this target's installed system.

## 5. Recommended first experiment: reservation survival, not eviction truth

This is a **proposed prerequisite pilot**, not an approved executable sequence
or a cache-state amplification claim. The source-backed starting point is S2C's
local primitive; its M3 relevance is a hypothesis. S2C's own validation correlated
exclusive status with independent reload timing (§3.2); our G3a did not establish
that independent discriminator. We therefore cannot inherit its eviction labels.
[Methodology](https://www.cs.ucr.edu/~trentj/papers/usenix23.pdf#page=4).

Arm documents the exclusive status and explicit monitor clearing, including
clearing on exception return: [A64 synchronization guide, §3.1–3.2](https://documentation-service.arm.com/static/68c223238a337a2bc6645c0a).
Intervening memory activity and long intervals do not give a portable guarantee
that a reservation survives. A failure can reflect interruption, translation,
monitor policy or elapsed activity, not just eviction. Do not use a retry-until-
success atomic loop: that would erase the observation. The proposed pilot makes
one attempt per trial and records the architectural result, including failures.

### Bounded protocol proposal

Use a new directory/package and experiment ID, e.g. `g3b-reservation-v1`, separate
from G3a's hash, executable, validator, results and archived model. One supervisor,
one disposable single-thread worker, ordinary user, native execution only. No
victim, shared target, privileged instructions, dynamic executable memory,
indirect gadget admission, secret value or deliberate misprediction.

Allocate a private, naturally aligned eight-byte target on its own page, a
private 1-MiB preparation buffer, a separate small hot-control buffer, prefaulted
stack and bounded result storage. Fully initialize/touch them in the worker.
Retain the initial 128-byte preparation step as an **experimental parameter**;
it is not a congruence/ERG/cache-line claim. M1 paper geometry is not M3 geometry.
All stored values are public constants; a successful conditional store writes
back its own loaded value. Verify final data/canaries outside the trial interval.

Define each trial in reviewed straight-line/finite-loop assembly. Hold reservation
and status in registers; no calls, logging, result stores or timer reads between
the exclusive pair. Capture only after the attempt. Any ordering instructions
must be fixed across comparable arms and separately reviewed for their effects
on reservation survival. The G3a DSB timestamp wrapper must **not** simply be
inserted into this interval. Keep optional ordinary counter timestamps outside
it, as perturbing duration context only. Inspect full Mach-O/ELF disassembly,
branches and finite bounds before collecting anything.

A balanced block has these six pairs (12 slots), randomized with a recorded seed:

| Pair | Two conditions / role |
| --- | --- |
| Primary | Same target exclusive load/store and same sweep. `reserve_last`: sweep precedes reservation; `reserve_before_sweep`: sweep occurs inside the reservation interval. Only order differs. Primary outcome: nonzero conditional-store status. |
| Label-null | Both use identical `reserve_last` preparation; randomized labels are unrelated to physical operations. |
| Identical repeat | Two more identical `reserve_last` operations, interleaved to assess drift/order. Not independent sessions. |
| Register-delay | Reservation followed by a register-only loop with the same iteration count versus adjacent-pair baseline. Controls interval activity; equal instruction counts do **not** establish equal duration. |
| Hot-buffer interference | Same load/loop count as the sweep but repeatedly visiting a small initialized owned range versus full-buffer traversal. Neither is a verified residency state; translation/footprint/prefetch effects remain. |
| Architectural clear | Explicit local-monitor clear versus matched sham between the pair. Tests status capture/clear semantics, **not** eviction. Normal adjacent attempts are not guaranteed to succeed on every interrupted trial. |

Proposed finite budget for review: 64 blocks/session (768 trials), four separate
calibration launches and eight held-out launches, at most 9216 planned trials.
Use seed IDs 101–104 and 201–208 respectively. Per-launch caps: 1024 trials,
33554432 preparation **load operations**, and 4 MiB owned allocation; keep the
preparation buffer at 1 MiB. Worker CPU cap 5 s, wall cap 10 s, outer
process-group cap 20 s. These are resource ceilings, not expected runtimes or
reliability targets. No automatic retries/replacements; a failed session stops
its cohort and preserves partial data and unattempted-session inventory.

### Physical provenance and raw observations

Capture clean committed source/snapshots, binary and full disassembly hashes,
compiler/SDK/build flags, actual SoC/model and OS build/kernel/page size, power/
background conditions, CPU policy/evidence, runtime addresses, all parameters,
seed, wall/session identity and chronological trial order. Mac CPU/migration
identity remains unknown when unavailable; Linux verifies allowed affinity and
endpoint CPUs but cannot rule out every interruption. Do not pool macOS/Linux
or known core types; seeds do not make sessions independent or certify identity.

A new strict schema should retain raw store status as an unsigned integer,
normalized `store_succeeded`, loaded/stored-value checks, actual preparation,
label, block/index, optional contextual counter start/end (decimal uint64 or
explicit unavailable), and complete/error/footer plus exit/timeout diagnostics.
Validate contradictions, duplication, bounds, counts and provenance. A legitimate
nonzero store status is an observation, not an execution error; a signal/timeout
is an invalid session with retained evidence. Never encode status as elapsed
cycles, cache hit/miss, or an HTrace. Reuse G3a's handoff principles in a separate
archive with an independently communicated SHA-256; preserve **all** attempts.

### Calibration, independent validation and decision criteria

Freeze assembly, dimensions, labels, allocation policy, classifiers, endpoints,
analysis code and planned exclusions after calibration, before held-out launches.
Calibration can veto a nonfunctional primitive; it cannot remove inconvenient
trials, flip the hypothesized direction after seeing held-out results or silently
retune parameters. An amendment requires a new experiment ID and fresh held-out
cohort. Do not reuse G3a data as G3b training/testing observations.

Primary per-session effect: failure fraction under `reserve_before_sweep` minus
failure fraction under `reserve_last`. Report exact counts/risk differences,
sequence plots and autocorrelation/drift; for the fixed prediction "failure means
before-sweep", give operational-label confusion matrices and both directional
error rates. These are not cache-state error rates. Weight sessions equally.

Proposed inferential plan, to freeze before collection: one directional primary
comparison, alpha 0.05 (an analysis choice, not a latency/performance threshold),
using session-level sign-flip enumeration for eight held-out paired session
effects. Its validity requires independent sessions and symmetric null effects;
if order/history controls undermine those assumptions, report descriptive results
and inconclusive inference. Never use 6144 correlated held-out trials as 6144
independent replications. Report session effects and session-resampled uncertainty
with the small-session limitation; any additional confirmatory comparisons need
a predeclared multiplicity correction. Failed/missing sessions do not qualify
for the planned complete-cohort test.

Non-significant null controls are **not equivalence evidence**. Before an
advance decision, separately review and freeze a tolerated null/drift effect and
operational-label error/cost bound; report intervals relative to those bounds.
No numeric tolerances are invented here. Without them, even apparent primary
separation can only be an exploratory preparation/reservation signal.

Independent validation proceeds in levels: architectural clear/sham plus data
checks; randomized identical-operation controls; hot-range/register-delay and
footprint/translation-matched follow-ups; finally an orthogonal cache observation
validated independently on this platform (or documented hardware evidence), on
separate re-prepared trials because both readers perturb state. Agreement between
two variants of the same reservation mechanism is not independent cache truth.
If orthogonal discrimination remains unavailable, keep the result named
"reservation survival under owned-memory interference" and do not declare G3.

| Outcome | Required interpretation |
| --- | --- |
| Unsupported instruction, signal, timeout, data/ABI corruption, incomplete output or provenance mismatch | Reject session, retain evidence; no privileged workaround or automatic replacement. |
| Clear control unexpectedly succeeds, or no baseline successes can be obtained | Status/monitor experiment invalid or non-discriminating; stop, inspect independently. |
| Every interfering condition fails similarly, controls separate, substantial drift, mixed/unknown placement explains effects, or sessions disagree | Inconclusive cache interpretation; investigate reservation lifetime/scheduling/translation, not "verified eviction". |
| Primary separation repeats with clean controls and frozen held-out analysis | Candidate reservation-sensitive observation only. Cache attribution, useful error/cost bounds and observer/program interaction remain separate gates. |

For eventual Revizor acceptance, specify campaign comparison count N and tolerated
campaign false-alarm probability B. A conservative per-comparison target is at
most B/N by the union bound, not an assumed IID repetition benefit. Measure both
repeatability and sensitivity to known allowed program differences, and a
per-HTrace budget. These requirements need a validated observation mapping and
relational error study; a significant primary p-value is insufficient.

## 6. Fallbacks and independently testable implementation sequence

1. **Next smallest coding task:** add a separate schema/host validator with
   synthetic raw exclusive-status fixtures, exact trial schedule and bounded
   supervisor lifecycle tests. Explicitly test no retries, clear/sham metadata,
   failed sessions, unknown CPU, split leakage and separate G3a identity. No
   physical-status claims and no native primitive are needed for that commit.
2. Separately implement/review only the adjacent-pair and explicit-clear owned-
   memory capability checks, full assembly verification and macOS/Linux adapters.
   Compile/disassemble on both platforms; do not add sweep/race logic until the
   primitive's architectural outcomes are trustworthy. No success-spin loop.
3. After review, add the bounded pairs in §5, preregister criteria and collect the
   fixed calibration/held-out plan on physical macOS. Linux is an independent
   cohort after native provenance/affinity validation, not a portability assertion.
4. If reservations do not offer useful evidence, first audit **one** Gates/SLAP
   gate, then consider a one-layer, small fixed fan-out study with owned input/
   output controls and untrained/disabled-gate comparisons. No tree/hyper-tree,
   LAP/LVP gadget, arbitrary code or secret read is justified by this audit.
   Initial output-state preparation must be independently investigated; an
   assumed cold output can make a perfectly timed gate test meaningless.
5. Defer FLOP-style replacement-policy amplification until congruent addresses,
   replacement-state persistence and a bounded reset protocol are established on
   each M3 core type. Raw sweep separation or 128-byte spacing does not supply
   those prerequisites. Repeated fresh prepare/probe totals may test aggregate
   workflow cost but do not amplify a single captured cache state.
6. Only after a physical observer passes a separately reviewed G3 criterion,
   design a post-program observation boundary and an explicit relation to C-traces.
   G1's fixed architectural validation and model contracts remain unchanged.

WSL2 can validate schemas, ordering, bounds, statistics on labeled synthetic
fixtures, failure preservation and cross-assembled instruction sequences. Generic
native ARM64 CI can compile/run capability software if separately authorized;
it cannot validate M3 cache/reservation behavior. Native Apple builds establish
Mach-O/ABI compatibility; only controlled physical M3 sessions can investigate
the proposed channel. No runtime validation follows from this design document.
