# B3.5k / G3a: preparation-order timing feasibility, not cache-hit/miss ground truth

Standalone, ordinary-user AArch64 Linux and Apple Silicon macOS. This is not a
Revizor backend, HTrace encoder, speculative gadget, victim/secret experiment,
cache-flush/PMU facility, executable-code generator or amplification technique.
No G3 acceptance is implemented. Source/metadata verification does not attest
that a file came from physical hardware.

## Audit and reuse boundary

Read alongside [the observation design](../README.arm64-userspace-observation-design.md),
[B3.5c](../README.m3-timer-protocol.md) and [the Linux runbook](../README.m3-experiment-runbook.md).
The G1 runner, G2 C/Python/protocol, production Revizor and existing CI assertions
are unchanged. The new CI step compiles/disassembles and runs synthetic checks;
it **never runs this cache experiment**.

`../arm64_timer_calibration.c:38-51` supplies the conservative reference ordering:
DSB ISH before each timestamp, ISB / CNTVCT_EL0 read / ISB. `probe.S` implements
that order explicitly with exactly one eight-byte target LDR, followed by the
second timestamp and only then result stores. The empty reference substitutes
a register MOV for the LDR; it is overhead context, not an exact isolated-memory
latency subtraction. Separate CNTFRQ probing, trap containment and decimal-string
ticks follow G2 conventions. No alternate clock supplies sample values;
CLOCK_MONOTONIC/Python time are used solely for deadlines/provenance.

The separately audited `m3-macos-gates` package was not found in the repository,
thesis tree or attachment paths searched for this task, so its timer source and
PROTOCOL were **not independently inspected/reused**. The new macOS adapter uses
ordinary POSIX memory/process APIs (see Apple's archived [mmap](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/mmap.2.html)
and [resource-limit](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setrlimit.2.html)
documentation); actual macOS 26.1 SDK compilation/runtime compatibility remains
pending. No QoS is set, and no physical CPU identity/pinning is claimed on macOS.

User-supplied physical baseline: G1-macOS 4/4 accepted, G2-macOS 40/40 runs and
15360 samples accepted, CNTVCT readable, reported CNTFRQ 24 MHz. Median ticks for
1/8/32/128 G2 buffer loads were 1/1/1/2. Those results establish neither a true
single-load resolution nor cache discrimination. G3a uses a different static
single-load probe, so these numbers are context, never classification thresholds
or invented observations. Fedora Asahi runtime compatibility remains unverified.

## Fixed experiment and boundaries

`pilot.c` supervises separate frequency and measurement children; no fork occurs
inside trial windows. Target and preparation mappings are private, anonymous RW
owned pages, never executable or shared with another application. The result
mapping is anonymous and shared **only between this supervisor and its own child**
so completed measurements survive worker failures. It is not a victim/shared
probe mapping. The parent reads it only after worker termination and emits all
committed samples, followed by complete/error. Failed runs are retained and
excluded from statistical analysis; a signal between capture and progress commit
may leave an uncommitted trial unavailable, explicitly an incomplete session.
No retry or replacement is performed.

Every target/preparation word, bounded result storage, and the measuring function's
64-KiB stack-prefault area are touched in the child before the access check.
The assembly leaf requires no stack. This exercises first touch; it cannot prevent
later paging, interrupts or translation misses. The target has constant value
`0x1122334455667788`, a single page-aligned address, and width eight in every trial.
Preparation loads are explicit assembly, not optimizable C expressions. The probe
is the same `g3_probe` tail target in every non-overhead condition. X18, SP and
ABI-preserved registers are untouched by the assembly.

| Series / label | Actual preparation before the same probe |
| --- | --- |
| ordered / 0 | Sweep buffer, then load target (`target_last`). |
| ordered / 1 | Load target, then sweep buffer (`target_before_sweep`). |
| null / 0 and 1 | Both sweep buffer then load target. Labels randomized independently of the identical preparation. |
| repeat / 0 and 1 | Both repeat the identical target-last condition. A separate repeatability/control stream, not additional independent sessions. |
| overhead / 0 and 1 | No preparation or target access; same conservative empty timestamp wrapper with a register MOV. |

Both ordered conditions do exactly one untimed target load, the same ascending
buffer sweep and one timed target load; only order changes. In target-last,
the final target LDR is followed only by register movement/branch to the timestamp
wrapper. No print, allocation, mapping, syscall or file I/O occurs in any timed
window. Sample bookkeeping is before preparation or after capture; output is
after the entire worker terminates. Branch-path, preparation-order, result-store,
instruction-fetch, TLB, prefetch, allocation/address and scheduling effects remain
confounds. A sweep is **not** an established eviction; preparation labels are not
physical hit/miss truth. Stable VA is not a guarantee of a physical cache index.

Each block contains all eight series/label slots once, permuted with recorded
nonzero uint32 seed, xorshift32 (13,17,5), Fisher-Yates descending 7..1 and modulo
selection (`schedule.h`, independently matched to Python in tests). This is
deterministic balanced randomization, not a cryptographic RNG or independence
claim. All sequential order, zero deltas and outliers are preserved.

Defaults are 64 blocks (512 trials), **1 MiB preparation bytes and 128-byte stride**.
These are pilot parameters, not M3 line size, capacity, associativity or eviction
claims. Bounds: 1..1024 blocks; 16 KiB..8 MiB preparation, divisible by runtime
page size and stride; stride 8..4096 in multiples of eight; at most 33554432 total
untimed preparation loads. Owned data/results/stack are below 10 MiB. Each child
has a CPU limit at most five seconds; supervisor deadlines are two seconds for
frequency and ten for measurement. Launcher bounds the whole process group to
20 seconds, then TERM/KILL. OS blocking/supervisor termination are not hard
real-time guarantees. Incomplete artifacts remain failures.

## Native build and reviewed disassembly (both platforms)

Prerequisites: Python >=3.11, reviewed **clean committed** checkout, normal user,
an output directory outside the checkout. Missing tools or dirty source block
the run and leave diagnostics. Do not disable the clean/native/user guards.
No automatic installation, sudo, module loading, CPU governor/interrupt changes,
or protected memory access is used. Keep the source unchanged during all sessions.

Linux needs native GCC/binutils; macOS needs native **Apple clang** and `otool`
from its Command Line Tools. Commands from the repository root:

```bash
set -euo pipefail
test "$(id -u)" -ne 0
# Linux: uname -m must be aarch64. macOS: arm64, not a translated x86 process.
python3 tools/cacheObservation/manage.py build --output "$HOME/g3a-build-01"
```

Exact compilation done by the helper:

```bash
# Linux (manual compilation alone does not create the required provenance bundle):
gcc -std=c11 -O2 -Wall -Wextra -Werror -fno-lto \
  tools/cacheObservation/pilot.c tools/cacheObservation/probe.S \
  tools/cacheObservation/platform_linux.c -o /tmp/g3a-linux
objdump -d /tmp/g3a-linux > /tmp/g3a-linux.disassembly.txt
# Native Apple Silicon macOS, pending actual SDK verification:
clang -std=c11 -O2 -Wall -Wextra -Werror -fno-lto -arch arm64 \
  tools/cacheObservation/pilot.c tools/cacheObservation/probe.S \
  tools/cacheObservation/platform_macos.c -o /tmp/g3a-macos
otool -tvV /tmp/g3a-macos > /tmp/g3a-macos.disassembly.txt
```

`build.json` records compiler command/full version/`__VERSION__`, source file
copies and SHA-256 aggregate, commit, binary hash, environment and disassembly
hash. The helper automatically checks the complete 12-instruction probe bodies
and the complete 11-instruction `g3_trial` body. It checks the W5 order branches,
both placements of the untimed target load, zero-based sweep offset, buffer load,
X3 stride addition, X2 bound, unsigned loop back-edge, result-pointer movement
and resolved tail destination at the identical `g3_probe`. GNU `b.cc` is explicitly
accepted as the alias of unsigned `b.lo`. Extra instructions, duplicate symbols,
noncontiguous addresses and changed destinations are rejected. The loop is bounded
in combination with the unchanged C dimension/stride validation, not by assembly
inspection alone. Unknown rendering or instruction mismatch blocks capture. Read
the **full** disassembly before the first physical run. The checker is not a general
decoder or an independent security proof. Synthetic Mach-O rendering tests do
not establish that actual Apple `otool` renders identically; report any failure
and inspect it, never bypass the check. Cross-compilation below proves only ELF
software compatibility and is never used by the native capture helper.

## Capture independent sessions and preserve failures

Record actual machine/OS/SoC evidence, build review, power/background conditions,
and core-label evidence in a separate `$HOME/g3a-notes.txt` **before** capture. Use the same
reviewed preparation parameters and platform-specific cohort throughout. Linux
can add `--cpu ID` from its allowed mask; child affinity and start/end CPU checks
are enforced. Without it Linux is unbound. Mac `--cpu` is rejected; core identity
and migration remain unknown, and QoS is never treated as affinity. Do not pool
core types, operating systems, machines or configurations. The host label is an
operator declaration, not hardware attestation. Metadata/hashes cannot detect
transparent virtualization by themselves; verify actual native machine identity.

Example calibration cohort (three independent launches, not three pieces of one
process). Change `m3pro-macos-unknown` to the correct recorded host label on Linux;
add the same chosen Linux `--cpu ID` to **every** capture in that cohort:

```bash
set -euo pipefail
for seed in 11 12 13; do
  python3 tools/cacheObservation/manage.py capture --build "$HOME/g3a-build-01" \
    --output "$HOME/g3a-cal-$seed" --session "cal-$seed" --seed "$seed" \
    --host-label m3pro-macos-unknown --blocks 64 --prep-bytes 1048576 --stride 128
done
python3 tools/cacheObservation/analyze.py describe "$HOME"/g3a-cal-{11,12,13} \
  --output "$HOME/g3a-cal-describe.json"
python3 tools/cacheObservation/analyze.py fit "$HOME"/g3a-cal-{11,12,13} \
  --output "$HOME/g3a-frozen-model.json"
# Freeze a persistent digest BEFORE launching any held-out session.
python3 - <<'PYHASH'
from pathlib import Path
import hashlib
model = Path.home() / "g3a-frozen-model.json"
with model.with_suffix(".sha256").open("x") as out:
    out.write(hashlib.sha256(model.read_bytes()).hexdigest() + "  " + model.name + "\n")
PYHASH
```

Stop the shell sequence on the **first** command failure (`set -euo pipefail` in
Bash, or explicitly inspect every exit). Failed directories must never be reused.
Retain and hash the frozen model **before** collecting held-out sessions, e.g.
Python `hashlib.sha256(Path(...).read_bytes()).hexdigest()` (or `shasum -a 256` on
macOS / `sha256sum` on Linux). Archive calibration IDs and your analysis plan.
Then use fresh launches, seeds and directories; do not adjust parameters or the
threshold based on these data:

```bash
set -euo pipefail
for seed in 21 22 23; do
  python3 tools/cacheObservation/manage.py capture --build "$HOME/g3a-build-01" \
    --output "$HOME/g3a-held-$seed" --session "held-$seed" --seed "$seed" \
    --host-label m3pro-macos-unknown --blocks 64 --prep-bytes 1048576 --stride 128
done
python3 tools/cacheObservation/analyze.py evaluate --model "$HOME/g3a-frozen-model.json" \
  "$HOME"/g3a-held-{21,22,23} --output "$HOME/g3a-held-report.json"
```

Each capture directory contains `launch.json` (exact command, context, expected
metadata, return code, timeout, timestamps, raw hash), `build.json`, Git diagnostics,
`raw.jsonl`, `stderr.txt`, and either `validation.json` or `failure.json`. Partial
worker samples/errors are retained; an outer timeout may produce truncated raw
output, still a failed session. Do not rerun/relabel a failed experiment as a
replacement sample. Re-experiments need new IDs, a documented cause/change and
their own cohort. The binary's private target/buffer addresses are historical
diagnostics after unmapping, never handles for another process.

## Final evidence handoff (including failed or inconclusive experiments)

Do this after collection/analysis stops; never edit or delete session artifacts
while packaging. Keep each physical platform/cohort separate. The example follows
the directory names above and includes **every** `g3a-cal-*` / `g3a-held-*`
directory in HOME, including failed and partial runs. Record any differently named
attempts in the notes and add their paths explicitly to `sessions` below. Inventory
all launches against the notes before transfer; a filename pattern cannot prove
that an operator retained every attempt. Do not replace failures with new samples.

The handoff contains the native build directory (binary, full disassembly, compiler
output, command and source snapshots), a full tracked-source archive of its exact
committed revision, all raw sessions/diagnostics, platform evidence from build and
launch metadata, notes, calibration description, frozen model plus its previously
recorded SHA-256, and the complete held-out report. Missing analysis products are
recorded as unavailable, **not** reconstructed or claimed successful. This lets a
blocked experiment be handed off too. A missing/mismatched pre-held-out model
digest means frozen-calibration provenance is unestablished; packaging does not
repair it. Hashes establish byte integrity, not when data were produced or whether
the experiment was physically valid.

Run as the ordinary user, from the same repository (no measurement runs here):

```bash
set -euo pipefail
python3 - <<'PYPACK'
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import tarfile

home = Path.home()
bundle = home / "g3a-handoff-01"  # Fresh name; never overwrite a previous handoff.
bundle.mkdir(exist_ok=False)
build = home / "g3a-build-01"
shutil.copytree(build, bundle / "build")
shutil.copyfile(home / "g3a-notes.txt", bundle / "notes.txt")
built = json.loads((build / "build.json").read_text())
commit = built["commit"]
(bundle / "source-commit.txt").write_text(commit + "\n")
# Preserve packaging-time diagnostics; physical capture itself requires clean source.
for name, args in (
        ("git-status.txt", ["status", "--short", "--untracked-files=all"]),
        ("unstaged.patch", ["diff", "--binary"]),
        ("staged.patch", ["diff", "--cached", "--binary"]),
        ("commit.txt", ["show", "-s", "--format=fuller", commit])):
    (bundle / name).write_bytes(subprocess.check_output(["git", *args]))
with (bundle / "committed-source.tar").open("xb") as out:
    subprocess.run(["git", "archive", "--format=tar", commit], stdout=out, check=True)

sessions = sorted(path for pattern in ("g3a-cal-*", "g3a-held-*")
                  for path in home.glob(pattern) if path.is_dir())
# Add any differently named failed/partial attempts here before packaging.
(bundle / "sessions").mkdir()
for path in sessions:
    shutil.copytree(path, bundle / "sessions" / path.name)
products = ("g3a-cal-describe.json", "g3a-frozen-model.json",
            "g3a-frozen-model.sha256", "g3a-held-report.json")
missing = []
for name in products:
    if (home / name).is_file():
        shutil.copyfile(home / name, bundle / name)
    else:
        missing.append(name)
model = bundle / "g3a-frozen-model.json"
digest = bundle / "g3a-frozen-model.sha256"
frozen_hash_matches = (model.is_file() and digest.is_file()
                       and digest.read_text().strip() ==
                       hashlib.sha256(model.read_bytes()).hexdigest() + "  " + model.name)
(bundle / "inventory.json").write_text(json.dumps({
    "sessions": [path.name for path in sessions], "unavailable_products": missing,
    "frozen_model_hash_matches": frozen_hash_matches,
    "g3_accepted": False, "note": "Review inventory against ALL attempted launches"
}, indent=2) + "\n")

# Hash every regular file except the manifest itself; reject symlinks.
entries = []
for path in sorted(bundle.rglob("*")):
    if path.is_symlink():
        raise ValueError("Unexpected symlink in evidence bundle: " + str(path))
    if path.is_file():
        with path.open("rb") as source:
            checksum = hashlib.file_digest(source, "sha256").hexdigest()
        entries.append(checksum + "  " + path.relative_to(bundle).as_posix())
(bundle / "SHA256SUMS").write_text("\n".join(entries) + "\n")
archive = bundle.with_suffix(".tar.gz")
with tarfile.open(archive, "x:gz") as out:
    out.add(bundle, arcname=bundle.name)
with archive.open("rb") as source:
    checksum = hashlib.file_digest(source, "sha256").hexdigest()
with Path(str(archive) + ".sha256").open("x") as out:
    out.write(checksum + "  " + archive.name + "\n")
print("Transfer:", archive, "and", str(archive) + ".sha256")
PYPACK
```

Retain the original directories locally. Transfer the **one archive and its digest
sidecar**, and communicate its SHA-256 through an independently checked channel
where possible. Verify the archive digest before extraction. After extraction,
verify `SHA256SUMS` (`shasum -a 256 -c SHA256SUMS` on macOS or
`sha256sum -c SHA256SUMS` on Linux), review `inventory.json`/notes/failures and
rerun offline validation/analysis against the frozen model. An integrity-valid
archive can still describe a failed or inconclusive experiment. No packaging
command launches the timer or substitutes missing physical measurements.

## Shared raw schema and offline rules

Version 1 / `g3a-order-v1`: exactly **one metadata**, `blocks*8` sample records
and **one complete** record for a successful run. Both platforms use identical
keys; strict field sets live in `protocol.validate`. Tick/count values that may
reach uint64 are canonical **decimal strings** (start/end/delta/value/frequency);
bounded dimensions/indices are JSON integers, never booleans/floats. Unknown keys,
duplicate JSON keys, NaN/Infinity, noncanonical or overflowing uint64, extra/missing
records, altered scheduling/labels/dimensions/provenance, counter reversals,
inconsistent differences, wrong target values and incomplete/error exits are
rejected. Zero differences are legal. Null frequency is explicit, separately
diagnosed, and never replaced by macOS's reported 24 MHz.

* Metadata: experiment/version/session/platform, source commit and hash, binary
  hash, compiler, OS kernel/machine/page size, dimensions/seed, eight-byte width,
  selected/start/end CPUs or null, frequency and probe status, owned addresses.
* Sample: kind/index/block/series/label/actual condition/status, raw start/end/delta
  and loaded value. Target value must equal the constant; overhead value is zero.
* Complete/error: status, committed sample count, stage, errno, worker exit/signal,
  timeout. Failed runs retain available samples and diagnostics but cannot enter
  statistical analysis. Initial failures may have only an error or no stdout;
  launcher failure/exit/stderr remain authoritative failure evidence.

Raw data/manifest reads are bounded to 4 MiB each; analysis accepts at most 32
sessions per split. A validated artifact says `physical_origin: not_attested` and
`g3_accepted: false`. Validation is consistency checking, not proof of physical
origin or independently known cache state. Source/binary provenance is cross-checked
against the separate build/launch artifact; it is not a producer-controlled
`physical=true` authorization flag.

## Analysis, uncertainty and evidence gates

Per session, series and randomized label: exact histogram, min/max, nearest-rank
p05/p50/p95/p99, zero count/fraction (exact numerator/denominator), and paired-block
label1-minus-label0 summaries. These include all outliers/zeros and remain
separate from empty-wrapper results. Never subtract minima and call it L1 latency.

`fit` uses **only calibration session medians**, weighting sessions equally. If
label medians coincide it fits no classifier and reports inconclusive. Otherwise
it fixes a tick threshold at their integer midpoint and orientation from their
ordering. This is data-derived **preparation-label** classification, not an
invented cache threshold. The fit artifact includes calibration IDs/raw hashes;
evaluation rejects overlaps and different host/platform/binary/kernel/page/CPU/
frequency/preparation cohorts. Evaluation reports all per-session 2x2 confusion
matrices, label0-as-label1/label1-as-label0 counts and balanced accuracies for
ordered, null, repeat and overhead controls, using the unchanged frozen threshold.
These are not false-L1-hit/miss rates without independent cache-state truth.

With fewer than three held-out sessions uncertainty is unavailable/outcome
inconclusive. Otherwise a deterministic 2000-replicate percentile bootstrap uses
**sessions**, never individual correlated loads, and reports descriptive 95%
intervals for session-mean balanced accuracy. Three sessions are a minimal pilot,
not a reliable calibrated significance test; independent launches also do not
guarantee independent thermal/system history. No p-value or automatic acceptance
threshold is inferred. Strong null/repeat separation, drift, platform/core mixing,
quantization overlap, scheduling or TLB/preparation-order signals require diagnosis.
Identical-condition controls must be examined before attributing an ordered
difference to cache effects.

Protocol failure = reject the session and preserve artifacts. Missing native
access/SDK/core evidence = blocked or limited scope. Coincident distributions,
coarse resolution, ambiguous controls or insufficient independent evidence =
inconclusive. Even apparent held-out separation is only **exploratory G3a**.
Before eventual G3 acceptance, separately specify/review/freeze a performance and
false-alarm/error criterion for Revizor's intended number of relational
comparisons, including independent calibration and held-out null controls.
This implementation cannot declare G3 accepted, leakage, or M3 H-trace equivalence.

## Software validation before the Mac is available

```bash
python3 -m unittest tests.unit_cache_observation -v
# x86-64: install/select ARM64 GNU binutils; do not execute the cross-built binary.
RVZR_ARM64_BINUTILS_PREFIX=aarch64-linux-gnu- python3 -m unittest tests.unit_cache_observation -v
aarch64-linux-gnu-gcc -std=c11 -O2 -Wall -Wextra -Werror -fanalyzer \
  tools/cacheObservation/pilot.c tools/cacheObservation/platform_linux.c \
  tools/cacheObservation/probe.S -o /tmp/g3a-cross
```

Tests use explicitly synthetic files for protocol/analysis, real host C integer
schedule code, and assembled/disassembled ARM64 instructions without running the
probe. The macOS rendering fixture is not a native build. No synthetic counter
exists in production C/assembly, and no x86 run is reported as physical success.
Linux compilation/CI cannot establish Apple clang/Mach-O compatibility or physical
M3 results. Both native macOS build/disassembly review and new G3a measurements
remain pending; Fedora Asahi remains unverified. Keep physical platform decisions
separate, even when all software tests pass.
