# B3.5c: module-free M3 Pro Linux timer feasibility protocol

Run only on native AArch64 Linux, as an ordinary user. This is timer calibration,
not a cache observer, generated-code executor, H-trace producer or Spectre test.
Do not load Revizor's module or change kernel configuration, PMU registers, CPU
governors, interrupt policy or page permissions. The only affinity changes below
affect the experiment's own processes. Do not run these commands under sudo.

## What the existing implementation establishes

| Source | Implemented behavior; remaining limit |
| --- | --- |
| [C:38–51](arm64_timer_calibration.c#L38) | `ISB; MRS CNTVCT_EL0; ISB`, compiler memory clobbers, and `DSB ISH` before each empty/buffer-window timestamp. No counter writes or PMU access. Barriers are part of overhead. |
| [C:54–104](arm64_timer_calibration.c#L54) | Adjacent reads, empty windows, then volatile loads/checksum arithmetic on an owned 512-byte buffer. Rejects backwards/nonadvancing runs and start/end CPU mismatch. Prior buffer accesses are not proof of L1 residency. |
| [C:109–139](arm64_timer_calibration.c#L109) | Separate frequency and measurement children; `CNTFRQ_EL0` is read independently. `waitpid` reports traps without resuming faulting instructions. Children disable core dumps. |
| [C:232–275](arm64_timer_calibration.c#L232) | Verifies a one-CPU affinity mask, obtains kernel/page metadata, prefaults result storage and runs the children. No privileged fallback. |
| [C:278–319](arm64_timer_calibration.c#L278) | Emits raw JSONL after worker success; an independent frequency failure/zero produces null frequency. Detects output-write errors. |
| [Verifier:68–188](verify_arm64_timer.py#L68) | Checks exit status, exact record counts/order, integer types, wide decimal strings, indices, deltas, monotonicity, checksums, summaries, CPU metadata and final completion. It does not establish timing accuracy. |
| [Verifier:191–212](verify_arm64_timer.py#L191) | CLI is deliberately fixed to 32 samples/series, two loads and a 15-second subprocess timeout. Its validator API supports other bounded dimensions, but still limits each captured stream to 128 KiB. |

The [28 existing host tests](../tests/unit_arm64_timer_calibration.py) cover
protocol rejection, arguments, affinity rejection, frequency/counter failures,
backwards/constant synthetic counters and output failures. Temporary C copies
replace only timer reads/barriers; their synthetic 24 MHz value is **not M3
evidence**. These tests never execute ARM instructions on x86-64.

The existing GitHub `Smoke test native ARM64 architectural timer` step compiles
and executes the real utility, checking 101 records. A passing result establishes
access/output consistency on that runner only. No M3 Linux counter frequency,
effective resolution, overhead, repeatability or cache discrimination is yet
established. This protocol leaves CI, C code and the verifier unchanged.

## 1. Record provenance and compile

Use a Bash terminal in the repository root. Required existing tools: native GCC,
Python 3, GNU coreutils (`timeout`, `sha256sum`, etc.) and util-linux (`taskset`,
`lscpu`). Python needs only its standard library, not a Revizor installation.
If a prerequisite is missing, report it; this protocol installs nothing.

```bash
set -euo pipefail
export LC_ALL=C
test "$(uname -m)" = aarch64
for timer_tool in gcc python3 timeout taskset lscpu sha256sum; do
    command -v "$timer_tool"
done
timer_results="$(mktemp -d "${TMPDIR:-/tmp}/rvzr-m3-timer.XXXXXX")"
printf 'Keep this results directory: %s\n' "$timer_results"
{
    date -u --iso-8601=seconds
    git rev-parse HEAD
    git status --short
    uname -a
    getconf PAGESIZE
    cat /etc/os-release
    lscpu
    lscpu -e=CPU,CORE,SOCKET,ONLINE
    taskset -pc $$
    cat /proc/cpuinfo
    gcc --version
    sha256sum tools/arm64_timer_calibration.c tools/verify_arm64_timer.py
    for timer_file in /proc/device-tree/model \
        /sys/devices/system/clocksource/clocksource0/current_clocksource; do
        printf '\n%s: ' "$timer_file"
        if [ -r "$timer_file" ]; then
            tr '\000' '\n' < "$timer_file"
        else
            printf 'unavailable without additional privileges\n'
        fi
    done
} > "$timer_results/environment.txt" 2>&1
gcc -std=c11 -O2 -Wall -Wextra -Werror tools/arm64_timer_calibration.c \
    -o "$timer_results/arm64-timer" > "$timer_results/build.log" 2>&1
sha256sum "$timer_results/arm64-timer" > "$timer_results/binary.sha256"
```

Read `environment.txt`: confirm the actual Mac/OS/kernel rather than assuming
the previously reported Fedora kernel is installed. Record dirty source changes
alongside the hashes, power source, background workload and session conditions.
The current Linux clocksource name is context, not proof that the utility uses
the kernel's accessors or receives their erratum workarounds.

## 2. Select and identify CPUs

Inspect the recorded allowed mask. Choose one allowed CPU; choose a second only
if useful for a separate core-type comparison. Do not assume low IDs are
Sawtooth or high IDs Everest. In the same terminal:

```bash
read -r -p 'One or two distinct allowed Linux CPU IDs, space separated: ' -a timer_cpus
test "${#timer_cpus[@]}" -ge 1
test "${#timer_cpus[@]}" -le 2
if [ "${#timer_cpus[@]}" -eq 2 ]; then test "${timer_cpus[0]}" != "${timer_cpus[1]}"; fi
python3 - "${timer_cpus[@]}" <<'PY'
import os
import sys
if not {int(cpu) for cpu in sys.argv[1:]}.issubset(os.sched_getaffinity(0)):
    raise SystemExit("Choose CPUs from the original allowed mask")
PY
for timer_cpu in "${timer_cpus[@]}"; do
    [[ "$timer_cpu" =~ ^[0-9]+$ ]]
    taskset -c "$timer_cpu" true
    {
        printf 'Linux CPU ID: %s\n' "$timer_cpu"
        for timer_file in \
            "/sys/devices/system/cpu/cpu$timer_cpu/regs/identification/midr_el1" \
            "/sys/devices/system/cpu/cpu$timer_cpu/cpu_capacity" \
            "/sys/devices/system/cpu/cpu$timer_cpu/cpufreq/scaling_governor" \
            /sys/devices/system/cpu/cpu"$timer_cpu"/cache/index*/{level,type,size,coherency_line_size,number_of_sets,ways_of_associativity,shared_cpu_list}; do
            printf '%s: ' "$timer_file"
            if [ -r "$timer_file" ]; then cat "$timer_file"; else printf 'unavailable\n'; fi
        done
    } > "$timer_results/cpu-$timer_cpu.identity.txt" 2>&1
done
```

Retain a manual `core-labels.txt` in the results directory: CPU ID, type
(`Sawtooth`, `Everest`, or `unknown`) and the evidence/source used to identify it.
MIDR plus a documented kernel/vendor mapping is stronger evidence than cache
capacity alone. Missing/zero cache fields do not establish geometry. Keep unknown
cores and both known types separate; never pool them under a guessed label.

The [Linux affinity interface](https://man7.org/linux/man-pages/man2/sched_setaffinity.2.html)
permits self-affinity and preserves masks across fork/exec. `taskset` below makes
the chosen CPU the utility's default allowed CPU, matching the verifier's existing
minimum-allowed-CPU rule. Each JSONL file therefore reports a one-CPU initial
mask; `environment.txt` preserves the original broader mask. The C utility
independently pins/verifies that CPU again. This is affinity, not CPU isolation:
other tasks and interrupts can still run there. Start/end checks cannot rule out
temporary external affinity changes or attribute delays to a particular sample.

## 3. Bounded repetitions with unmodified measurements

Use 128 samples per series, loads 1/8/32/128, five repetitions per selected CPU.
Rotate load order per repetition. These are pilot workload dimensions, not
latency acceptance thresholds. There are 20 runs/CPU, each with 389 records
(384 samples); at most 40 runs/15360 samples for two CPUs. Individual streams
fit the existing validator's limit. The three series within each run remain in
their original fixed order, so within-run drift is still a limitation.

```bash
timer_loads=(1 8 32 128)
for timer_rep in 1 2 3 4 5; do
    for timer_cpu in "${timer_cpus[@]}"; do
        for timer_slot in 0 1 2 3; do
            timer_load="${timer_loads[$(((timer_rep - 1 + timer_slot) % 4))]}"
            timer_stem="$timer_results/cpu-$timer_cpu-loads-$timer_load-rep-$timer_rep"
            date -u --iso-8601=seconds > "$timer_stem.started.txt"
            timer_command=(timeout --verbose --kill-after=2s 15s taskset -c "$timer_cpu"
                "$timer_results/arm64-timer" --samples 128 --loads "$timer_load")
            if [ -x /usr/bin/time ]; then
                timer_command=(/usr/bin/time -v -o "$timer_stem.rusage.txt" "${timer_command[@]}")
            else
                printf 'GNU time unavailable; scheduling counters not collected\n' \
                    > "$timer_stem.rusage.txt"
            fi
            if "${timer_command[@]}" > "$timer_stem.jsonl" 2> "$timer_stem.stderr"; then
                timer_status=0
            else
                timer_status=$?
            fi
            printf '%s\n' "$timer_status" > "$timer_stem.exit"
            python3 - "$timer_stem" "$timer_load" <<'PY'
from pathlib import Path
import sys
from tools.verify_arm64_timer import validate_output
stem, loads = sys.argv[1], int(sys.argv[2])
metadata = validate_output(Path(stem + ".jsonl").read_bytes(),
                           int(Path(stem + ".exit").read_text()), samples=128, loads=loads)
print(stem, "validated; frequency:", metadata["reported_frequency_hz"])
PY
        done
    done
done
```

Stop on the first failure and retain the directory. GNU `timeout` is deliberately
used without `--foreground`, bounding the command and its worker processes;
TERM is followed by KILL if necessary. Raw stdout/stderr and the external exit
code remain available even for a trap, timeout (124/137), launch failure or
truncated output. Do not classify a timeout as timer unavailability.
This external bound also avoids relying on the existing verifier CLI to retain
partial output on a subprocess timeout; that CLI saves output only after return.

If GNU time is present, its context-switch, fault and time statistics describe
the surrounding process execution, including setup/timeout tooling, not individual
measurement windows. A context switch is not evidence of migration. Zero reported
switches do not exclude interrupts or all interference. Never delete slow samples
solely because they are inconvenient.

## 4. Raw files and per-run analysis

The [existing schema](README.arm64-timer.md#output-and-interpretation) is unchanged:
one metadata record, indexed raw start/end/delta decimal-string samples in three
series, three summaries and one complete record. Failed calibrations normally
emit one `error` record and exit 1; argument errors exit 2. Frequency-only failure
can still yield valid counter samples with null frequency. The validator raises
`CounterProbeTrapped` for an initial SIGILL/SIGSEGV, a failed environment candidate
requiring diagnosis, not proof of cause. No alternate timer or data is substituted.

Generate a small derived JSONL report without losing the original samples:

```bash
python3 - "$timer_results" > "$timer_results/analysis.jsonl" <<'PY'
from collections import Counter
import json
from pathlib import Path
import sys
from tools.verify_arm64_timer import SERIES, validate_output
root = Path(sys.argv[1])
for path in sorted(root.glob("cpu-*-loads-*-rep-*.jsonl")):
    parts = path.stem.split("-")
    cpu, loads = int(parts[1]), int(parts[3])
    metadata = validate_output(path.read_bytes(), int(path.with_suffix(".exit").read_text()),
                               samples=128, loads=loads)
    if metadata["selected_cpu"] != cpu:
        raise SystemExit("File/metadata CPU mismatch: " + str(path))
    records = [json.loads(line) for line in path.read_text().splitlines()]
    for series in SERIES:
        deltas = sorted(int(row["delta_ticks"]) for row in records
                        if row.get("kind") == "sample" and row["series"] == series)
        counts = Counter(deltas)
        print(json.dumps({
            "file": path.name, "cpu": cpu, "loads": loads, "series": series,
            "frequency_hz": metadata["reported_frequency_hz"], "samples": len(deltas),
            "zero_count": counts[0], "min_ticks": str(deltas[0]),
            "p05_ticks": str(deltas[(5 * len(deltas) + 99) // 100 - 1]),
            "p50_ticks": str(deltas[(50 * len(deltas) + 99) // 100 - 1]),
            "p95_ticks": str(deltas[(95 * len(deltas) + 99) // 100 - 1]),
            "p99_ticks": str(deltas[(99 * len(deltas) + 99) // 100 - 1]),
            "max_ticks": str(deltas[-1]),
            "min_positive_observed_ticks": next((str(d) for d in deltas if d > 0), None),
            "histogram_ticks": [[str(d), n] for d, n in sorted(counts.items())],
        }))
PY
```

Quantiles use nearest rank and exact integer arithmetic. Review per run, CPU,
load count and session, not just pooled minima. `empty_window` characterizes
wrapper overhead; `adjacent_reads` exposes observed increments/quantization.
Frequency, nominal period `1/frequency`, minimum positive observed delta and
effective ability to distinguish work are different quantities. Read/barrier
overhead can hide smaller increments. No result here establishes intrinsic
timer resolution or a cache-hit latency. Leave unknown frequency in ticks;
never substitute macOS's reported 24 MHz.

Repeat the complete protocol in a second fresh directory/session, reversing
the selected CPU order. Preserve both sessions, environment, source/binary
hashes, core labels, all exit/stderr files, resource diagnostics and analysis.
Copy the directory out of temporary storage before rebooting. A failed/partial
batch remains failed even if later files or sessions happen to succeed.

## Decision gates before a separate cache-state pilot

1. **Provenance:** confirm actual native Linux/M3 identity and the CPU evidence;
   keep every core type/unknown CPU separate. Missing prerequisites mean blocked.
2. **Access and correctness:** require exit zero and full validator acceptance
   for every accepted run, advancing/nondecreasing counts and matching CPU checks.
   Any trap/backwards count/CPU mismatch is a stop for diagnosis, not a reason
   to enable privileged access. Individual zero deltas are allowed and reported.
3. **Frequency:** record probe availability and within/across-session consistency.
   Null frequency permits tick-domain investigation only, pending interpretation;
   a reported value alone neither verifies the oscillator nor establishes accuracy.
4. **Repeatability and work sensitivity:** compare per-run quantiles, histograms,
   overhead and zero fractions for each fixed workload across both sessions.
   Predeclare a conservative pilot gate per CPU: the smallest `owned_buffer`
   p50 for loads=128 must exceed the largest p50 for loads=1 across all ten runs
   of each workload (five in each session). This uses observed replicate ranges,
   not an assumed ns/cycle threshold. If ranges overlap, call the work-sensitivity
   result inconclusive under this wrapper. This gate is a protocol decision,
   not a significance test or a measured cache-hit/miss threshold; passing it
   establishes sensitivity to larger loop work, not suitability for one load.
5. **Scope of a go decision:** at most authorize a separate, controlled cache-state
   pilot. It must establish resident/absent preparation independently, distinguish
   L1-absent from lower-level/DRAM absence, control translations and prefetching,
   interleave controls and estimate held-out classification errors. Repeated loads
   of one address warm it; they do not amplify its original miss. A stable timer
   with unsuitable single-access granularity may still require a different
   experiment, never an automatic declaration of a usable per-probe observer.

No calibration-only result authorizes generated-code/kernel execution or a claim
of reliable H-traces. The future observer needs a stated error budget and null
controls suitable for Revizor's equal-C-trace relational tests. Kernel timer
errata handling, physical core behavior, effective granularity, load sensitivity,
noise and cache-state discrimination ultimately require measurements on this Mac.
