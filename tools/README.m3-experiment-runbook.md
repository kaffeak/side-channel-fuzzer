# B3.5j: first M3 Pro / Fedora Asahi experiments

Use native AArch64 Linux, an ordinary user, and a clean, reviewed, committed checkout. This runbook
reuses the [architectural runner](README.arm64-userspace.md) and the unchanged
[B3.5c timer protocol](README.m3-timer-protocol.md). G1 and G2 have separate
verdicts; either may be blocked while the other is investigated independently.
Do not load modules, execute arbitrary code, change kernel protections/governors,
use PMU registers or perform cache probes. The architectural runner changes only
its own mappings using its existing guarded RW-to-RX publication.

**Evidence already available:** user-reported native Ubuntu AArch64 CI passed
45/45 B3.5i tests, including 102 architectural executions and real seq/cond typed
trace checks. This establishes software behavior on that runner. All M3/Fedora
results below are **pending physical access**; do not prefill successful verdicts.

## 1. Prerequisites, provenance and a durable results directory

Required tools: Bash, Git, native GCC/binutils, `file`, GNU `timeout`/`sha256sum`/`tar`,
util-linux `taskset`/`lscpu`/`script`, Python 3.11 or newer. G1 input preparation additionally
needs the existing Revizor Python dependencies (notably NumPy). G2 and the offline
G1 validator need only Python's standard library. Missing prerequisites mean
**blocked**; arrange installation separately, not by running experiments as root.

In a Bash terminal at the repository root:

```bash
set -euo pipefail
export LC_ALL=C
test "$(id -u)" -ne 0
test "$(uname -m)" = aarch64
for run_tool in git gcc as readelf file timeout sha256sum taskset lscpu script tar python3; do
    command -v "$run_tool"
done
export RUN_REPO="$PWD"
export RUN_PYTHON="$(command -v python3)"
export RUN_RESULTS="$(mktemp -d "$HOME/rvzr-m3-results.XXXXXX")"
mkdir -p "$RUN_RESULTS/software" "$RUN_RESULTS/g1/inputs" "$RUN_RESULTS/g2"
cp tools/README.m3-experiment-runbook.md tools/README.m3-timer-protocol.md \
    "$RUN_RESULTS/software/"
git status --short --untracked-files=all --ignore-submodules=none \
    > "$RUN_RESULTS/software/git-status.txt"
git diff --binary > "$RUN_RESULTS/software/unstaged.patch"
git diff --cached --binary > "$RUN_RESULTS/software/staged.patch"
if ! git rev-parse --verify 'HEAD^{commit}' > "$RUN_RESULTS/software/commit.txt" \
    2> "$RUN_RESULTS/software/git-head.stderr" \
    || [ -s "$RUN_RESULTS/software/git-status.txt" ]; then
    printf 'G1/G2 BLOCKED: a clean, reviewed, committed checkout is required.\n' \
        > "$RUN_RESULTS/VERDICTS.txt"
    printf 'BLOCKED: preserve Git diagnostics in %s; do not run G1/G2.\n' "$RUN_RESULTS" >&2
    exit 1
fi
sha256sum tools/arm64_architectural_smoke.c tools/arm64_architectural_fixture.S \
    tools/arm64_userspace_input.py tools/arm64_userspace_program.py \
    tools/arm64_timer_calibration.c tools/verify_arm64_timer.py \
    tools/verify_arm64_architectural_output.py > "$RUN_RESULTS/software/sources.sha256"
mkdir -p "$RUN_RESULTS/software/sources"
cp tools/arm64_architectural_smoke.c tools/arm64_architectural_fixture.S \
    tools/arm64_userspace_input.py tools/arm64_userspace_program.py \
    tools/arm64_timer_calibration.c tools/verify_arm64_timer.py \
    tools/verify_arm64_architectural_output.py "$RUN_RESULTS/software/sources/"
uname -r > "$RUN_RESULTS/software/kernel.txt"
getconf PAGESIZE > "$RUN_RESULTS/software/page-size.txt"
{
    date -u --iso-8601=seconds
    id
    uname -a
    cat /etc/os-release
    lscpu
    lscpu -e=CPU,CORE,SOCKET,ONLINE
    taskset -pc $$
    cat /proc/cpuinfo
    gcc --version
    as --version
    readelf --version
    timeout --version
    script --version
    "$RUN_PYTHON" --version
    for run_file in /proc/device-tree/model /proc/device-tree/compatible \
        /sys/devices/soc0/{family,machine,soc_id,revision}; do
        printf '\n%s: ' "$run_file"
        if [ -r "$run_file" ]; then tr '\000' '\n' < "$run_file"; else printf 'unavailable\n'; fi
    done
} > "$RUN_RESULTS/software/environment.txt" 2>&1
if "$RUN_PYTHON" -m pip freeze > "$RUN_RESULTS/software/pip-freeze.txt" 2>&1; then
    printf '0\n' > "$RUN_RESULTS/software/pip-freeze.exit"
else
    printf '%s\n' "$?" > "$RUN_RESULTS/software/pip-freeze.exit"
fi
printf 'Results: %s\n' "$RUN_RESULTS"
```

Read the files before proceeding. Confirm actual Apple M3 Pro/OS identity using
the recorded model/compatible/CPU information and a documented identification
source; if unresolved, label the SoC/core **unknown**, not M3-verified. Record
power source, session conditions/background workload, Linux CPU IDs, core labels
and their evidence in `software/session-notes.txt`. Do not assume a kernel release
from an RPM listing is the running kernel, or that macOS's page/cache inventory
describes Linux. Dirty checkouts are not supported: the saved staged/unstaged
patches and status are diagnostics, not a complete source archive. Untracked
contents are not preserved, so any untracked file blocks the experiment. Use
committed experiment sources; ignored environments/build outputs are not audited
by Git status and still need the recorded software versions and binary hashes.
Do not bypass the gate by continuing at G1 or G2. Keep the checkout unchanged
throughout both experiments; after any edit, stop and repeat this preflight into
a new results directory using a clean, reviewed commit.

Choose an allowed CPU explicitly; CPU numbering does not identify Sawtooth versus
Everest. Record readable per-CPU MIDR/capacity/cache fields using B3.5c section 2
when selecting G2 CPUs; keep unknown labels and core types separate. Affinity is
not CPU isolation and does not exclude interrupts or preemption.

## 2. G1: four approved architectural executions

This first target check uses **only the embedded original B3.4a image**, both
branch directions, each twice. It is not the full 102-execution CI matrix and
does not validate the other four MOVZ images. Input bytes come from the existing
InputData serializer/adapter. No timer or model is involved in these four runs.

```bash
read -r -p 'Allowed Linux CPU ID for G1: ' RUN_CPU
export RUN_CPU
"$RUN_PYTHON" - <<'PY'
import os
cpu = int(os.environ['RUN_CPU'])
if cpu not in os.sched_getaffinity(0):
    raise SystemExit('CPU is not in the allowed affinity mask')
PY
printf '%s\n' "$RUN_CPU" > "$RUN_RESULTS/g1/selected-cpu.txt"
{
    for run_file in "/sys/devices/system/cpu/cpu$RUN_CPU/regs/identification/midr_el1" \
        "/sys/devices/system/cpu/cpu$RUN_CPU/cpu_capacity" \
        /sys/devices/system/cpu/cpu"$RUN_CPU"/cache/index*/{level,type,size,coherency_line_size,number_of_sets,ways_of_associativity,shared_cpu_list}; do
        printf '%s: ' "$run_file"
        if [ -r "$run_file" ]; then cat "$run_file"; else printf 'unavailable\n'; fi
    done
} > "$RUN_RESULTS/g1/cpu-identity.txt" 2>&1
run_build=(gcc -std=c11 -O2 -Wall -Wextra -Werror tools/arm64_architectural_smoke.c
    tools/arm64_architectural_fixture.S -o "$RUN_RESULTS/g1/architectural-smoke")
printf '%q ' "${run_build[@]}" > "$RUN_RESULTS/g1/build.command"
printf '\n' >> "$RUN_RESULTS/g1/build.command"
if "${run_build[@]}" \
    > "$RUN_RESULTS/g1/build.stdout" 2> "$RUN_RESULTS/g1/build.stderr"; then
    printf '0\n' > "$RUN_RESULTS/g1/build.exit"
else
    printf '%s\n' "$?" > "$RUN_RESULTS/g1/build.exit"
    exit 1
fi
file "$RUN_RESULTS/g1/architectural-smoke" > "$RUN_RESULTS/g1/elf.txt"
readelf -h "$RUN_RESULTS/g1/architectural-smoke" >> "$RUN_RESULTS/g1/elf.txt"
sha256sum "$RUN_RESULTS/g1/architectural-smoke" > "$RUN_RESULTS/g1/binary.sha256"
```

Before continuing, verify `elf.txt` says AArch64 and review build diagnostics.
Then prepare inputs and execute the bounded matrix:

```bash
"$RUN_PYTHON" - <<'PY'
import os
from pathlib import Path
import numpy as np
from rvzr.tc_components.test_case_data import InputData
from tools.arm64_userspace_input import encode_input
root = Path(os.environ['RUN_RESULTS']) / 'g1/inputs'
for selector in (0, 1):
    value = InputData(1)
    value.view(np.uint8).fill(0)
    value[0]['gpr'][0], value[0]['main'][0] = selector, 7
    (root / f'selector-{selector}.raw').write_bytes(encode_input(value))
PY
for run_rep in 1 2; do
    for run_selector in 0 1; do
        run_stem="$RUN_RESULTS/g1/cpu-$RUN_CPU-selector-$run_selector-rep-$run_rep"
        test ! -e "$run_stem.command"
        run_input="$RUN_RESULTS/g1/inputs/selector-$run_selector.raw"
        run_command=(timeout --verbose --signal=TERM --kill-after=2s 10s
            taskset -c "$RUN_CPU" "$RUN_RESULTS/g1/architectural-smoke"
            --input-format rvzr-inputdata-raw-v1)
        printf '%q ' "${run_command[@]}" > "$run_stem.command"
        printf '< %q > %q 2> %q\n' "$run_input" "$run_stem.jsonl" "$run_stem.stderr" \
            >> "$run_stem.command"
        date -u --iso-8601=seconds > "$run_stem.started.txt"
        if "${run_command[@]}" < "$run_input" > "$run_stem.jsonl" 2> "$run_stem.stderr"; then
            run_status=0
        else
            run_status=$?
        fi
        printf '%s\n' "$run_status" > "$run_stem.exit"
        if "$RUN_PYTHON" tools/verify_arm64_architectural_output.py "$run_stem.jsonl" \
            --input "$run_input" --exit-file "$run_stem.exit" \
            --kernel "$(cat "$RUN_RESULTS/software/kernel.txt")" \
            --page-size "$(cat "$RUN_RESULTS/software/page-size.txt")" \
            > "$run_stem.validation.json" 2> "$run_stem.validation.stderr"; then
            run_validation=0
        else
            run_validation=$?
        fi
        printf '%s\n' "$run_validation" > "$run_stem.validation.exit"
        if [ "$run_status" -ne 0 ] || [ "$run_validation" -ne 0 ]; then
            printf 'REJECTED: %s; stop and preserve all files\n' "$run_stem"
            exit 1
        fi
        if [ -s "$run_stem.stderr" ]; then
            printf 'INCONCLUSIVE: unexpected stderr at %s; review before proceeding\n' "$run_stem"
            exit 1
        fi
    done
done
```

The external GNU timeout is deliberately not `--foreground`: it bounds the
process group, including the child. Keep timeout exits (124/137), signals,
partial stdout and stderr; never retry over a failed file or continue after a
rejected trial. The C parent's own deadline is not protection against every
possible supervisor/OS failure. Stderr or a bare architectural-state record
cannot replace exit zero and the final complete record.

| Input selector / first word | Expected X0-X7 | NZCV | Final main |
| --- | --- | --- | --- |
| 0 / 7 | 0,22,7,29,0,0,0,0 | `0x60000000` | First word 29, remaining 4088 bytes zero |
| 1 / 7 | 1,11,7,18,0,0,0,0 | `0x20000000` | First word 18, remaining 4088 bytes zero |

Each saved stream must contain exactly one metadata, one architectural state and
one final complete record, with matching kernel/page/input identity. The offline
validator checks these, full main bytes, all eight reported registers, flags,
SP alignment and nonoverlapping aligned guarded-address arithmetic. It rejects
partial/extra records, incorrect modes, nonzero exits and malformed JSON. Addresses
are historical, not reusable pointers; file validation cannot attest execution
or address liveness. Both repetitions must match the table, not each other's ASLR
addresses. G1 is **accepted only within this fixed-image scope** after all four
runs pass. A 4096-byte runtime can validate only that geometry; it cannot pass the
intended 16-KiB target gate. Unexpected identity/page size means target-scope
**inconclusive** pending diagnosis; setup/missing dependencies are **blocked**;
an execution, cleanup or output mismatch is **rejected**.

For broader G1 follow-up only after this passes, the unchanged CI command runs
45 tests/102 architectural executions with model/oracle checks. It requires all
existing Python/binutils dependencies. It is optional here, not a substitute for
preserving the four raw streams above; record any follow-up command/log separately.

## 3. G2: preserve the unchanged B3.5c protocol, twice

Run independently of G1's verdict; a rejected G1 must not be called a successful
architectural gate because G2 passes. B3.5c does not authorize generated code.
Use a terminal transcript so commands, CPU choices, validator messages and failures
survive. In the same ordinary-user environment:

```bash
export TIMER_SESSION="$RUN_RESULTS/g2/session-1"
test ! -e "$TIMER_SESSION"
mkdir -p "$TIMER_SESSION"
if script --return --flush --command 'bash --noprofile --norc' "$TIMER_SESSION/transcript.txt"; then
    printf '0\n' > "$TIMER_SESSION/protocol.exit"
else
    printf '%s\n' "$?" > "$TIMER_SESSION/protocol.exit"
fi
```

Inside that recorded shell, `cd "$RUN_REPO"`, verify `id -u` is nonzero, then:

1. Run **B3.5c section 1's Bash block unchanged** (provenance and compilation).
   Immediately record its temporary directory before proceeding:
   `printf '%s\n' "$timer_results" > "$TIMER_SESSION/raw-path.txt"`.
2. Run section 2 unchanged: choose one or two allowed CPUs, retain all readable
   MIDR/capacity/cache information, and write its required `core-labels.txt` with
   evidence or `unknown`. Keep the actual CPU sequence in the transcript.
3. Run section 3 unchanged: five repetitions, rotating loads 1/8/32/128, 128
   samples per series, original 15-second timeout and per-run raw/exit files.
   Stop on its first failure. Its existing validator prints into the transcript;
   failed or partial batches remain failed even if later experiments succeed.
4. On a complete batch, run section 4 unchanged to produce validated per-run
   `analysis.jsonl`. Exit the recorded shell. **Even after failure**, return to
   the parent terminal and copy the retained raw directory as below.

```bash
if [ -f "$TIMER_SESSION/raw-path.txt" ]; then
    timer_saved_path="$(cat "$TIMER_SESSION/raw-path.txt")"
    mkdir -p "$TIMER_SESSION/raw"
    cp -a "$timer_saved_path/." "$TIMER_SESSION/raw/"
else
    printf 'BLOCKED/PARTIAL: inspect transcript for failure before raw directory recording\n'
fi
```

If section 1 failed before path recording, recover its printed results path from
the transcript and preserve that directory too. Do not reboot/remove temporary
data before copying. Do not overwrite session-1. Repeat in a fresh `session-2`
directory, re-running sections 1-4 and reversing the selected CPU order as B3.5c
requires. Record both sessions' power/background conditions. Each complete session
has **20 runs per CPU**, 384 samples/389 records per run. With two CPUs and two
sessions this is at most 80 raw runs/30720 samples. Check expected file counts;
missing files, missing analysis or incomplete transcripts cannot count as a pass.

Use B3.5c's existing decision gates, without inventing new timing thresholds:

| Verdict | Conditions |
| --- | --- |
| Accepted for a separate cache-pilot design | Every run validates; kernel/page/CPU identities agree; counters advance/nondecrease; full files and two sessions exist; per-CPU loads=128 minimum replicate p50 exceeds loads=1 maximum replicate p50 across both sessions. Review distributions/overhead/zero fractions and retain all outliers. This establishes larger-work sensitivity only. |
| Rejected / stop | Trap, backwards/nonadvancing run, CPU mismatch, nonzero/timeout exit, malformed/truncated output or missing completion. Initial counter-probe SIGILL/SIGSEGV is an unavailable-environment candidate requiring diagnosis, not fabricated success or proven cause. Do not switch clocks or enable privileges. |
| Inconclusive / blocked | Missing prerequisites or unresolved target/core identity; overlapping workload-median ranges, unexplained drift/interference or incomplete sessions. Null frequency permits tick-domain analysis only; it is not a fabricated frequency or automatically a failed counter calibration. |

Never replace null CNTFRQ with macOS's 24 MHz. The wrapper's minimum observed
increment is not intrinsic resolution; warmed buffer operations are not proven
L1 hits. Affinity/start/end CPU checks do not attribute every scheduling delay.

## 4. Results packaging and the next gate

Keep this layout, with raw failures beside successful trials:

```text
rvzr-m3-results.*/
  software/  commit, git status, staged/unstaged patches, source hashes, environment, versions, session notes
  g1/        build command/stdout/stderr/exit, ELF/binary hash, selected CPU/identity, inputs/
             cpu-*-selector-*-rep-*.{command,started.txt,jsonl,stderr,exit}
             cpu-*-selector-*-rep-*.validation.{json,stderr,exit}
  g2/session-{1,2}/
             transcript.txt, protocol.exit, raw-path.txt
             raw/arm64-timer, environment/build/binary hash, core labels and CPU identity
             raw/cpu-*-loads-*-rep-*.{started.txt,jsonl,stderr,exit,rusage.txt}
             raw/analysis.jsonl (only for completed, validated batches)
  VERDICTS.txt    G1/G2 separately: accepted/rejected/inconclusive/blocked + evidence
  MANIFEST.sha256
```

Record actual counts, kernel/page, selected CPUs/core evidence, scope and failure
reasons in `VERDICTS.txt`; leave missing evidence pending. After files are closed:

```bash
"$RUN_PYTHON" - <<'PY'
import hashlib
import os
from pathlib import Path
root = Path(os.environ['RUN_RESULTS'])
manifest = root / 'MANIFEST.sha256'
with manifest.open('w') as output:
    for path in sorted(root.rglob('*')):
        if path.is_file() and path != manifest:
            with path.open('rb') as data:
                digest = hashlib.file_digest(data, 'sha256').hexdigest()
            output.write(f'{digest}  {path.relative_to(root).as_posix()}\n')
PY
(cd "$RUN_RESULTS" && sha256sum -c MANIFEST.sha256)
tar -czf "$RUN_RESULTS.tar.gz" -C "$(dirname "$RUN_RESULTS")" "$(basename "$RUN_RESULTS")"
sha256sum "$RUN_RESULTS.tar.gz" > "$RUN_RESULTS.tar.gz.sha256"
```

A later controlled cache pilot still requires: justified resident/absent
preparation on owned memory; single-access timer discrimination; translation/
prefetch and observer-perturbation controls; independent held-out validation and
false-positive/negative estimates; a declared error budget; repeatable per-core
null/identical-input controls; and separately reviewed observation boundaries.
G1+G2 do not establish any of these, physical speculation, equal M3 H-traces or
leakage. The [B3.5h/i design](README.arm64-userspace-observation-design.md) retains
the full evidence gates.

**Before hardware access:** WSL2 can validate the offline verifier with synthetic
records, timer failure/protocol tests, real Unicorn typed equivalence and mapping
arithmetic, strict cross-compilation and command syntax. Native CI already covers
its own architectural executions and timer smoke. Neither supplies the missing
M3/Fedora identity, 16-KiB execution, timer distributions or cache-state evidence.

Host commands (use the existing project Python environment):

```bash
python3 -m unittest tests.unit_arm64_architectural_verifier tests.unit_arm64_timer_calibration -v
# Additional real model/admission regressions: cross-binutils on x86-64, no native requirement.
RVZR_ARM64_BINUTILS_PREFIX=aarch64-linux-gnu- python3 -m unittest \
    tests.unit_arm64_userspace_execution tests.unit_arm64_location_correspondence -v
```

Current WSL2 validation ran these four modules together: **77 tests, 74 passed,
three native-only skips**. The four new verifier tests use synthetic records only;
the 45-test native CI selection, original timer protocol and C tools are unchanged.
