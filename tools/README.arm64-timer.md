# ARM64 Linux timer-capability calibration

This standalone utility investigates a timer, not cache leakage. It does not use
Revizor, PMU registers, cache-maintenance instructions, speculative execution,
kernel modules, or other processes' memory. It requires no root privileges.

Build on AArch64 Linux:

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror tools/arm64_timer_calibration.c -o /tmp/arm64-timer
/tmp/arm64-timer --help
```

Cross-compile on x86-64 Linux with a Linux AArch64 toolchain and libc:

```sh
aarch64-linux-gnu-gcc -std=c11 -O2 -Wall -Wextra -Werror \
    tools/arm64_timer_calibration.c -o /tmp/arm64-timer
```

There is deliberately no x86, macOS, emulated-clock, or `clock_gettime` fallback.
Cross-compilation verifies the build, not timer access or measurement validity.

On the future Fedora Asahi target, identify an allowed Linux CPU ID before running:

```sh
taskset -pc $$
/tmp/arm64-timer --cpu 0 --samples 10000 --loads 1 > calibration.jsonl
```

Replace `0` with the chosen **allowed Linux CPU ID**. IDs are not assumed to
identify Sawtooth or Everest; record that mapping separately. Without `--cpu`,
the first CPU in the process's allowed mask is selected. The process pins itself
to exactly that CPU; its children inherit affinity. Start/end CPU checks detect
some affinity failures, not every possible mid-run external interference.
CPU IDs are limited to the libc `cpu_set_t` capacity (`CPU_SETSIZE`); a larger
kernel affinity mask fails explicitly rather than being silently truncated.

`--samples` defaults to 10000 per series, bounded to 1..100000. `--loads` defaults
to 1, bounded to 1..256. The owned buffer is always 512 bytes. Result storage is
below 5 MB; maximum output is 300000 raw records plus metadata/summaries. Small
sample counts are suitable only for output smoke tests. Measurements run at the
normal scheduler policy with interrupts enabled. Neither real-time priority nor
CPU isolation is requested. Seccomp/container policies may prohibit `fork`,
shared anonymous mappings, affinity, or timer access; failures are reported.

## Counter and ordering

The counter is `CNTVCT_EL0`. Its reported frequency is read independently from
`CNTFRQ_EL0`. Frequency probing and calibration run in separate child processes;
there are no forks within measurement windows. Register traps are detected by
`waitpid`, without trying to resume a faulting instruction.
Children disable core dumps. Frequency access can fail while counter access
succeeds: frequency is then `null`, with its probe exit/signal recorded. There
is also no usable frequency if the register returns zero (`null`, probe exit 0).
There is no inference from a macOS timebase or the device tree's reference-clock node.

Counter reads use `ISB; MRS CNTVCT_EL0; ISB`, plus a compiler memory clobber.
Empty and buffer windows additionally execute `DSB ISH` before **each** timestamp
to complete earlier normal-memory accesses in the inner-shareable domain. These
conservative barriers are included in the observed window overhead; this is not
an optimized load-latency primitive. The post-read ISB and compiler barrier keep
subsequent operations on the intended side of the timestamp.

The implementation does not apply kernel alternatives or CPU-specific counter
erratum workarounds. Native execution and comparison with the target kernel's
timer implementation are still required. Linux's corresponding accessors are in
[arch_timer.h][timer-source].

[timer-source]: https://github.com/torvalds/linux/blob/v6.18/arch/arm64/include/asm/arch_timer.h#L60

## Output and interpretation

Output is JSON Lines, schema version 1:

- One `metadata` record: counter/frequency, frequency-probe status, kernel release,
  machine, kernel page size, selected/start/end CPUs, initial allowed mask, sample
  counts, buffer size, and a load checksum.
- `sample` records for three sequential series, with zero-based `index` and raw
  `start_ticks`, `end_ticks`, and `delta_ticks`.
- A `summary` for each series: min/max deltas, zero count, and minimum **observed**
  positive delta (or `null` if absent).
- One final `complete` record containing `status: "ok"` and the sample count.

All tick values and the checksum are decimal strings, preserving integers beyond
JSON consumers' usual 53-bit exact range. Frequency is a reported register value,
not a measured or independently verified oscillator frequency. Convert ticks to
seconds only when that frequency is available and trusted.

The three series are:

1. `adjacent_reads`: successive ordered reads. Differences include loop/recording
   overhead. Zero and positive increments expose observed sampling granularity.
2. `empty_window`: two conservative timestamps with no intentional buffer access
   between them. This characterizes wrapper/barrier overhead and scheduling noise.
3. `owned_buffer`: the same wrapper around a volatile load-and-checksum loop,
   starting at buffer word zero and wrapping after 64 words. Initialization and
   prior accesses happen before measurements. They do **not** establish reliable
   L1 residency. Loop arithmetic and checksum work are part of the window.

Do not equate the minimum positive observed delta with the timer's true hardware
resolution. Read overhead can hide smaller increments. A nominal tick period
`1 / reported_frequency_hz` is a different quantity. Do not subtract the empty
minimum and call the remainder a cache-hit latency. Samples retain preemption,
interrupt, page-fault, virtualization, and frequency/thermal effects; no per-sample
interrupt or context-switch attribution is provided.

A timer-worker signal, backwards counter, entirely nonadvancing run, CPU mismatch,
or setup failure produces an `error` record and nonzero exit, with no sample records.
Worker exit codes 10..13 mean setup failure, backwards counter, no advance, and
CPU mismatch respectively. Argument errors print usage and exit 2. Consumers must
require exit status zero **and** a final `complete` record; output errors may leave
an incomplete stream. A successful run can still have individual zero deltas.

Before cache discrimination, validate actual Linux timer access/frequency and
effective increments on each core type, ordering, and observer overhead. Then
design independent resident/absent preparation (with an explicitly permitted
method), warm translations, randomized/interleaved controls, and held-out error
estimates. Distinguish fully flushed memory from L1-absent/L2-resident data. Repeated
loads of one address warm it and do not amplify its original miss. Raw calibration
on a generic or virtual ARM64 runner establishes none of these M3 properties.

## Reproducible verification

On Linux with a native C11 compiler and Python, run the host-only checks:

```sh
python -m unittest tests.unit_arm64_timer_calibration -v
```

These retain the original 13 temporary synthetic checks and add argument syntax,
help, JSONL validation and verifier failure tests. They compile a **temporary copy**
of the C source with synthetic reads and no ARM instructions. Only register reads
and the barrier are substituted; argument parsing, affinity, fork/wait, error
handling and output code come from the utility. Each substitution must match
exactly once; changed source requires review. The repository C source is unchanged.
This fixture validates control flow and formatting, never architectural timer access.

On **native AArch64 Linux**, compile and verify the real utility:

```sh
gcc -std=c11 -O2 -Wall -Wextra -Werror tools/arm64_timer_calibration.c -o /tmp/arm64-timer
python tools/verify_arm64_timer.py /tmp/arm64-timer --output /tmp/arm64-timer.jsonl
```

The verifier invokes `--samples 32 --loads 2`, with no CPU override, and a 15-second
execution timeout. It requires exit zero and exactly 101 JSONL records: one
metadata, 96 samples, three summaries and one final complete record. It checks the
three series in order, continuous indices, unsigned 64-bit decimal tick strings,
`delta = end - start`, monotonic windows, summary statistics, checksum, CPU metadata
and completion count. Duplicate keys, nonfinite JSON numbers, malformed/truncated
streams and output over 128 KiB are rejected. A null frequency is accepted when
the independent frequency probe fails or returns zero; no frequency is invented.
No timing threshold is asserted.

The `arm64-baseline` job in `.github/workflows/arm64-software-baseline.yml` runs
both checks. It compiles the unmodified source with native GCC on
`ubuntu-24.04-arm`; the Fedora kernel-header build job does not run the utility.
Both new steps are limited to two minutes. Raw stdout and stderr are saved under
`RUNNER_TEMP` (small files, no uploaded artifact or long-term measurement archive).
The success count is printed in the job log. Run locally to retain the raw files.

Verifier exit codes:

- `0`: real execution and protocol verification succeeded.
- `1`: execution/setup failure, timeout, malformed output, or inconsistent data.
- `3`: the initial `counter_probe` worker trapped with SIGILL or SIGSEGV and emitted
  an explicit error. This is an **unsupported-environment candidate**, still a
  failed CI step, never a successful or silently skipped calibration. The raw
  stage/signal/exit diagnostic is retained. Investigate timer policy and the
  program before assigning a cause; SIGSEGV can also be a memory defect. Signals
  at later stages are ordinary failures, not classified as unavailable access.

The synthetic signal test confirms the program's failure path, not how a particular
kernel delivers a register trap. Only native execution establishes accessibility
on that environment. GitHub runner timings are specific to its CPU, hypervisor and
load; they do **not** validate Apple M3 Pro compatibility, cache-hit/miss
discrimination, physical timer resolution or the future Fedora Asahi environment.
