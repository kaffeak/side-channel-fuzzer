# M1-G3-P0 Phase 2 — static exclusive-reservation worker

**Compile/disassembly and synthetic desktop validation only. No native worker execution,
physical result or G3 acceptance.** The unchanged [Phase 1 protocol](README.m1-g3-p0.md)
and [validator](m1_g3_p0.py) remain authoritative. This document supplements their
historical software-preparation status; it does not amend their schema or thresholds.
Deployment and physical execution still require separate review and explicit approval.

## Components and observation boundary

* `exclusiveReservation/probe.S`: four static AArch64 Linux ELF entry points.
* `exclusiveReservation/worker.c` / `worker.h`: bounded plan decoding, schedule,
  owned-memory lifecycle, capture, publication, failure handling and JSONL.
* `exclusiveReservation/linux.c`: actual Fedora Asahi 45/T8103 identification and
  singleton affinity. No native/synthetic runtime switch.
* `m1_g3_p0_native.py`: passive packet encoder and compile/evidence builder. It never
  launches a worker. Python 3.11+, standard library only.
* `../tests/m1_g3_p0/host.c`: separately linked **synthetic** desktop backend. Ordinary
  C reads/writes substitute for the assembly; it cannot accept physical-labelled plans.
  Its fault controls are absent from the native backend.

No timers, cache sweeps, PMU access, executable allocations, arbitrary instruction
admission, retry loops or exclusive-instruction warmups are implemented. `_a` and `_b`
dispatch to the same operation with the same A/B values and target address.

## Complete assembly bodies and verification

Arguments: X0 = aligned target, X1 = B, X2 = separate result capture. The complete
adjacent entry is:

```asm
dmb ish                // outside exclusive interval: reset ordering
ldxr x3, [x0]          // interval starts: 64-bit A
stxr w4, x1, [x0]      // interval ends: distinct 32-bit status register
dmb ish                // outside interval: store/readback ordering
ldr x5, [x0]           // independent architectural memory read
stp x3, x5, [x2]       // loaded value, memory-after
str w4, [x2, #16]      // raw status
ret
```

`p0_clear` inserts exactly one `clrex` between LDXR and STXR; `p0_sham` inserts
exactly one `nop`. `p0_clear_old` is exactly `clrex; ret`, called before reset A.
Full function sizes are 32, 36, 36 and 8 bytes respectively. None accesses SP,
callee-saved registers or X18. There are no instructions other than the intended
pair/control inside each interval; capture stores happen afterwards. Barriers match
across all operations. Natural alignment is enforced by the private 16 KiB mapping
and fixed target offset 8192. Canaries are at target−8 and target+8.

The fail-closed verifier consumes GNU `objdump -d -w` and `readelf -sW`, requires exact
global ELF FUNC names/sizes and every instruction in each body, and checks disassembled
opcode words against the saved executable's actual bytes. It requires little-endian
AArch64 ELF64 EXEC, no interpreter segment and no executable GNU stack. Unknown
renderings fail; Mach-O is deliberately unsupported. Linker padding outside a function's
ELF size is preserved in the full dump but is not part of that function. Static libc
may itself contain atomics elsewhere; verification concerns these complete entry points,
not a claim that the whole executable contains only three exclusive pairs.

This proves a bounded machine-code property, not exclusive-monitor behavior, physical
cache state, immunity to interrupts, or source/binary provenance on a remote machine.

## External plan and byte transport

The independent launch plan remains external JSON validated by the original module.
Prepare a **new** input packet without executing anything:

```bash
python3 -B tools/m1_g3_p0_native.py prepare \
  --plan /saved/independent-launch.json --output /saved/new-worker-input.bin
```

The C process accepts no CLI options. Its stdin must contain this packet followed by
EOF. This avoids adding a second JSON parser in C. The bounded, versioned transport is:

1. Eight bytes `4d 31 47 33 50 30 00 01`.
2. Five little-endian uint32: CPU, seed, blocks, phase (0 calibration / 1 held-out),
   evidence kind (0 physical / 1 synthetic).
3. Eleven strings, each uint16 little-endian byte length followed by UTF-8 bytes:
   `run_id`, `session_id`, `cohort_id`, `target_id`, `kernel_release`, `source_commit`,
   `source_sha256`, `binary_sha256`, `disassembly_sha256`, `build_manifest_sha256`,
   `frozen_calibration_sha256`. Null calibration digest is zero length.

Python checks the exact old JSON plan schema and 4096-byte ceiling; packet size is at
most 1024 bytes. C independently checks bounds, enum values, token/hash syntax, phase
seeds, calibration digest presence and EOF. It reconstructs `metadata.plan` rather than
echoing unchecked JSON. Live kernel release must match the plan. The unchanged validator
then compares the emitted metadata to the independently saved plan and actual supervisor
execution record. No worker can authenticate producer-supplied source/binary hash strings;
the future supervisor must independently hash the saved/executing artifacts and check them.

Native identity requires nonroot AArch64 little-endian Linux, 16384-byte runtime pages,
DT `apple,t8103`, `ID=fedora-asahi-remix`, `VERSION_ID=45`, an `ID_LIKE` token `fedora`,
selected CPU 0/4 allowed, and its protocol MIDR. Actual compatible/ID_LIKE lists and MIDR
are recorded. Simple quoted/unquoted os-release values are supported; escapes, duplicate
required keys and unavailable metadata fail closed. CPU is pinned and the singleton mask
re-read, with endpoints per attempt and a final mask check. These are endpoint checks,
not proof of uninterrupted execution or absence of external affinity changes.

## Publication, resource ceilings and failure evidence

One process performs one planned launch: independently supervised PID equals recorded
measurement PID. No internal fork or campaign scheduling. The future external supervisor
must enforce the protocol's 10-second timeout, 2-second kill/reap guard and independent
20-second outer watchdog, preserve stdout/stderr/status, and never replace failed runs.
That supervisor/physical launcher is **not implemented** in this phase.

The worker additionally sets both CPU limits to at most 2 seconds, disables core dumps,
arms a 10-second wall alarm, and bounds signal-error dumping with a 2-second alarm.
Pre-existing tighter limits are retained. These are not hard real-time guarantees;
blocked kernel I/O can exceed an in-process deadline. No resource settings apply outside
the worker process and its owned mappings.

Owned experimental virtual-memory budget at maximum 384 trials:

| Allocation/reservation | Bytes |
| --- | ---: |
| Target R/W page plus two PROT_NONE guards | 49152 |
| Results: round_up(128 + 384×128, 16384) | 65536 |
| Append-only JSON storage | 524288 |
| Required prefaulted stack area | 65536 |
| Alternate signal stack | 32768 |
| **Total** | **737280 (720 KiB)** |

Default 32 blocks use 704512 bytes. Ordinary executable/libc RSS and ordinary stack
overhead are excluded as in the protocol. Allocation sums, result geometry and assembly
capture offsets have runtime/compile-time checks. All used target/results/JSON/signal
stack pages and the 64 KiB measurement stack area are initialized and prefaulted before
the first trial. Results occupy separate pages, prefilling every raw status with
UINT32_MAX. All mappings have process lifetime; normal exit, signal death or kill lets
Linux reclaim them. No persistent service or reused allocation is introduced.

Each attempt clears the old monitor outside the interval, resets A, captures before
state/canaries/CPU, performs exactly one entry, captures after state/canaries/CPU, then
serializes. An immutable completed-prefix descriptor is release-published via a lock-free
atomic pointer only after the complete record exists. Signal handling acquire-loads
only that descriptor. An in-flight attempt is never published as successful.

**Output is flushed after metadata and each completed attempt, outside every exclusive
interval.** This preserves earlier records even after SIGKILL and avoids a supervisor
polling shared results, while maintaining the original PID/schema interface. Consequently,
formatting/write syscalls occur **between** trials and can affect scheduling, caches and
later monitor behavior. This is an explicit intertrial confound to review before physical
deployment, not a cache-neutral protocol. No metadata collector runs concurrently.

Invalid status/value/canary or CPU-after is retained as an actual sample before an error;
CPU-before/preparation failures produce no unexecuted sample. Traps/interrupts attempt
to emit only the retained prefix and an error, then re-deliver the original fatal signal;
there is no recovery/retry. If interrupted during output, the last JSON line may be
partial or malformed. Hard kills preserve only already-flushed bytes; no promise is made
for the in-flight record. All such exits/prefixes are unsuccessful under the unchanged
validator. Normal raw output stays below the tighter 512 KiB buffer and 8192-byte lines,
within the protocol's 1 MiB/386-record limits.

## Reproducible compile-only evidence

On a desktop with AArch64 GNU cross tools and static libc development files:

```bash
python3 -B tools/m1_g3_p0_native.py build --output /tmp/p0-new-build \
  --cc aarch64-linux-gnu-gcc --objdump aarch64-linux-gnu-objdump \
  --readelf aarch64-linux-gnu-readelf
```

The same build-only command can select native AArch64 GNU tools, without executing
the resulting worker. For an extracted Ubuntu cross-toolchain, the optional
`--sysroot /absolute/extracted/root` adds the matching sysroot and cross-header directory.
No root installation is required. A build directory must not already exist.

Exact compiler/linker flags:

```text
-std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
-D_FORTIFY_SOURCE=2 -static -Wl,-z,noexecstack,-z,relro,-z,now
```

The helper records exact command arrays, compiler/linker/objdump/readelf versions,
source snapshots, sorted canonical `source-manifest.sha256`, native binary, full
disassembly, symbol/ELF metadata, per-command stdout/stderr/exit, verification report,
canonical `build.json` and internal `SHA256SUMS`. Failed builds retain their sources
and diagnostics. Source links are rejected. The checksum manifest excludes itself.
`source_sha256` is the digest of `source-manifest.sha256`; `build_manifest_sha256` is
the digest of canonical `build.json`. Binary/disassembly digests cover exact saved bytes.
Development builds truthfully record a dirty checkout; they are **not approved physical
release artifacts**. Clean committed provenance remains a prerequisite for deployment.

## Software validation and golden schedules

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest \
  tests.unit_m1_g3_p0_worker tests.unit_m1_g3_p0 \
  tests.unit_hwmon_investigation tests.unit_experimental_environment \
  tests.unit_m1_g2_launcher tests.unit_arm64_timer_calibration -v
.venv/bin/python -m flake8 --max-line-length=100 \
  tools/m1_g3_p0_native.py tests/unit_m1_g3_p0_worker.py
.venv/bin/python -m mypy --follow-imports=skip \
  tools/m1_g3_p0_native.py tests/unit_m1_g3_p0_worker.py
PYLINTHOME=/tmp/p0-pylint .venv/bin/python -m pylint --persistent=n --score=n \
  tools/m1_g3_p0_native.py tests/unit_m1_g3_p0_worker.py
```

Cross-checks use `P0_AARCH64_CC`, `P0_AARCH64_OBJDUMP`, `P0_AARCH64_READELF` and optional
`P0_AARCH64_SYSROOT`, or standard cross-tool names. Missing tools explicitly skip the
machine-code check; that is **not** disassembly verification. The cross-built binary
is never launched by these tests. Native identity reads/affinity are source-audited and
cross-compiled; the desktop backend supplies synthetic identity/CPU observations.

Condition byte IDs are 0 adjacent_a, 1 adjacent_b, 2 clear_a, 3 clear_b, 4 sham_a,
5 sham_b. Full 64-block byte streams are compared C/Python. Independently frozen first
blocks and SHA-256 of each **32-block / 192-byte** stream:

| Seed | First block | SHA-256 |
| --- | --- | --- |
| 101 | 0,4,3,5,2,1 | `b10e73fbf1b21f3a2df8f7c3934181d0871bb2e85d0f9ccf23e1d03cbc25e621` |
| 102 | 1,3,4,5,0,2 | `510f9cba1715e0c8e0c31129661f0d72e675801f61b9b7e29ae78540503a38c8` |
| 201 | 2,4,3,0,1,5 | `1dfb6c3598ae9213f0a2c25ba30d018c3d53b36cad02575d83a4fc882945fc20` |
| 202 | 1,5,0,4,3,2 | `7641aa621eb907cd8c5ccab7b7bcb8bd4116a4319e4a0ff91d6529695df89476` |

Synthetic tests exercise actual C scheduling, memory layout, packet limits, all four
seeds/both CPUs, default/max output against the unchanged validator, trap/kill prefixes,
CPU/wall-limit setup and invalid architectural outcomes. They do **not** test actual
LDXR/STXR semantics or live M1 metadata. Separate AddressSanitizer and UBSan runs cover
the C core with the synthetic backend; LSan is disabled because the desktop ptrace
environment does not support it, so no leak-check result is claimed. Mappings intentionally
last until process exit. Disassembly mutations must fail, including altered access width,
register overlap, CLREX removal, unexpected calls, capture offsets and mismatched bytes.

Before physical execution: independently review this worker and full disassembly,
prepare a clean committed build and external plans, establish a separately approved
bounded supervisor and artifact preservation, verify actual native identity/resource
interfaces, then obtain explicit execution approval. IRQs and scheduling remain enabled;
affinity and endpoint canaries do not establish monitor reliability. No present result
establishes cache discrimination, observer suitability, HTrace semantics or leakage.
