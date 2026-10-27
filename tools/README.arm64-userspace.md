# Fixed ARM64 Linux userspace architectural execution (B3.5d/e)

This experiment executes one trusted, compiled-in instruction body with one
validated raw `InputData` fragment per process. It returns actual architectural
state, **not an H-trace**. It has no program upload interface, PMU access, timer, cache observer,
kernel-module dependency, speculative model, or production executor integration.
Do not extend its command line to accept arbitrary machine code.

B3.5d's three fixed inputs passed native Ubuntu AArch64 CI on a 4K-page kernel
(user-reported). The B3.5e input adapter needs a new native CI run. Cross-compilation,
Unicorn execution, and host mocks do not establish native execution. Fedora Asahi
M3 Pro execution and its memory-protection policy remain unverified.

## Interface audit and reuse boundary

| Existing component | Relevant implementation | Reuse / limitation |
| --- | --- | --- |
| ARM64 generation and parsing | `rvzr/factory.py:242-267`; `rvzr/code_generator.py:202-244`; `rvzr/arch/arm64/asm_parser.py:27-145` | Existing template, GNU assembly and `TestCaseProgram` are reused by the tests, with one actor and no random macros. No generator changes. |
| ELF metadata and serialization | `rvzr/elf_parser.py:226-307`; `rvzr/tc_components/test_case_binary.py:43-136` | The test compares the native body's bytes against the real B3.4a ELF section. RCBF metadata is not executable code and is not copied into the mapping. |
| Inputs | `rvzr/tc_components/test_case_data.py:23-36,86-104,148-204`; `rvzr/input_format.py` | `tools/arm64_userspace_input.py` validates the supported subset and returns production raw bytes unchanged. C consumes one raw actor fragment; it does not import the kernel RDBF parser or implement general input loading. |
| Existing RDBF decoder | `rvzr/executor_km/input_parser.c:30-146`; `rvzr/executor_km/include/input_parser.h:11-35` | Stateful kernel parser consumes a 16-byte header, per-actor 16-byte metadata, then 12288-byte fragments; it depends on global actor/input state and kernel allocations. The userspace adapter needs none of that state and does not copy its parser. |
| ARM64 model placement and registers | `rvzr/model_unicorn/model.py:698-756`; `rvzr/arch/arm64/target_desc.py:160-163` | Sequential Unicorn remains the comparison model. Its synthetic main base is `0x10a000`; native addresses need not match because this fixture has no pointer-valued outputs. Input slots 6/7 are NZCV/SP, not X6/X7. |
| Kernel-dependent adapter | `rvzr/executor.py:235-265,271-330,332-340`; `rvzr/arch/arm64/executor.py:13-28` | Constructor, loading, input transport and trace collection depend on sysfs. Do not instantiate it for this experiment. |
| Executor selection | `rvzr/factory.py:87-99` | Still selects the existing kernel adapter. This experiment is deliberately unregistered. |
| Kernel entry/code loading | `rvzr/executor_km/code_loader.c:39-157`; `rvzr/executor_km/arm64/entry_exit_points.h:23-201` | Kernel prologue/epilogue use utility offsets, stack replacement, measurement registers and macro expansion. These are not a userspace ABI. Nothing is copied from the kernel executable template. |
| Trace types | `rvzr/traces.py:41-69,188-224,256-270` | C-traces describe model observations; H-traces hold repeated hardware observations (or legacy architectural debug values). No cache/timing observation exists here, so no HTrace is produced. |

B3.4b/f fixtures additionally exercise deliberate wrong paths and memory rollback
in Unicorn. Native execution must follow architectural branch semantics. They
are not run by this utility. The smaller B3.4a body already suffices to establish
the architectural boundary without admitting computed pointers or random code.

## Fixed fixture and independent oracle

`arm64_architectural_fixture.S` is assembled by GNU AArch64 binutils. Its 36-byte
read-only object contains B3.4a's 32-byte body followed by `RET X30`:

```asm
cmp x0, #0
b.eq taken
mov x1, #11
b join
taken: mov x1, #22
join:  ldr x2, [x20], #0
add x3, x1, x2
str x3, [x20], #0
ret
```

Tests establish equality to bytes `[12,44)` of the actual generator/assembler/ELF
result from `tests/arm64/asm/contract_slice.asm`. The start/end measurement
placeholders and model exit NOP are omitted, not expanded into kernel macros.
All intra-body branches retain their relative displacements. The assembled
fixture and trampoline have no relocations. Neither loads literals nor calls an
external function. The executable is linked normally; only the fixture's raw
bytes are copied into the new executable mapping.

| X0 selector | Initial main word | Final X0 / X1 / X2 / X3 | NZCV | Main word |
| --- | --- | --- | --- | --- |
| 0 | 7 | 0 / 22 / 7 / 29 | `0x60000000` | 29 |
| 1 | 7 | 1 / 11 / 7 / 18 | `0x20000000` | 18 |
| 2 | 19 | 2 / 11 / 19 / 30 | `0x20000000` | 30 |

The original three cases remain regression inputs, now provided through the
adapter rather than embedded in C. Additional B3.5e cases are:

| Input index | Selector | Initial word | X1 / X2 / X3 and stored word | NZCV |
| --- | --- | --- | --- | --- |
| 0 | 0 | 7 | 22 / 7 / 29 | `0x60000000` |
| 1 | 1 | 7 | 11 / 7 / 18 | `0x20000000` |
| 2 | 2 | 19 | 11 / 19 / 30 | `0x20000000` |
| 3 | 0 | 7 | 22 / 7 / 29 (identical input) | `0x60000000` |
| 4 | 1 | 18 | 11 / 18 / 29 | `0x20000000` |
| 5 | 0 | `2^64-1` | 22 / `2^64-1` / 21 (wrap) | `0x60000000` |
| 6 | `2^64-1` | 5 | 11 / 5 / 16 | `0xa0000000` |
| 7 | 0 | 41 | 22 / 41 / 63 | `0x60000000` |

Input 7 also initializes each remaining main word `i` to `i+100`, for `i=1..511`.
All those bytes must survive execution. Inputs 0/4 have the same stored result
and final main memory but different complete register/flag states. This supported
input-to-complete-state map is injective: X0 retains the selector, X2 retains
the original first word, and the remaining main bytes are preserved. Different
serialized inputs cannot produce identical complete reported state in this
subset; an equal stored word is not asserted to be full architectural equivalence.

X4-X7 start and remain zero. The body reads X0 and X20, writes X1-X3 and NZCV,
loads eight bytes at main, and stores eight bytes at main. Other bytes in the
logical 4096-byte main payload retain their initial values. CMP supplies the final flags; MOV,
ADD, load, store, and branch do not overwrite them. The test's arithmetic oracle
is independent of both native execution and Unicorn. There are no expected
architectural output values in the C runner.

## Restricted input transport and ownership (B3.5e)

The sole accepted invocation is `--input-format rvzr-inputdata-raw-v1`, with
one **12288-byte** raw actor fragment on stdin, followed by EOF. This tag names
the experiment's restricted transport; it is not a kernel ABI or a new RDBF
version. No automatic format detection is used. All intervals below are half-open
and relative to the start of the raw fragment, not to a runtime mapping base.

| Raw byte range | Meaning | Accepted values |
| --- | --- | --- |
| `[0,4096)` | Main payload, 512 little-endian uint64 words | All byte patterns |
| `[4096,8192)` | Faulty payload | Zero only; no faulty mapping is provided |
| `[8192,8200)` | GPR slot 0, X0 branch selector | All uint64 values, never dereferenced |
| `[8200,8240)` | X1-X5 initial slots | Zero only |
| `[8240,8248)` | NZCV input slot (not X6) | Zero only |
| `[8248,8256)` | SP input slot (not X7) | Zero only; host stack is owned by the trampoline |
| `[8256,8512)` | SIMD initialization | Zero only |
| `[8512,12288)` | Serialized padding | Zero only |

The Python adapter requires the actual one-actor `InputData` dtype, little-endian
payloads, and zero unsupported fields. It returns immutable owned `bytes` equal
to `InputData.save()` output and to the fragment after the 32-byte one-actor RDBF
header/metadata from `save_input_sequence_as_rdbf()`. Existing serializers are
unchanged. RDBF files, multiple fragments/actors, format paths, unknown versions,
truncation, excess bytes and nonzero unsupported fields are rejected by C too.

C reads at most 12289 bytes into a bounded stack buffer, handles short reads and
requires EOF with a two-second input deadline. Only complete valid input is
copied to a separate stack snapshot, **before any result/data/code allocation or
fork**. Caller must supply a sole-consumer pipe or redirected file and close
stdin; the outer process-group timeout still bounds blocking OS operations.
The snapshot is inherited privately by the execution child, never borrowed from
Python, a file mapping, or external storage. Both buffers have automatic storage
duration, including on rejection. There are no input allocation/free failure paths.

The full main payload is copied to an owned RW page, while remaining bytes of
a 16K data page stay zero. X0 comes from the validated selector bytes; X1-X7 and
NZCV are initialized to zero by the unchanged trampoline. All addresses, SP, LR
and code bytes originate in the component. Scalar data may numerically resemble
an address but is never used as a pointer. Main data is never copied into code.
This is not a general input adapter for arbitrary generated/boosted inputs:
nonzero excluded fields are rejected, not silently dropped.

## Safety and lifetime review

* Only Linux little-endian AArch64 is accepted for the actual executable. Runtime
  page sizes 4096 and 16384 are supported; other sizes fail explicitly. Logical
  main remains 4096 bytes. Each private allocation reserves three kernel pages:
  `PROT_NONE` guard, payload page, `PROT_NONE` guard. At 16K, trailing bytes of
  the middle data page are padding, **not another logical input region**.
  Guards do not protect individual subpage logical boundaries. This is not
  activation of Revizor's passive candidate 16K sandbox profile.
* Data is RW and never executable. Code goes from inaccessible to RW for the
  copy, through GCC `__builtin___clear_cache`, then RX. No RWX request, writable
  executable alias, fixed virtual address, private PTE update, or protection
  fallback is used. `READ_IMPLIES_EXEC` is queried and rejected, not changed.
  A denial of executable memory or cache publication is a failure.
* The ABI trampoline initializes X0-X7 and NZCV and sets X20 to owned main memory.
  Other caller-saved registers are not general-purpose input state; the fixed
  body does not read them. X19 retains the result pointer. FP/LR and X19/X20
  are saved/restored with a 32-byte frame; SP remains 16-byte aligned. X18,
  X21-X28 and SIMD are untouched. The fixed body leaves SP, X19, X20 and LR
  intact, so RET reaches the trampoline, which captures X0-X7 and NZCV before
  restoring host state. There is no sandbox-stack switch or signal recovery.
* The native fixture's only data write is `[main,main+8)`. Trampoline writes
  target its own 32-byte frame and its C result object (80 bytes, offsets checked
  by `_Static_assert`). It never writes executable memory after publication.
  Tests also emulate the real trampoline with sentinel X18-X29, LR/SP and Q8-Q15
  to check preservation; this supplements source inspection, not native evidence.
* Each accepted input gets a fresh child and fresh data/code reservations. The parent owns
  one small shared result mapping, prefaulted before fork, and reads it only
  after a successful wait/exit and completed cleanup. Both reservations are
  released even after partial setup failure. Failed releases are failures;
  child process exit releases any residual mappings. No retry follows failure.
* Parent wait uses a 2-second monotonic deadline and kills/reaps only its owned
  child on timeout. Signals, nonzero exits, setup errors and incomplete results
  are failures. There is no instruction-fault continuation. Parent termination
  by an external agent is outside this internal deadline; use the outer timeout
  below for process-group cleanup. A process stuck indefinitely in kernel exit
  cannot be given a strict userspace time bound.
* This is reviewed trusted code, not an adversarial-code sandbox: a child still
  has process credentials and inherited descriptors. No safety argument here
  permits arbitrary/generated instructions, SP/LR corruption, actor transitions,
  faults, privileged instructions, or kernel-like fault/permission semantics.

The ABI obligations follow [AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst).
Cache publication uses GCC's documented
[`__builtin___clear_cache`](https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html),
rather than a guessed cache-line stride. Linux
[`mprotect`](https://man7.org/linux/man-pages/man2/mprotect.2.html) operates on
kernel-page-aligned mappings. BTI/PAC/SELinux or other policy changes on a future
target require validation; this utility does not disable system protections.

## Native build, execution and CI

From the repository root on native AArch64 Linux, without sudo for execution:

```bash
python - <<'PY'
from pathlib import Path
import numpy as np
from rvzr.tc_components.test_case_data import InputData
from tools.arm64_userspace_input import encode_input
input_ = InputData(1)
input_.view(np.uint8).fill(0)
input_[0]['gpr'][0] = 0
input_[0]['main'][0] = 7
Path('architectural-input.raw').write_bytes(encode_input(input_))
PY
gcc -std=c11 -O2 -Wall -Wextra -Werror \
  tools/arm64_architectural_smoke.c tools/arm64_architectural_fixture.S \
  -o /tmp/rvzr-architectural-smoke
timeout --signal=TERM --kill-after=2s 10s \
  /tmp/rvzr-architectural-smoke --input-format rvzr-inputdata-raw-v1 \
  < architectural-input.raw > architectural-state.jsonl
# Check the exit status before using output; preserve partial output on failure.
```

Successful stdout has three JSON Lines: metadata (kernel, page size, fixture
and input-format identity), one `architectural_state`, and a final `complete`
record with `cases:1`. The `input` ordinal is always zero within this process;
external campaign ordering is the caller's responsibility.
Each state records input identity, X0-X7, NZCV, return-point SP modulo 16,
historical data/code base addresses and `main_hex` (all 4096 bytes). Addresses
have already been unmapped when printed; they are diagnostic values, not live
allocation handles. No observation bitmap or trace encoding is synthesized.
Output is under 10 KiB. Any failure has a nonzero exit; ordinary caught failures
emit an `error` JSON record with stage, errno, signal, timeout and child exit.
An architectural-state record alone never implies successful completion. Output/pipe failures may
prevent an error record; always check exit status and the final complete record.
Parse integer fields without floating-point conversion: inputs/results can include
`UINT64_MAX`.

The existing **Verify fixed ARM64 userspace architectural execution (no kernel
module)** step in the existing `arm64-baseline` job runs:

```bash
set -euo pipefail
test "$(uname -m)" = aarch64
gcc --version
RVZR_REQUIRE_NATIVE=1 python -m unittest tests.unit_arm64_userspace_execution -v
```

It uses the already installed build-essential/binutils/Python dependencies. The
native test compiles the program with the flags above, checks the generated ELF
body before fixture execution, runs the three legacy inputs and eight new inputs
twice (**22 native fixture executions, 22 oracle comparisons, 22 sequential-model
comparisons**). It separately rejects **16 malformed payloads and 4 unsupported
argument/format requests** without executing the fixture. No arbitrary fuzz-generated case is
sent to the native component. Missing native execution is an error in CI.

On x86-64 WSL2 use `binutils-aarch64-linux-gnu` and the same unittest module,
without `RVZR_REQUIRE_NATIVE`. Twenty-three tests run; the actual native test skips.
`RVZR_ARM64_BINUTILS_PREFIX` can select an extracted cross-binutils installation.
Host tests include actual C input-reader/admission checks, production byte-parity
and sequential-model checks, mocked allocation/protection/release failures, and
owned-child exit/timeout checks. Mock invocation never executes any fixture bytes or produces
architectural measurements. 4K/16K arithmetic simulations do not verify native
mapping permissions. The fixture and ABI emulation use actual assembled bytes.

## Before future executor integration

Reuse the reviewed fixed fixture, runtime-page mapping mechanics, code publication,
bounded-child handling and architectural oracle unchanged on Fedora Asahi for
an initial test. Record its actual kernel/page size; do not infer compatibility
from macOS or Ubuntu. The fixed program needs no timer/PMU or CPU affinity.

Keep generation, `TestCaseProgram`, fixed `InputData` serialization, boosting,
contract model and analyser. A future loader needs an explicit supported subset
and validator, bounded relocation/exit translation, broader input-to-register and
memory semantics, preparation/allocation identity, and consistent model addresses.
Faulty pages, multiple actors, arbitrary pointers, host-ABI clobbering, faults and
speculation-sensitive instrumentation need separate safety designs. The existing
kernel's safety blockers remain unchanged.

An architectural-state result can support a later real architectural mismatch
check; it cannot serve as a cache HTrace. Before implementing `Executor.trace_test_case`
for relational leakage testing, independently validate a physical observer and
its noise/repetition/affinity behavior, define its real HTrace representation,
and synchronize model/hardware preparation. No fuzzer, factory, HTrace or analyser
integration is implemented here. This experiment establishes neither a cache
leak nor a Spectre vulnerability.
