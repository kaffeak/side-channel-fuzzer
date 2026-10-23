# B3.4b: deterministic ARM64 conditional-speculation slice

Run from the repository root:

```sh
python -m unittest tests.unit_arm64_conditional_contract tests.unit_arm64_contract_slice -v
```

The unchanged B3.4a `software_environment()` supplies temporary tool aliases and
synthetic CPU identification. Everything else uses production generation, GNU
assembly/ELF parsing, InputData, Unicorn execution and CTTracer. No kernel executor
is constructed. On x86-64 WSL2 install `binutils-aarch64-linux-gnu`, or select an
unpacked toolchain using `RVZR_ARM64_BINUTILS_PREFIX` as documented in
[B3.4a](README.contract-slice.md). Generated files stay in temporary directories.
Missing/broken tools fail explicitly.

## Audit and bounded correction

| Component inspected | Finding |
| --- | --- |
| [factory.py:119](../../rvzr/factory.py#L119), [ARM model selection:179](../../rvzr/factory.py#L179) | `seq`/`no_speculation` select SeqSpeculator. `cond`/`conditional_br_misprediction` select the dedicated ARM64CondSpeculator, not the x86 branch decoder. The tests actually execute `seq` and `cond`. |
| [ARM generator:33](../../rvzr/arch/arm64/generator.py#L33), [line parser:93](../../rvzr/arch/arm64/asm_parser.py#L93), [conditions:100](../../rvzr/arch/arm64/target_desc.py#L100) | Printer/parser represent B.cond using CondOp; normal template generation and metadata work for the fixture's `b.eq`. This is deterministic template generation, not a random campaign. |
| [ARM64CondSpeculator:211](../../rvzr/model_unicorn/speculators_basic.py#L211) | Recognizes B.cond, CBZ/CBNZ and TBZ/TBNZ. Reads NZCV for B.cond and the tested register for CB/TB. It checkpoints the correct continuation and redirects execution to the alternative path. |
| [checkpoint/rollback:96](../../rvzr/model_unicorn/speculator_abc.py#L96), [window/barrier handling:122](../../rvzr/model_unicorn/speculator_abc.py#L122), [checkpoint creation:174](../../rvzr/model_unicorn/speculator_abc.py#L174) | Saves Unicorn context, NZCV, continuation, window and taint dependencies; logs speculative stores and restores them in reverse. Nesting bounds checkpoint creation. Windows count dispatched instructions, not cycles. ARM barriers are `dmb`, `dsb`, `isb` ([target:221](../../rvzr/arch/arm64/target_desc.py#L221)). |
| [dispatcher:90](../../rvzr/model_unicorn/model.py#L90), [state machine:401](../../rvzr/model_unicorn/model.py#L401) | PC observation precedes speculation/stop handling. Memory observations arise from Unicorn memory callbacks. A stop while speculating rolls back; exits and faults also terminate speculative paths. Trace observations are deliberately not rolled back. |
| [ARM interpreter:131](../../rvzr/model_unicorn/interpreter.py#L131), [measurement macros:241](../../rvzr/model_unicorn/interpreter.py#L241) | No x86 instruction interpreter is used. A speculative measurement-end macro does not disable tracing. |
| [CTTracer:194](../../rvzr/model_unicorn/tracer.py#L194), [normalization:68](../../rvzr/model_unicorn/tracer.py#L68) | Records PC and read/write byte addresses, including transient accesses; normalizes code and data against their separate bases. Values are not CT observations. |
| [taint checkpoint/rollback:103](../../rvzr/model_unicorn/taint_tracker.py#L103), [trace API:280](../../rvzr/model_unicorn/model.py#L280) | Dependency checkpoints exist. This slice uses `trace_test_case()`, which disables taint tracking; it does not validate speculative input boosting. |
| [existing x86 speculative tests:282](../x86_tests/unit_model.py#L282), ARM model-preparation/lifetime tests | Existing shared rollback and x86 execution tests are useful regressions, but prior ARM constructor/checkpoint tests did not establish actual ARM branch execution. |

The initial real `cond` run of the B3.4a fixture failed with `KeyError: 23`:
the branch at offset 16 targeted offset 28, but decoded immediate 3 was used as
a byte offset from PC+4, producing 23. The new decoder regression also failed on
a backward branch before the production correction (`-1` versus expected `-8`).

The only production changes are in ARM64CondSpeculator: convert signed immediates
to byte displacements relative to the following instruction (`signed_imm * 4 - 4`),
and treat condition 15 (`b.nv`) as taken, matching actual single-step AArch64
Unicorn execution. After the displacement fix, the new test independently exposed
the former `b.nv` mismatch. No checkpoint, dispatcher or state-machine refactor
was required. A target equal to the following instruction has offset zero and
needs no misprediction; branch-to-self has offset -4 and is distinguishable.

The decoder oracle assembles 42 branch variants at four targets (backward, self,
next instruction, forward), then executes each in a separate, hook-free Unicorn
engine for one instruction. Five register values and all 16 NZCV combinations
give **13,440 comparisons**. CB/TB cases include W/X widths, bits 0/31/32/63,
X29/X30 and zero registers. This validates decoding, not full contract tracing
for every form. The full generated slice uses B.EQ only; the existing parser's
condition vocabulary does not include `nv`.

Other registered ARM clauses remain distinct from demonstrated support:
`bpas`, `seq-assist` and ARM delayed-exception handling have implementations but
are not execution-validated here. `cond-bpas` is inherited from the generic
factory table yet selects X86CondBpasSpeculator; its x86-only constructor rejects
ARM64. It must not be advertised as ARM conditional-plus-store-bypass support.
X86-only fault/value-speculation clauses are not thereby available on ARM.

## Actual experiment and C-traces

[conditional_contract_slice.asm](asm/conditional_contract_slice.asm) sets
X4 = X20 + 128, compares X0 with zero, and executes one of two paths:

| Path | Operations | Main-region bytes |
| --- | --- | --- |
| Fall-through | X1=11; load X2; store X1; CMP X1,12; jump to join | [0,8) |
| Taken | X1=22; load X2; store X1; CMP X1,22 | [128,136) |
| Join | X3 = X1 + X2 | None |

Owned input bytes start at zero, except X0 (0 or 1), main word 0 (7), and main
word 16 (19). Input bytes remain unchanged. Synthetic data/code bases are
0x109000/0x200000; X20 is main at 0x10a000. The active legacy 4 KiB layout is used.
Execution configuration is `unicorn`, `ct`, no handled faults, coverage disabled,
nesting 1 and maximum speculative window 32. Both inputs run twice in the same
models and produce identical traces on repetition.

Below, unprefixed numbers are normalized **PC** entries; `mN` is a normalized
**memory** entry relative to data base, not an instruction PC or cache-set index:

```text
P = [12,16,20]
F = [24,28,m4096,32,m4096,36,40]
T = [44,48,m4224,52,m4224,56]
J = [60,64]
E = [76]

X0=0: seq+ct = P + T + J
      cond+ct = P + F + J + E + T + J
X0=1: seq+ct = P + F + J
      cond+ct = P + T + J + E + F + J
```

E is the final generated NOP observed while still speculating. The existing
layout computes exit as the section's last byte ([sandbox.py:222](../../rvzr/sandbox.py#L222));
the NOP at 76 executes before stopping beyond that boundary. In architectural
execution the measurement-end macro at 64 disables subsequent tracing.

An independent Unicorn memory hook confirms two eight-byte accesses (read/write)
on the wrong path with speculation active, followed by the correct path's two
accesses with speculation inactive. The observer calls the original rollback
method: immediately before rollback the wrong-path register results, flags and
store are visible; immediately afterward X1/X2/X3, NZCV and all 4096 main bytes
match the branch checkpoint, and execution resumes at 44 or 24 as appropriate.
No speculative fault is needed. Both models then agree on committed state:

| X0 | Final X1 | X2 | X3 | NZCV | Committed store |
| ---: | ---: | ---: | ---: | --- | --- |
| 0 | 22 | 19 | 41 | 0x60000000 | main[128:136] = 22 |
| 1 | 11 | 7 | 18 | 0x80000000 | main[0:8] = 11 |

Additional regressions set nesting to zero (sequential trace), limit the window
to two instructions (wrong-path MOV/load execute, store does not), and insert
ISB before the join ADD (wrong-path ADD does not execute). Stop-instruction PCs
are still observed because dispatch traces the PC before deciding to stop.
A PC observation alone is not proof that all instruction effects executed.

## Validation and limits

Local x86-64 WSL2 validation used GNU binutils 2.42 and Unicorn 1.0.3:
four new tests plus B3.4a pass; 199 combined focused/core regressions, seven
existing ARM ISA/generator/parser tests and seven existing x86 Unicorn tests
pass (**213 tests total**, including the four new tests).

Flake8 (100-column limit), Pylint (10/10) and `git diff --check` pass. The new
test module passes strict mypy. Checking the existing speculator module uses
`--strict --no-warn-unused-ignores --disable-error-code=import-untyped` to
accommodate its pre-existing Unicorn imports/type ignores; unrestricted strict
mypy reports those existing typing issues. No typing cleanup is included.

Native ARM64 needs no new dependencies beyond the existing binutils and Python
dependencies. The current native workflow explicitly lists test modules, so a
future workflow edit must add this module to run it there; CI is unchanged here.
Native execution is outstanding, particularly with the separately selected
Unicorn version on ARM64. It is software emulation, not M3 hardware measurement.

This demonstrates a minimal conditional-speculation contract, not broad ARM64
speculation correctness, a real predictor, Spectre detection or contract
compliance. Fault-driven/nested speculation, SIMD, multi-actor execution and
taint/boosting semantics remain outside this slice. In particular, the shared
store undo log currently saves **eight bytes regardless of store width**
([speculator_abc.py:157](../../rvzr/model_unicorn/speculator_abc.py#L157)); the
eight-byte stores tested here do not validate rollback of wider stores. The
decoder checks are finite and do not cover every immediate/register encoding.

The next small model task is an ARM branch-dependent taint/boosting regression,
before progressing to bounded generated speculative campaigns. Connecting to
H-traces still requires safe native preparation/execution/recovery, coherent
model/executor allocations, and a calibrated hardware observer. These tests
establish none of those kernel or physical prerequisites.
