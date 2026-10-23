# B3.4c: ARM64 conditional-speculation taints and boosting

Run the new regression and preserve both earlier slices:

```sh
python -m unittest tests.unit_arm64_taint_boosting \
  tests.unit_arm64_contract_slice tests.unit_arm64_conditional_contract -v
```

Use the same native GNU binutils or cross-tool prefix as
[B3.4a](README.contract-slice.md). No new Python dependency or kernel interface is
needed. Local validation used x86-64 WSL2, GNU binutils 2.42 and Unicorn 1.0.3.
The new tests and B3.4b still need native AArch64/Unicorn 2.1.4 validation; the
previous native B3.4a result does not establish their correctness. CI is unchanged.
The existing native job can eventually invoke the command above.

## Pipeline and dependency semantics

| Production interface inspected | Verified meaning / scope |
| --- | --- |
| [Model interface:61](../../rvzr/model.py#L61), [Unicorn taint API:292](../../rvzr/model_unicorn/model.py#L292) | The public API is `trace_test_case_with_taints(inputs, nesting)`, returning `(List[CTrace], List[InputTaint])`. There is no `get_taints()` method in this tree. `trace_test_case()` explicitly disables tracking ([model.py:280](../../rvzr/model_unicorn/model.py#L280)). |
| [execution loop:367](../../rvzr/model_unicorn/model.py#L367) | Resets execution/services for each input, executes real Unicorn instructions, then calls the tracker's singular `get_taint(n_actors)` at line 397. Taints are not reconstructed from a C-trace afterward. |
| [tracking:130](../../rvzr/model_unicorn/taint_tracker.py#L130), [observation callbacks:227](../../rvzr/model_unicorn/taint_tracker.py#L227), [CTTracer:194](../../rvzr/model_unicorn/tracer.py#L194) | Tracks operand dependencies. CT taints address registers for memory observations and the pseudo-PC `RIP` for observed control-flow instructions. Loading a value alone does not expose that value under CT. A branch controller is not automatically tainted independently of observation/dependency handling. |
| [static operand handling:359](../../rvzr/model_unicorn/taint_tracker.py#L359), [propagation:415](../../rvzr/model_unicorn/taint_tracker.py#L415) | Register, flag and dynamic memory dependencies are shared across ISAs. Source dependencies propagate to destinations, then observed labels are expanded to input dependencies. The prior generic parser ignores CondOp. |
| [ARM target:30](../../rvzr/arch/arm64/target_desc.py#L30), [condition flags:100](../../rvzr/arch/arm64/target_desc.py#L100), [Unicorn register mapping:201](../../rvzr/arch/arm64/target_desc.py#L201) | W/X registers normalize to `Rn`; PC normalizes to `RIP`. Shared flag labels CF/ZF/SF/OF represent ARM C/Z/N/V. They all map to the single serialized NZCV word, `gpr[6]`. These names do not mean the engine reads x86 EFLAGS on ARM. |
| [checkpoint/rollback:103](../../rvzr/model_unicorn/taint_tracker.py#L103), [speculator checkpoint:174](../../rvzr/model_unicorn/speculator_abc.py#L174) | Deep-copies dependency state. Rollback restores dependencies but deliberately retains accumulated observed taints, including transient observations. Per-input reset clears checkpoints, dependencies and accumulated taints. |
| [InputTaint:227](../../rvzr/tc_components/test_case_data.py#L227), [conversion:280](../../rvzr/tc_components/test_case_data.py#L280) | One Boolean per input uint64 word, not one Boolean per byte. Dynamic memory dependencies are rounded to eight-byte words; legacy sandbox offsets are translated into serialized-input indices. No 16 KiB runtime layout is used. |
| [DataGenerator.generate_boosted:72](../../rvzr/data_generator.py#L72) | Generates random candidates using the existing generator and copies **tainted** words from the originals. Untainted words may change; not every untainted word must change. Seed state is reset for repeatable boosting. Order is `[A,B,A',B',A'',B'']` for two inputs and three members per class. Padding remains subject to normal generator initialization. |
| [round boosting:226](../../rvzr/fuzzer.py#L226), [C-trace collection:244](../../rvzr/fuzzer.py#L244) | The actual fuzzer calls the taint API and shared booster. Fast tracing can reuse original C-traces without executing boosts; the regression disables that shortcut and executes every boosted input. The existing `taint_mistake` stage at line 164 can also force retracing. |
| [x86 taint tests](../x86_tests/unit_taint_tracker.py), [fuzzer tests](../unit_fuzzer.py) | Existing x86 tests exercise real dependency tracking. Existing fuzzer tests mostly mock model/boosting results. The new round-manager test uses a real model and data generator; only the fuzzer container and hardware executor boundary are mocked. |

The bridge added in [taint_tracker.py:150](../../rvzr/model_unicorn/taint_tracker.py#L150)
is deliberately small: for ARM `b.` it derives flag reads from the actual CondOp
and target condition table, and marks the tracked PC as a destination. It changes
only per-instruction tracking state, not the instruction object, flags table,
branch decoder, generated bytes, C-trace observation rules or execution semantics.
It composes with the existing dependency and checkpoint implementation.

## Reproduced failure before correction

The real B3.4b fixture compared X0 with zero, but its branch metadata contained a
CondOp and a **read-only** implicit PC, with no flag-read operand
([min_arm64.json:296](min_arm64.json#L296)). Consequently the shared tracker did
not connect CMP's X0 dependency to an observed PC.

Before correction, `seq` reported only `gpr[4]` for X0=0 and nothing for X0=1;
`cond` reported only `gpr[4]` for both inputs. The new branch regression failed
on that original implementation: `[1028] != [1024,1028,1030]`.

A separate bounded production-booster run (seed 123, entropy 8,
special-value probability 0, two originals, three members per class) changed
X0=0 to 287762808899 and then 356482285651. Both boosted taken-branch inputs
changed their C-traces, under both `seq` and `cond`. This was real model execution,
not a synthetic expected trace or a hypothetical allocation/model mismatch.

## Bounded regression evidence

The six new tests reuse the unchanged B3.4b fixture through the real generator,
GNU assembly/ELF and model. Normal configuration is one actor, `seq` or `cond`,
`ct`, nesting 1, window 32, no handled faults and disabled coverage. Inputs are
zero-initialized, with X0=0/1, main word 0=7 and main word 16=19.

The corrected exact taints are:

| Fixture/configuration | X0=0 (taken) | X0=1 (fall-through) |
| --- | --- | --- |
| Original, seq | gpr[0], gpr[4], gpr[6] | gpr[0], gpr[6] |
| Original, cond | gpr[0], gpr[4], gpr[6] | gpr[0], gpr[4], gpr[6] |
| Address-dependent variant, seq | main[0], gpr[0], gpr[4], gpr[6] | gpr[0], gpr[6] |
| Address-dependent variant, cond | main[0], gpr[0], gpr[4], gpr[6] | main[0], gpr[0], gpr[4], gpr[6] |

These are conservative dependencies: initial X4 and NZCV remain tainted even
though this program overwrites them. Shared dependency cleanup only recognizes
certain overwrite patterns ([taint_tracker.py:458](../../rvzr/model_unicorn/taint_tracker.py#L458));
arithmetic/load destinations retain old dependencies, and flag dependencies retain
their own labels. This reduces boost freedom but does not justify removing those
taints or changing existing x86 semantics during this stage.

The address-dependent case is generated from an owned copy of the B3.4b template,
replacing its first ADD with:

```asm
ldr x4, [x20], #0
and x4, x4, #128
add x4, x20, x4
```

Every derived address is bounded to main+0 or main+128, regardless of input word
value. With main[0]=135, the CT memory entries (data-base-relative byte offsets) are:

| Configuration | X0=0 | X0=1 |
| --- | --- | --- |
| seq | 4096,4224,4224 | 4096,4096,4096 |
| cond | 4096,4096,4096,4224,4224 | 4096,4224,4224,4096,4096 |

Changing main[0] to 7 changes the taken-path address. For X0=1 it changes the CT
only when the taken path runs transiently under `cond`. The reported main[0]
taint is therefore exercised against an actual trace dependency.

The rollback observer delegates to the real tracker method and compares restored
register, flag and memory dependency dictionaries with the saved checkpoint.
It also verifies that the already-observed wrong-path main[0] dependency remains
tainted. Running the same model/input afterward with nesting 0 removes the
transient-only main[0]/X4 taints; returning to nesting 1 restores the original
results. Batches, repeated calls and tracking-disabled/enabled transitions agree,
with no residual checkpoints or mutation of earlier returned taint arrays.

The booster test uses two originals, three members per class, seed 123, entropy
8, and special-value probabilities **0 and the default 0.05**, for both contracts.
It checks exact copying of tainted words, unchanged originals and generator state,
idempotent output, and variation of untainted words against candidates from a
second real generator. Every one of the six boosted inputs is retraced and
matches its original's C-trace. This is bounded evidence, not a proof for every
ARM instruction or input distribution.

## Validation and next step

Local results: **243 tests passed**: 220 combined focused/core/fuzzer regressions
(including six new tests and unchanged B3.4a/B3.4b), nine existing x86 Unicorn
taint tests plus seven x86 model regressions, and seven ARM ISA/generator/parser
tests. Flake8 (100 columns), strict mypy for both changed Python files, Pylint
(10/10) and whitespace checks pass.

No general taint rewrite was needed. Demonstrated support is limited to one
actor, B.EQ, scalar bounded accesses, `ct` and one speculative level. CB/TB,
indirect control flow, other observation clauses, SIMD, faults, nested speculation
and multi-actor taints/boosting remain unvalidated. ARM SIMD input registers are
still absent from the Unicorn target. Generic CondOp flag generation also retains
an explicit NotImplementedError ([code_generator.py:725](../../rvzr/code_generator.py#L725));
this change does not pretend to complete that broader instruction-metadata path.

The next small step is a bounded, fixed-seed **template-generated software
campaign** using the existing RANDOM_* expansion
([code_generator.py:202](../../rvzr/code_generator.py#L202)), a small explicitly
validated instruction subset, fixed B.EQ control flow and bounded addresses.
Keep nesting at one and retrace every boosted input. Expand only after checking
generated operand/flag metadata and address instrumentation for that subset.
Do not begin with unrestricted ARM generation or fast C-trace reuse.

No generated instructions run on the host CPU. This work establishes software
contract-model/boosting behavior, not physical branch prediction, microarchitectural
leakage or Spectre detection. Kernel preparation/recovery and a calibrated hardware
observer remain separate prerequisites for connecting these traces to H-traces.
