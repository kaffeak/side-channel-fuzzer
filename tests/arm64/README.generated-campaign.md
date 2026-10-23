# B3.4d/e: bounded generated ARM64 software campaign

```sh
python -m unittest tests.unit_arm64_generated_campaign -v
```

This runs eight seeds through real production template expansion, GNU AArch64
assembly, ELF/instruction metadata parsing, ARM64 Unicorn `cond+ct`, taints and
boosting. It never constructs an executor, creates H-traces or invokes hardware.
Only the CPU-identification/tool-lookup adapter from B3.4a is used. The earlier
sequential, conditional and taint tests remain unchanged.

## Generation audit and chosen subset

| Source | Meaning for this campaign |
| --- | --- |
| [CodeGenerator.create_test_case_from_template:202](../../rvzr/code_generator.py#L202) | Parses/caches a template, marks template instructions, expands RANDOM macros, runs ARM passes, prints/assembles and populates ELF metadata. A fresh generator with the same seed is used for a second generation to check reproducibility. |
| [_expand_template:320](../../rvzr/code_generator.py#L320) | Actual syntax is `.macro.random_instructions.N.M:`. It expands to N instructions with memory-selection probability M/N, rather than guaranteeing exactly M memory accesses. This test uses only `.8.0` and `.4.0`; it does not rely on undocumented extra arguments or sampling order. |
| [generate_from_random_spec:581](../../rvzr/code_generator.py#L581), [register operands:637](../../rvzr/code_generator.py#L637) | Chooses an existing ISA spec and generates its operands with their declared widths/read-write roles. The test selects MOV/ADD register forms in the public `non_memory_access_specs` pool; it does not replace this algorithm. |
| [ISA reduction:133](../../rvzr/isa_spec.py#L133), [parser vocabulary:480](../../rvzr/asm_parser.py#L480) | Normal register-blocklist reduction restricts random operands. The parser uses `instructions_unfiltered`, so the fixed template can still refer to protected registers and instruction forms outside the random pool. |
| [ARM printer:33](../../rvzr/arch/arm64/generator.py#L33), [sandbox pass:134](../../rvzr/arch/arm64/generator.py#L134) | Ordinary scalar register copies print/assemble directly. Template memory operations are skipped by the sandbox pass and therefore must already be bounded. This campaign does not claim to validate random memory instrumentation. |
| [ARM target:15](../../rvzr/arch/arm64/target_desc.py#L15), [minimal ISA:110](min_arm64.json#L110), [taint propagation:415](../../rvzr/model_unicorn/taint_tracker.py#L415) | MOV has one destination/one source; ADD has one destination/two sources. Both selected forms use REG64 operands without flag or memory operands. ADD's fixture flag metadata required the narrow correction described below. The shared tracker unions source dependencies; it retains old ADD-destination dependencies conservatively. |

The random subset is now exactly **two instruction forms**, `mov Xd,Xn` and
`add Xd,Xn,Xm`, with every register restricted to **X1/X2/X3/X5**. All operands
are 64 bits; the first is write-only and each remaining operand is read-only.
No shifts, immediate variants or implicit operands are selected. Every generated
instruction is checked for the absence of flag operands as well as its register
roles. Register choices vary across seeds.
X0 is protected as the branch selector, X4 as the derived pointer and X20 as the
main-region base. No random instruction changes flags, branches or touches memory.

The full production ISA vocabulary remains available to the fixed template.
The test-only random pool excludes the immediate MOV form, including its signed
immediate range; it does not assume that every such operand assembles as MOV.
Conditional operands, SIMD, system registers, privileged instructions, indirect
branches, faults and actor transitions are excluded before choosing any seed.
Generic conditional-flag generation still has an explicit NotImplementedError
([code_generator.py:725](../../rvzr/code_generator.py#L725)); no broader generator
port or metadata repair is attempted here.

### B3.4e ADD validation and isolated fixture correction

Both candidate ADD/EOR register forms in the available minimal ISA declared flag
writes inappropriate for the printed, non-S operation. B3.4e selects **ADD only**;
it does not silently accept that metadata or normalize it in the test pool.

A new assembled regression inserts `add x3,x1,x2` between CMP and B.EQ in an
owned copy of B3.4b. Before correction, real Unicorn preserved NZCV and computed
7+9=16, but the production taint result omitted X0. The test failed at
`assertTrue(mask[0])`: the fixture's false flag writes caused the tracker to
replace CMP's X0 dependency before observing the branch. The tracker reads the
FlagsOp operation list regardless of its generic src/dest booleans.

The only ISA change removes the erroneous implicit FlagsOp from the **64-bit,
three-register ADD entry** ([min_arm64.json:110](min_arm64.json#L110)). No generator,
parser, assembler, decoder, taint-engine or rollback code changes are needed.
Other ADD variants and EOR metadata are not corrected or validated by this stage.

The regression also redirects the fixed join ADD's destination to X5 so X3
retains the inserted ADD result through completion. It executes three inputs
under each of `seq+ct` and `cond+ct`:

| X0 | Initial X1 | Initial X2 | Final X3 from inserted ADD | NZCV at subsequent load(s) |
| ---: | ---: | ---: | ---: | --- |
| 0 | 7 | 9 | 16 | 0x60000000 |
| 1 | 2^64-1 | 1 | 0 | 0x20000000 |
| 1 | 7 | 9 | 16 | 0x20000000 |

The zero sum must not set Z: this is ADD, not ADDS. Real Unicorn read hooks witness
X3/NZCV and X5=0, once for sequential execution and twice for conditional execution.
The wrong-path join ADD changes X5 to 18 or 41; its restoration to zero before the
correct-path load verifies actual rollback. Final X5 is 41/18 on the correct path.
X0 remains tainted, while X1/X2 are untainted under CT because this variant's
addresses do not depend on their values. The last two inputs produce different
final architectural X3 values but identical typed C-traces. This is six additional
model executions, separate from the 80-execution generated campaign.

## Exact campaign

[generated_contract_campaign.asm](asm/generated_contract_campaign.asm) derives
from B3.4b: eight random register operations before pointer setup/CMP, four on each branch path,
then the same fixed B.EQ, loads/stores and join. There are **16 random instructions**
and **144 machine-code bytes** per case. The test validates every four-byte offset:
all random operands/widths/read-write roles, all fixed instruction names/operands,
branch topology, pointer construction, macros and NOPs. No unexpected instruction
or failing seed is silently filtered out.

Settings are one actor, legacy 4 KiB sandbox, `cond+ct`, nesting one, speculative
window 32, no handled faults and disabled coverage. The 8-byte memory accesses
are always main[0:8] or main[128:136]. Every retraced boost is checked for the
expected four CT memory observations, completed non-speculative state, no fault,
empty checkpoints, unchanged X0/X4, correct final X1/X2/X3/NZCV and main-region contents.

Seeds are the fixed tuple **1 through 8**; seed zero is intentionally excluded
because production treats it as a request for a random seed. Each seed generates
a primary and a repeat case using actual binutils. Repeat payload and generated
metadata must match. Diversity hashes cover `.data.main` instruction **bytes**,
not incidental ELF file metadata or filenames. The strengthened assertion now
requires **eight distinct streams**, and both instruction forms across the seed set.

Each case has two deterministic `InputData` originals, X0=0 and X0=1. Other bytes
start zero except main[0]=seed+7 and main[16]=seed+19. Thus both branch directions
are covered with 16 distinct original serialized inputs across the campaign.
Inputs are saved through the existing raw-input API; model execution uses the
normal in-memory test-case/InputData interfaces, not sysfs or kernel upload parsing.

The public `trace_test_case_with_taints()` API executes both originals, then
executes them again to compare typed traces and taint masks. The production data
generator uses seed **1000 + 10 * program_seed**, entropy 8, special-value probability
0 and three inputs per class. Its output is `[A,B,A',B',A'',B'']`. Every element,
including A/B, is then separately executed through `trace_test_case()` and compared
using its full typed trace against its own parent's trace. Tainted words must
remain equal; added inputs must also change some untainted words. Original input
bytes must remain unchanged. No fast C-trace reuse is used.

Different copy/arithmetic operations can have identical CT observations: CT
records PCs and memory addresses, not register values. In this campaign random
results cannot affect the protected selector/pointers, and fixed MOV/LDR/join
instructions determine the later store values and X3. Scratch X5 may vary but
is not a CT observation. The campaign asserts machine-code diversity without
claiming new architectural-result or CT diversity from adding a mnemonic. The
separate ADD regression demonstrates architectural-result diversity explicitly.
Within every campaign program the two branch directions still produce distinct traces.

## Reports and reproducible failures

The test prints a compact JSON summary. To retain successful assembly, ELF objects,
raw original/expanded inputs, code hashes, per-seed instruction frequencies and
generated operand roles/widths/flag metadata, exact tainted
word indices and all independently computed traces, select a **new absolute** path:

```sh
RVZR_ARM64_CAMPAIGN_OUTPUT=/tmp/my-new-arm64-campaign \
  python -m unittest tests.unit_arm64_generated_campaign -v
```

It refuses to overwrite an existing output directory. On any generation,
assembly, validation, model or boost failure, it stops at that seed and copies
the available artifacts/report to a fresh `/tmp/rvzr-arm64-campaign-failure-*`
directory, reporting its path and the original exception. Active boosted-input
identity is recorded before comparison. There are no retries with substitute
seeds, skips, mocked observations or success classifications after errors.

Production template generation stores relative `generated.*` paths; the test
isolates each generation directory and loads each primary object from that
directory. No production path behavior is changed.

## Local results and native follow-up

| Count | Result |
| --- | ---: |
| Seeds / distinct primary machine-code streams | 8 / 8 |
| Successful assembly/ELF generations, including repeat checks | 16 |
| Original inputs | 16 |
| Added boosted inputs | 32 |
| Expanded input instances, including originals | 48 |
| Successful per-input model executions / independently computed C-traces | 80 / 80 |
| Boost-to-parent trace mismatches | 0 |

Static instruction frequencies below count only the 128 primary random
instructions, excluding fixed template instructions and repeat generations:

| Seed | MOV | ADD |
| ---: | ---: | ---: |
| 1 | 7 | 9 |
| 2 | 8 | 8 |
| 3 | 6 | 10 |
| 4 | 7 | 9 |
| 5 | 9 | 7 |
| 6 | 11 | 5 |
| 7 | 13 | 3 |
| 8 | 8 | 8 |
| Total | **69** | **59** |

B3.4d's earlier MOV-only baseline used the same eight seeds and campaign size.
B3.4e extends its pool; all earlier B3.4a/b/c regression files and the campaign
template remain unchanged. The new isolated ADD regression tests the fixture
correction independently of the mixed random pool.

The 80 executions are 16 original taint runs, 16 repeat taint runs and 48 expanded
input retraces. These are actual model executions, not generated H-traces or
native host execution. Local validation used x86-64 WSL2, binutils 2.42 and
Unicorn 1.0.3. The standalone campaign took about half a second locally; this is
not a measurement of ARM64 or M3 performance.

Validation: **245 tests passed**: 222 focused/core/fuzzer tests including unchanged
B3.4a/B3.4b/B3.4c, 16 selected x86 model/taint tests, and seven ARM ISA/generator/parser
tests. Flake8, strict mypy, Pylint and whitespace checks also pass.

Native ARM64 needs no new packages beyond the existing GNU binutils and Python
dependencies. After local verification, run this module alongside B3.4a/B3.4b/B3.4c
on the native runner with Unicorn 2.1.4. B3.4a/b/c have passed natively; this mixed
campaign and the new ADD regression still need native verification. No CI edits
are made here.

For meaningful CT diversity, the next small software experiment is a **fixed**
template where ADD feeds an explicitly masked offset selecting main+0 or main+128.
That would test both ADD sources as address dependencies and boost equivalence;
it must precede any random memory generation. Random memory instrumentation still
needs separate boundary tests. Do not expand the pool further just to add mnemonics.
Determining a safe native M3 hardware-execution route remains the larger priority.
Native execution safety, coherent executor/model preparation and a calibrated hardware observer remain
separate requirements before relational testing against real H-traces. This
campaign proves neither hardware leakage, physical predictor behavior, Spectre
detection nor Apple Silicon compliance.
