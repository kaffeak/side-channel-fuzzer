# B3.4d: bounded generated ARM64 software campaign

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
| [generate_from_random_spec:581](../../rvzr/code_generator.py#L581) | Chooses an existing ISA spec and generates its operands. The test selects one existing MOV form in the public `non_memory_access_specs` pool; it does not replace this algorithm. |
| [ISA reduction:133](../../rvzr/isa_spec.py#L133), [parser vocabulary:480](../../rvzr/asm_parser.py#L480) | Normal register-blocklist reduction restricts random operands. The parser uses `instructions_unfiltered`, so the fixed template can still refer to protected registers and instruction forms outside the random pool. |
| [ARM printer:33](../../rvzr/arch/arm64/generator.py#L33), [sandbox pass:134](../../rvzr/arch/arm64/generator.py#L134) | Ordinary scalar register copies print/assemble directly. Template memory operations are skipped by the sandbox pass and therefore must already be bounded. This campaign does not claim to validate random memory instrumentation. |
| [ARM target:15](../../rvzr/arch/arm64/target_desc.py#L15), [minimal ISA](min_arm64.json) | MOV REG64,REG64 has one destination, one source and no implicit flags/memory operands. The shared tracker already recognizes full-width MOV overwrites. Current ARM tests exercise ISA loading, parsing and broad instruction assembly; they do not establish this RANDOM-to-boosted-execution combination. |

The random subset is deliberately **one instruction form**, `mov Xd,Xn`, with
both registers restricted to **X1/X2/X3/X5**. Register choices vary across seeds;
the instructions need not have different mnemonics to have distinct machine code.
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

## Exact campaign

[generated_contract_campaign.asm](asm/generated_contract_campaign.asm) derives
from B3.4b: eight random copies before pointer setup/CMP, four on each branch path,
then the same fixed B.EQ, loads/stores and join. There are **16 random instructions**
and **144 machine-code bytes** per case. The test validates every four-byte offset:
all random operands/widths/read-write roles, all fixed instruction names/operands,
branch topology, pointer construction, macros and NOPs. No unexpected instruction
or failing seed is silently filtered out.

Settings are one actor, legacy 4 KiB sandbox, `cond+ct`, nesting one, speculative
window 32, no handled faults and disabled coverage. The 8-byte memory accesses
are always main[0:8] or main[128:136]. Every retraced boost is checked for the
expected four CT memory observations, completed non-speculative state, no fault,
empty checkpoints, unchanged X0/X4 and the correct final main-region contents.

Seeds are the fixed tuple **1 through 8**; seed zero is intentionally excluded
because production treats it as a request for a random seed. Each seed generates
a primary and a repeat case using actual binutils. Repeat payload and generated
metadata must match. Diversity hashes cover `.data.main` instruction **bytes**,
not incidental ELF file metadata or filenames. The campaign requires more than
one distinct stream and reports the actual result: **eight** locally.

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

Different register-copy operands can have identical CT observations: CT records
PCs and memory addresses, not those register values. The campaign asserts machine
code diversity, not that each program must have a distinct C-trace. Within each
program the two branch directions do produce distinct traces.

## Reports and reproducible failures

The test prints a compact JSON summary. To retain successful assembly, ELF objects,
raw original/expanded inputs, code hashes, per-seed generated metadata, tainted
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

The 80 executions are 16 original taint runs, 16 repeat taint runs and 48 expanded
input retraces. These are actual model executions, not generated H-traces or
native host execution. Local validation used x86-64 WSL2, binutils 2.42 and
Unicorn 1.0.3. The standalone campaign took about half a second locally; this is
not a measurement of ARM64 or M3 performance.

Validation: **244 tests passed**: 221 focused/core/fuzzer tests including unchanged
B3.4a/B3.4b/B3.4c, 16 selected x86 model/taint tests, and seven ARM ISA/generator/parser
tests. Flake8, strict mypy, Pylint and whitespace checks also pass.

Native ARM64 needs no new packages beyond the existing GNU binutils and Python
dependencies. After local verification, run this module alongside B3.4a/B3.4b/B3.4c
on the native runner with Unicorn 2.1.4. B3.4c and this campaign still need that
verification; this task makes no CI edits.

The next small software step is to validate one additional scalar register form
and its operand/flag metadata before expanding this pool. Random memory generation
needs its own address-instrumentation/boundary tests. Native execution safety,
coherent executor/model preparation and a calibrated hardware observer remain
separate requirements before relational testing against real H-traces. This
campaign proves neither hardware leakage, physical predictor behavior, Spectre
detection nor Apple Silicon compliance.
