# B3.4f: bounded ADD-derived address dependencies

This deterministic software experiment uses the existing template generator,
GNU AArch64 assembler/ELF loader, Unicorn model, taint tracker and data generator.
It does not execute generated instructions on the host processor, collect hardware
traces, test physical speculation, or validate Apple M3 compatibility. The
B3.4a–e tests/fixtures are unchanged except for the narrow ISA metadata correction
described below. No production Python, kernel, layout or CI code changes.

The source program is [asm/add_address_contract.asm](asm/add_address_contract.asm);
the regression is [../unit_arm64_add_address.py](../unit_arm64_add_address.py).
There is one actor using the active legacy 4 KiB layout, `seq+ct` or `cond+ct`,
nesting one, and a 32-instruction speculative window. A reset check also uses
the same conditional model with nesting zero.

## Program and metadata

After `cmp x0, #0`, the address calculation is:

```asm
add x4, x1, x2
and x4, x4, #128
add x4, x20, x4
b.eq .computed
```

Thus `d = (((X1 + X2) mod 2^64) & 128)` and `X4 = main_base + d`.
For every 64-bit input pair, `d` is 0 or 128. All memory operations are
eight-byte, aligned loads/stores within `[main_base, main_base + 4096)`.
X0 selects the path independently; X1/X2 are never overwritten. X20 is the
model-initialized main pointer. X4 is calculated before either path executes.

The fallthrough path loads from main offset 0, stores 11 there, and compares
11 with 12. The computed path loads from offset `d`, stores 22 there, and
compares 22 with 22. Both join at `add x3, x3, x5`. X5 holds the loaded word;
X3 holds the path marker plus that word modulo 2^64. The CT observes PCs and
memory **byte addresses**, not these loaded/stored values.

The test checks the parsed ADD/AND operands: 64-bit destination write, two
64-bit sources (the last AND operand is an immediate), no implicit operands,
and no flags operand. `#128` is accepted by the real logical-immediate assembler.
ADD register metadata was already corrected in B3.4e.

Before this change, the minimal ISA's **64-bit immediate AND form** incorrectly
declared implicit NZCV writes. The new real-execution regression first failed:

```text
seq, X0=0, X1=0, X2=0:
AssertionError: CMP's branch-selector dependency must survive AND
```

Actual memory-hook observations had already verified that NZCV remained
`0x60000000` through the non-S ADD/AND/ADD chain, and full traces and architectural
state matched the independent oracle. The tracker nevertheless omitted X0 from
its taint mask. Removing only that AND form's implicit FLAGS operand fixes this
reproducer. Other ISA forms are not certified by this experiment; remaining
non-S flag metadata in the minimal ISA requires a separate bounded audit before use.
The original failure log for this run is `/tmp/rvzr-b34f-before-and-fix.log`.

## Inputs and actual observations

Each input is explicitly byte-zeroed, then main word 0 is set to 7 and main
word 16 (byte offset 128) to 19. Initial X3/X4/X5/NZCV are zero.
Each pair is tested with X0=0 and X0=1:

| Pair | X1 | X2 | d | Meaning |
| --- | ---: | ---: | ---: | --- |
| A | 0 | 0 | 0 | Baseline |
| B | 128 | 0 | 128 | Change X1 only |
| C | 0 | 128 | 128 | Change X2 only |
| D | 64 | 64 | 128 | Different sources, same address as B/C |

Data allocation base is `0x109000`, main is `0x10a000`, and code is `0x200000`.
CT data addresses are normalized to the **data allocation base**: main offset
0 is `m4096`, offset 128 is `m4224`. These are byte addresses, not cache-line
numbers or trace bitmap bits.

| Configuration | X0 | Actual memory event order (read, write pairs) |
| --- | ---: | --- |
| seq | 0 | architectural `m(4096+d), m(4096+d)` |
| seq | 1 | architectural `m4096, m4096`; computed pointer unobserved |
| cond | 0 | transient `m4096, m4096`, then architectural `m(4096+d), m(4096+d)` |
| cond | 1 | transient `m(4096+d), m(4096+d)`, then architectural `m4096, m4096` |

Changing A to B or C changes the **complete typed CT** whenever the computed
address is observed. These are the negative controls for source preservation.
B/C/D have identical full traces within each configuration/direction. For
seq/X0=1 all four pairs have identical traces. Direction is distinguished by
instruction PCs even when both paths happen to access offset zero.

## Complete typed traces

Here `pN` abbreviates `CTraceEntry("pc", N)` and `mN` abbreviates
`CTraceEntry("mem", N)`. Every observation is shown, in order. B/C/D share the
`d=128` rows. PC offsets refer to the assembled actor section, not source lines.

```text
seq X0=0 d=0:
p12 p16 p20 p24 p28 p52 p56 m4096 p60 m4096 p64 p68 p72
seq X0=0 d=128:
p12 p16 p20 p24 p28 p52 p56 m4224 p60 m4224 p64 p68 p72
seq X0=1 d=0 or 128:
p12 p16 p20 p24 p28 p32 p36 m4096 p40 m4096 p44 p48 p68 p72

cond X0=0 d=0:
p12 p16 p20 p24 p28 p32 p36 m4096 p40 m4096 p44 p48 p68 p72 p84 p52 p56 m4096 p60 m4096 p64 p68 p72
cond X0=0 d=128:
p12 p16 p20 p24 p28 p32 p36 m4096 p40 m4096 p44 p48 p68 p72 p84 p52 p56 m4224 p60 m4224 p64 p68 p72
cond X0=1 d=0:
p12 p16 p20 p24 p28 p52 p56 m4096 p60 m4096 p64 p68 p72 p84 p32 p36 m4096 p40 m4096 p44 p48 p68 p72
cond X0=1 d=128:
p12 p16 p20 p24 p28 p52 p56 m4224 p60 m4224 p64 p68 p72 p84 p32 p36 m4096 p40 m4096 p44 p48 p68 p72
```

The generator inserts measurement macros and placeholder NOPs. PC72 is the
measurement-end macro. In speculation it does not terminate execution, so the
exit NOP at PC84 is also observed before rollback. These PCs describe software
model observations, not hardware retirement. The regression independently
observes real emulated memory operations at PC36/40 (fixed path) and PC56/60
(computed path), including access type, size and speculative state.

## Taints, rollback and boosting

The actual API is `trace_test_case_with_taints()`; ordinary `trace_test_case()`
does not collect taints. Masks contain input uint64 word indices:

| Configuration | X0 | Exact tainted words | Registers |
| --- | ---: | --- | --- |
| seq | 0 | 1024, 1025, 1026, 1028, 1030 | X0, X1, X2, initial X4, initial NZCV |
| seq | 1 | 1024, 1030 | X0, initial NZCV |
| cond | either | 1024, 1025, 1026, 1028, 1030 | X0, X1, X2, initial X4, initial NZCV |

X1/X2 are direct address dependencies; X0 controls the observed path.
Initial X4 and NZCV are conservative overtaints retained by the shared engine,
even though actual execution overwrites them. CT does not observe main payload
values, so no main/faulty/SIMD words or X3/X5 are tainted in this fixture.

For each original input, memory hooks verify the pointer, marker, loaded value,
access width and unchanged pre-path-CMP NZCV. A wrapper calls **real** rollback
and compares the entire main region, registers X0–X5/X20 and NZCV immediately
before/after it. It also compares restored register/flag/memory dependency maps
to the real checkpoint. This covers both aliasing (`d=0`) and distinct (`d=128`)
wrong-path stores. Final architectural state commits only the correct path:
X0=0 gives X3=29 or 41, X5=7 or 19, NZCV=`0x60000000`; X0=1 gives X3=18,
X5=7, NZCV=`0x80000000`. The whole main region is unchanged except the correct
eight-byte store. Source inputs themselves remain unchanged.

The same conditional model runs X0=1 with nesting 1, then 0, then 1 twice.
X1/X2/X4 taints disappear for nesting zero and return when speculation is
enabled; previously returned masks remain unchanged. Observed transient taints
survive rollback intentionally, while dependency maps restore and the next
input starts clean.

Production boosting uses seed 123, eight-bit entropy, special-value probability
zero and two inputs per class. For **each clause**, eight parents yield eight
additional inputs (16 expanded). All tainted words are checked
as uint64 values, untainted variation is demonstrated, and repeating boosting
produces identical bytes. Every expanded input is independently executed again
with ordinary full tracing and matched to its own parent's complete typed CT.
Final registers and the whole main region are also checked for every retrace.

Across both clauses: **16 original input instances, 16 additional inputs, 32
expanded inputs, 32 independent retraces, zero mismatches**. Collecting parent
taints plus retracing requires 48 actual Unicorn executions. All three tests
together perform 68 executions (16 source/rollback checks, four reset checks,
48 boosting checks). Repeated boosting itself performs no model executions.

## Reproduction and limits

On x86-64 WSL2 install GNU cross-binutils; on native AArch64 use GNU native tools:

```sh
python -m unittest -v tests.unit_arm64_add_address
```

For cross-tools extracted outside PATH, set `RVZR_ARM64_BINUTILS_PREFIX` to the
full path ending in `aarch64-linux-gnu-`; also set `LD_LIBRARY_PATH` if those
tools need extracted shared libraries. The existing B3.4a host adapter adapts
tool lookup and CPU identification only, with hardware factories guarded.

Local validation: x86-64 WSL2, Unicorn 1.0.3, GNU binutils 2.42. Three focused
tests pass, as do 222 other selected regressions, 16 x86 taint/model tests and
seven ARM64 ISA/generator tests (248 total). Flake8, strict mypy and Pylint pass.
Native AArch64/Unicorn 2.1.4 verification is pending; no new dependencies or CI
steps were added. Existing native software dependencies suffice to run this
test explicitly. No result establishes Apple PMU/timer/cache compatibility,
native executor safety, physical speculation, a vulnerability or contract
compliance. Random memory instrumentation, nested/fault/multi-actor contracts
and remaining ISA metadata are outside this bounded experiment.
