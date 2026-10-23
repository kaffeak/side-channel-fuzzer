# B3.4a: deterministic ARM64 contract-model vertical slice

Run the focused integration regression from the repository root:

```sh
python -m unittest tests.unit_arm64_contract_slice -v
```

It needs Revizor's Python dependencies and GNU AArch64 binutils. On x86-64
Ubuntu/WSL2, install `binutils-aarch64-linux-gnu`; on native AArch64 Linux the
test selects ordinary `as` and `objdump`. An absolute cross-tool prefix can be
selected without installing or replacing system tools:

```sh
RVZR_ARM64_BINUTILS_PREFIX=/path/to/bin/aarch64-linux-gnu- \
  python -m unittest tests.unit_arm64_contract_slice -v
```

Missing/broken tools fail explicitly; no synthetic assembly or trace fallback
is used. An unpacked tool package may additionally require its library directory
in `LD_LIBRARY_PATH`. Local validation used Ubuntu binutils 2.42 unpacked under
`/tmp`, without modifying system tools, and Unicorn 1.0.3 on x86-64 WSL2.

## Working production path

| Component | Existing interface exercised / limitation |
| --- | --- |
| Generator and ARM64 instrumentation | `factory.get_program_generator()` selects `ARM64Generator`; `CodeGenerator.create_test_case_from_template()` at [code_generator.py:202](../../rvzr/code_generator.py#L202) parses, runs passes, prints and assembles the fixed template. This exercises deterministic template generation, not arbitrary random instruction generation. Template instructions intentionally retain their manually bounded addressing. |
| Assembly parser | [AsmParser.parse_file:621](../../rvzr/asm_parser.py#L621) builds functions/basic blocks and inserts default measurement macros. The ARM-specific line parser resolves AArch64 operands/conditions. A conditional branch requires a following basic-block label; a terminator cannot be followed by ordinary instructions in the same block. |
| Assembler / metadata | [assemble:362](../../rvzr/code_generator.py#L362) invokes real GNU `as`; [ELFParser](../../rvzr/elf_parser.py) uses pyelftools and real `objdump` to populate section locations, instruction offsets and macro/function symbols. The test asserts a little-endian `EM_AARCH64` object, never manually assigns ELF metadata or instruction bytes. |
| Serialization | `TestCaseBinary.save_rcbf()`, `InputData.save()/load()` and `save_input_sequence_as_rdbf()` are exercised unchanged. The model consumes the assembled `TestCaseProgram` plus raw-round-tripped `InputData`; it does not import the RCBF/RDBF exports. Those exports are checked separately, not sent to a kernel parser. |
| Model | `factory.get_model()` selects `ARM64UnicornModel`, `SeqSpeculator`, `CTTracer` and `ARMExtraInterpreter`; `load_test_case()` loads real assembled code; `trace_test_case()` runs it and returns actual `CTrace` objects. Emulation and tracing are not mocked. |
| Host adaptation | Target construction normally reads ARM-specific `/proc/cpuinfo` fields ([target_desc.py:136](../../rvzr/arch/arm64/target_desc.py#L136)); only that CPU-identification method is replaced with synthetic ARM metadata. The original bare tool names resolve through temporary symlinks to real binutils. No production interface changes are needed. |

The test context restores configuration, environment, current directory and Python
random state. All generated files live in a temporary directory because the
template API writes `generated.asm`/`generated.o` in the current directory.
The source template is copied before parsing. The adapter is for serial unit
tests, not a new cross-compilation configuration API. Construction of a fuzzer
or kernel executor is explicitly rejected by test guards.

## Program, inputs and architectural oracle

[contract_slice.asm](asm/contract_slice.asm) executes:

```asm
cmp x0, #0
b.eq .taken
.fallthrough:
mov x1, #11
b .join
.taken:
mov x1, #22
.join:
ldr x2, [x20], #0
add x3, x1, x2
str x3, [x20], #0
```

`x20` is initialized by the existing model to actor 0's main region. The load and
store each access its first eight bytes; the zero writeback keeps the base
unchanged. The next eight bytes are checked to remain zero. All serialized input
bytes, including padding, start at zero, except the explicitly supplied `x0` and
first main word:

| Input | Initial x0 | Initial main[0] | Branch | Final x1 | Final x2 | Final x3 / main[0] | NZCV |
| --- | ---: | ---: | --- | ---: | ---: | ---: | --- |
| 0 | 0 | 7 | Taken | 22 | 7 | 29 | `0x60000000` |
| 1 | 1 | 7 | Not taken | 11 | 7 | 18 | `0x20000000` |
| 2 | 2 | 19 | Not taken | 11 | 19 | 30 | `0x20000000` |

Register outcomes are read directly from the real Unicorn engine, separately
from the C-trace. A repeated batch `[0, 1, 2, 0]` verifies deterministic traces
and per-input reset after the store. Original input bytes must remain unchanged.

The assembled code is 60 bytes: eight instructions, two three-NOP macro
placeholders and one exit NOP. RCBF is 276 bytes, including the automatically
populated four function/macro symbols. Each raw input remains 12,288 bytes;
RDBF metadata continues to advertise 8,512 meaningful bytes per actor. These
existing dimensions and bytes are preserved.

## Observation oracle and interpretation

Configuration is explicit: ARM64, Unicorn, sequential `seq` execution, `ct`
observation, no handled faults and disabled instruction coverage. `nesting=1`
does not introduce speculation: `SeqSpeculator.is_sequential` is true. This is
architectural execution in an emulator, not a misprediction experiment.

`ct` records instruction PCs and memory byte addresses, not these loaded/stored
data values ([tracer.py:194](../../rvzr/model_unicorn/tracer.py#L194)). Its common
normalization subtracts code/data allocation bases ([tracer.py:68](../../rvzr/model_unicorn/tracer.py#L68)).
Synthetic bases are data `0x109000`, code `0x200000`; main is at data offset 4096.
No host page size, hardware address, physical cache index or cache-line rounding
is used to compute the oracle.

Expected untyped C-traces are:

```text
Taken:     [12, 16, 28, 32, 4096, 36, 40, 4096, 44]
Not taken: [12, 16, 20, 24, 32, 4096, 36, 40, 4096, 44]
```

The test asserts typed entries too: the two `4096` entries are `mem`, all others
are `pc`. PC 44 is the measurement-end macro, observed before its interpreter
callback disables tracing. The start macro and remaining NOP placeholders are
excluded by the current dispatch semantics. Input 0 differs from input 1 in
control flow; inputs 1 and 2 have equal C-traces despite different values and
architectural outputs. No hash or diagnostic visualization substitutes for the
typed-list assertions.

## Validation and limits

The new full-path regression and seven existing ARM64 ISA/generator/parser tests
passed on WSL2 with the real cross tools and synthetic CPU identification. The
existing generator tests were run with a temporary copy of their fixtures to
contain their assembly outputs. The shared test adapter can reproduce that run:

```sh
python - <<'PY'
from pathlib import Path
from unittest.mock import patch
import shutil, tempfile, unittest
from tests.unit_arm64_contract_slice import software_environment
from tests.arm64 import unit_generators, unit_isa_loader
with tempfile.TemporaryDirectory(prefix="rvzr-arm64-existing-") as temporary:
    directory = Path(temporary)
    fixtures = directory / "arm64"
    shutil.copytree(unit_generators.test_dir, fixtures)
    with software_environment(directory), \
            patch.object(unit_generators, "test_dir", fixtures), \
            patch.object(unit_isa_loader, "test_dir", fixtures):
        suite = unittest.defaultTestLoader.loadTestsFromNames([
            "tests.arm64.unit_isa_loader", "tests.arm64.unit_generators"])
        result = unittest.TextTestRunner(verbosity=2, failfast=True).run(suite)
        if not result.wasSuccessful():
            raise SystemExit(1)
PY
```

The combined slice, preparation/lifetime/coverage, cache-observation, trace,
analyser, input-format, descriptor, geometry/parity and test-case-component suites
passed **195 tests**, including the new integration test. Together with the
seven legacy ARM64 tests above, **202 tests passed**. Flake8 (100-column limit),
strict mypy and Pylint passed for the new Python file; Pylint reported 10/10.

On a native ARM64 runner, rerun the new test with native binutils and record the
installed Unicorn version; also retain the existing unadapted generator/parser
tests to exercise real CPU discovery. This task does not change CI. Native ARM64
Python/Unicorn execution still does not measure Apple Silicon hardware.

This slice covers a single host/kernel actor and a tiny instruction subset.
It does not validate speculative clauses, faults, boosting/taints, multi-actor
switching or broad random campaigns. Known incomplete ARM interfaces remain:
the Unicorn target's SIMD register list is empty, ARM userspace/VM emulation
hooks are no-ops, and DynamoRIO is rejected for ARM64. The active model remains
on the legacy 4 KiB layout; candidate 16 KiB placement is not activated.

To connect this to hardware later, bind the same test case and input batch to a
completed, coherent executor allocation and model-address snapshot, establish
native execution/recovery safety, and calibrate a usable hardware observer.
Then compare H-trace distributions **within C-trace-equivalent input groups**
using the existing analyser; do not equate hardware bitmap positions with the
contract's byte addresses. This deterministic smoke test establishes neither
Spectre detection nor contract compliance. Kernel/PTE/transport/measurement code
and native build configurations are unchanged.
