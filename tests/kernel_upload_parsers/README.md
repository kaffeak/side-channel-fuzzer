# Host upload-parser baseline

This runs the repository's production `test_case_parser.c` and `input_parser.c` as host C code.
It also compiles the exact `test_case_store()`, `check_test_case_compat()` and
`trace_show()` definitions extracted from `main.c`, with counted success stubs
for preparation and measurement.
It does not load a module, execute test-case instructions, access sysfs or model
kernel concurrency. Readiness publication, generations and failure injection
are outside this stage.

From a checkout with Revizor's Python dependencies and a native compiler:

```sh
python -m unittest tests.unit_kernel_upload_parsers -v
RVZR_PARSER_VERBOSE=1 python -m unittest tests.unit_kernel_upload_parsers -v
```

`CC` may select a native compiler/flags. Each scenario runs a fresh executable
process with a five-second timeout; the replacement scenario intentionally keeps
both uploads in that one process. Compilation has a 30-second timeout per
command. Binaries, generated headers and fixtures live in a temporary directory
and are removed afterward. Verbose mode emits exact build commands, compiler
diagnostics and per-call JSON records.

The tests use `TestCaseBinary.save_rcbf()` for one or three host/kernel actors,
three symbols per actor and sections of 36, 40 and 44 owned ARM64 NOP bytes.
They use `save_input_sequence_as_rdbf()` for one actor
and one 12,288-byte patterned input fragment, including its serialized padding.
No ARM64 host or assembler is required. The fixtures require a little-endian,
64-bit host, such as x86-64 WSL2 or little-endian AArch64 Linux.

| Scenario | Supplied bytes | Expected positive returns | Last finished / receiving |
| --- | ---: | --- | --- |
| Complete RCBF | 220 | 16, 48, 96, 24, 36 | true / false |
| Incomplete RCBF | 212 | 16, 48, 96, 24, 28 | false / true |
| Complete three-actor RCBF | 640 | 16, 144, 288, 72, 36, 40, 44 | true / false |
| Incomplete three-actor RCBF | 632 | 16, 144, 288, 72, 36, 40, 36 | false / true |
| Complete RDBF | 12320 | 16, 16, 4096, 4096, 4096 | true / false |
| Incomplete RDBF | 12312 | 16, 16, 4096, 4096, 4088 | false / true |

The incomplete cases stop eight bytes before the payload ends, after supplying
the complete header and metadata. This is an interrupted stream, not malformed
metadata or a split header. The driver advances by the actual positive return,
resubmitting unconsumed bytes; it never assumes a whole supplied buffer was read.
A seventh scenario sends the complete three-actor fixture in chunks of at most
32 bytes. Section payload returns are 32+4, 32+8 and 32+12, with only the final
call setting `finished`. The different lengths check next-section boundaries.

JSON records distinguish requested bytes, return/consumed bytes, cursor, receiving
state and the per-call `finished` flag. `not_receiving` is the actual production
completion predicate: it is also true before any upload, so it does not establish
semantic validity or kernel readiness. Negative returns have `consumed=null`.
In `store` mode, records also include the actual callback return, its `tc_ready`
storage, preparation-stub counts and `next_measurement_id`. Direct mode does not
call the callback or update that readiness storage.

Completed, nonnegative calls also report an FNV-1a digest of decoded payload bytes,
checked against the fixture payload by Python. The digest reader independently
checks tracked allocation sizes and section lengths before accessing data. It
checks each inline code region's byte offset and length within the actual sections
allocation, as well as its individual `code` array capacity, before hashing it. It
does not read incomplete payloads. This is a bounded comparison, not proof that
every possible metadata value is valid or that hash collisions are impossible.

The sources are included without build-time rewriting in **separate translation units**, each with
one appended read-only cursor accessor. This preserves private static names and
avoids modifying parser code. Init/free functions and production parser headers,
actor/sandbox/input structures, macro IDs and allocation/error macros are reused.
The actual parsing entry points are `parse_test_case_buffer()` and
`parse_input_buffer()`; there is no replacement parser. GNU linker's
`--wrap=parse_test_case_buffer` records the real parser's return and `finished`
flag, including inside the callback. The wrapper calls `__real_parse_test_case_buffer`
and returns its result unchanged. The callback must invoke it exactly once per
supplied chunk. RDBF still uses direct-parser mode only.

Minimal generated Linux/ASM include files forward to `compat.h`. That header
substitutes libc allocation/free and stderr logging. Two unused page-helper
functions have declarations only; accidentally using them fails to link. No
physical-address translation is implemented. Allocations are **exact-sized**:
no guard padding conceals parser accesses outside their requested allocations.
Records include `metadata_allocation_bytes`; RCBF tests require exactly 24 bytes
per actor (24 or 72 here). With ASan enabled, the nonexistent next entry is in a
redzone, so a final-section overread fails instead of being hidden by extra capacity.
Input-call buffers have only the additional terminating NUL used by kernfs.

Compiler options are `-std=gnu11 -O0 -g -Wall -Wextra -Werror`, with synthetic
`VENDOR_ID=3`, `PHYSICAL_WIDTH=48`, `L1D_ASSOCIATIVITY=8`, `L1D_SIZE_KB=32`.
These select declarations, not hardware properties. Test `PAGE_SIZE` is explicitly
4096, independently of the host. Only production-parser units receive
`-Wno-error=sign-compare`: their existing signedness warnings remain captured and
visible in verbose mode. Only the extracted callback unit receives
`-Wno-error=unused-parameter` for its original unused sysfs arguments; those
warnings are also retained. Harness warnings remain fatal. `-O0` makes source-level
control flow straightforward to diagnose; optimized campaigns are not benchmarked.

Memory bounds are 128 KiB per fixture, 2 MiB of tracked live parser allocations,
128 tracked blocks, 4096 calls and 4096 bytes per supplied chunk. Unexpected host
allocation failures or bounds violations fail explicitly. Parser teardown must
leave zero tracked bytes; leftover allocations produce a nonzero exit even though
the harness releases them before exiting. This is not Linux allocator behavior.

Run instrumented builds separately, after the ordinary tests:

```sh
RVZR_PARSER_SANITIZER=undefined python -m unittest -f tests.unit_kernel_upload_parsers -v
RVZR_PARSER_SANITIZER=address python -m unittest -f tests.unit_kernel_upload_parsers -v
```

These add the selected `-fsanitize` option, `-fno-omit-frame-pointer`,
`-fno-sanitize-recover=all` and `-no-pie`. Runtime diagnostics are not suppressed;
a crash fails the test with the full preceding JSON and stderr. LeakSanitizer
reported an unsupported ptrace environment on the development host, so these
runs explicitly set `ASAN_OPTIONS=detect_leaks=0:halt_on_error=1`. Address/bounds
checks remain enabled; allocation tracking separately requires zero live bytes.
This baseline makes no LeakSanitizer claim. `-f` stops the
suite on the first failure. Unsupported compiler/runtime instrumentation is an
explicit failure, not a silently skipped safety check.

An ordinary valid-input pass cannot establish memory safety. If instrumentation
exposes another error, stop and retain the diagnostic; do not pad allocations or
silently broaden the fix. Neither clean sanitizer output nor these bounded
scenarios would establish kernel, sysfs, M3 or 16 KB execution compatibility.

## Original B3.3b.1 failure evidence

On x86-64 WSL2 (Linux 5.15.167.4, Python 3.12.3, GCC 13.3.0), all four
ordinary scenarios passed with the returns and states above. Both complete
fixtures passed the separate UndefinedBehaviorSanitizer build. With ASan bounds
checking, complete RDBF passed but complete RCBF failed: an **8-byte heap read**
at `test_case_parser.c:277`, eight bytes beyond the exact 24-byte metadata
allocation made at line 79. After finishing actor zero's section, the parser
increments `curr_section_id` to one and accesses `metadata[1].size` before testing
final completion. The stack identifies the production parser access, not the
harness payload-digest reader. ASan aborted before that final call returned.

Parser experiments stopped at that failure. The complete original diagnostic is
retained verbatim in [evidence/rcbf-asan-before-fix.txt](evidence/rcbf-asan-before-fix.txt),
including the original source line numbers, stack, allocation size and preceding
JSON records. It describes the pre-fix source, not a current expected failure.

## B3.3b.2 boundary correction

After advancing the section index, the production parser now reads the next
metadata entry only when `curr_section_id < n_actors`. A non-final section still
updates its start/end for the next actor. A final section reaches the existing
completion block without dereferencing a nonexistent next entry; that block
resets the indices, clears receiving, sets `finished` and validates the program.
Consumed-byte handling and serialization are unchanged. Validation can still
fail after `finished=true`; this change does not redefine completion as readiness.

On the same WSL2/GCC environment, all seven ordinary scenarios and all seven
scenarios in each separate ASan and UBSan build passed. The original single-actor
ASan failure is no longer reproducible with these exact-sized allocations.
No new sanitizer finding appeared. LeakSanitizer remains disabled for the
documented environment limitation; no loaded-kernel safety claim follows.

## B3.3b.3 callback error propagation (historical, before correction)

This section retains the defect evidence from before B3.3c.1. Its failure-state
table describes the original callback; the current regression expectations and
corrected results are documented in the next section.

The Python wrapper isolates exactly one definition each of `check_test_case_compat()`
and `test_case_store()` from the current `main.c`. It copies their source text
verbatim into a generated translation unit, with `#line` directives retaining
production diagnostic locations. A narrow, fail-on-mismatch extractor handles
these two current top-level definitions, not arbitrary C. The only adapter calls
the static callback with null unused sysfs arguments; it contains no upload logic.
Changing their declaration/brace style may require updating this extractor.

The actual compatibility checker is compiled for `VENDOR_ID=3` (ARM), where its
x86-only checks are absent. Real production `CHECK_ERR` macros remain in use.
`tc_ready` and `next_measurement_id` have host storage with the production initial
values. `allocate_sandbox()` and `load_sandbox_code()` are counted stubs that
always return zero; they neither allocate a sandbox nor execute/load its code.
No preparation failure is injected. No other upload callback is extracted.

Four additional fresh-process tests exercise complete and incomplete RCBF uploads
through the callback, plus a deterministic semantic failure through both direct
and callback modes. The failing fixture uses the existing serializer and contains
the main function and measurement-start symbol, but omits measurement-end. Its
188 bytes form a complete serialized stream, not an interrupted upload. Including
start ensures `has_start` is initialized on this path; this test does not depend
on the separate uninitialized-`has_start` concern.

Observed results on x86-64 WSL2/GCC 13.3.0, with successful preparation stubs:

| Scenario | Parser returns | Final callback return | Final finished / receiving | Final `tc_ready` | Allocate / load calls |
| --- | --- | ---: | --- | --- | --- |
| Complete RCBF, callback | 16, 48, 96, 24, 36 | 36 | true / false | true | 1 / 1 |
| Incomplete RCBF, callback | 16, 48, 96, 24, 28 | 28 | false / true | false | 0 / 0 |
| Missing end, direct | 16, 48, 64, 24, -1 | not called | true / false | false (untouched) | 0 / 0 |
| Missing end, callback | 16, 48, 64, 24, -1 | -1 | true / false | **true** | **1 / 1** |

All callback returns equal their parser returns in these scenarios. Every
non-final callback leaves readiness false and preparation counts zero. The
negative final return is an error, not a consumed-byte count: JSON reports
`consumed=null`, although the parser cursor has reached all 188 fixture bytes.
The validator emits its missing-start/end error. The harness retains that error,
records callback state, performs parser teardown and exits 65 rather than
mislabeling the operation successful. Negative validation returns suppress the
payload-digest reader.

This confirms a callback control-flow defect, not just a source-derived
prediction: a negative parser result with `finished=true` reaches preparation
and can set readiness true when preparation returns success. The original test
`test_legacy_risk_store_prepares_after_validation_failure` characterized this
behavior, without specifying that it was safe. B3.3c.1 replaces that expectation
with an error-propagation regression; the original observed values remain above.
Changing the meaning of parser completion alone would not replace explicit
callback error handling.

The stubs cannot establish whether real sandbox/code preparation would succeed,
fail or partially modify resources for this invalid program. Actual allocator,
code-loader errors, cleanup, abort/retry reset, sysfs dispatch, locking and
concurrent execution remain untested. The immediate follow-up was the explicit
callback parser-error guard and a regression asserting error/false/zero calls.
Allocation-failure characterization remains separate. The original ASan evidence
above is preserved unchanged.

All 11 tests (the original seven plus these four) passed ordinarily and in each
separate ASan and UBSan build on WSL2. No sanitizer finding appeared in these
bounded scenarios; the LeakSanitizer limitation above still applies. The expected
semantic error remains a program error even when its characterization test passes.

## B3.3c.1 parser errors and replacement readiness

The only production behavior change is an immediate negative-return check after
`parse_test_case_buffer()` in `main.c:test_case_store()`. It returns the original
error before compatibility checking, sandbox allocation or code loading,
independently of `finished`. Positive short returns and normal preparation are
unchanged. The existing `tc_ready=false` assignment stays **before** parsing, with
a comment explaining that the previous preparation is invalidated before the
parser modifies test-case state. A failed upload does not restore that old state.
No parser, trace-entry, allocation or synchronization behavior is changed.

The renamed `test_store_rejects_final_validation_failure` now requires parser and
callback return -1, `finished=true`, readiness false and zero preparation calls.
Direct-parser characterization and all seven original baseline tests remain.

The harness accepts an optional seventh argument, a replacement fixture, only in
RCBF `store` mode after a complete first upload. It feeds the two fixtures in one
process without reinitializing the parsers, readiness or preparation counters.
Each fixture remains bounded to 128 KiB; the original process/call/time limits
still apply. There are no simulated readiness transitions. `upload_id` separates
the records, `ready_before_call` observes readiness before the actual callback,
and `ready_at_parser_entry` observes it immediately before the real RCBF parser
runs. The latter is null outside store-mode parser calls. These are observations,
not setters or synchronization guarantees.

The sequential regression successfully prepares the valid 220-byte fixture and
then uploads the complete 188-byte missing-end replacement. It checks every
partial replacement call as well as final failure:

| Point | Parser / callback return | Finished | Readiness before callback / at parser entry / afterward | Cumulative allocate / load calls |
| --- | --- | --- | --- | --- |
| Original final call | 36 / 36 | true | false / false / true | 1 / 1 |
| Replacement header | 16 / 16 | false | true / false / false | 1 / 1 |
| Replacement intermediate calls | 48 / 48, 64 / 64, 24 / 24 | false | false / false / false | 1 / 1 |
| Replacement validation failure | -1 / -1 | true | false / false / false | 1 / 1 |

An initially invalid upload also returns -1 with readiness false and **zero**
allocate/load calls. The replacement's final cursor is 188, receiving is false,
and consumed bytes and payload digest are null for the error return. Each
scenario frees all tracked parser allocations at teardown. Preparation stubs
still always return success; actual sandbox/code resources and their cleanup
are not exercised.

Before changing production code, both corrected regressions were run against the
original callback and failed at the readiness assertion. The sequential records
showed false readiness at replacement parser entry, but true readiness after
failure and cumulative preparation counts **2 / 2**. The historical section above
retains the earlier isolated-failure evidence, and the original ASan evidence
file is unchanged. Neither defect is hidden by padding or altered parser results.

On x86-64 WSL2/GCC 13.3.0, all 12 ordinary tests and all 12 tests in each separate
ASan and UBSan build passed after the correction. No sanitizer finding appeared;
the documented LeakSanitizer limitation still applies. The 102 existing input-format,
descriptor, preparation, coverage and resource-lifetime regressions also passed,
as did Flake8, strict mypy, Pylint and `git diff --check`. Full kernel-module
compilation was unavailable locally: this WSL2 host has no kernel build tree or
ARM64 kernel development tree/cross-compiler. Compiling the extracted production
callback as host C is not a substitute for the existing native ARM64 module checks.

### Deliberately limited guarantee at B3.3c.1

Before B3.3c.2, `main.c:trace_show()` checks `measurements`, `input_parsing_completed()` and
`tc_parsing_completed()`, but does **not** check `tc_ready` or `inputs_ready`.
The parser clears receiving before final semantic validation, so completion can
be true after validation failure. `measurement.c:pre_run()` checks entry and input
pointers (and the entry PTE), not semantic readiness or allocation generations.
These are source observations; this harness never calls trace execution.

Consequently the callback correction **does not prevent trace execution after
invalid preparation**. Previous loaded code/input resources may remain reachable,
and a nonnegative `next_measurement_id` can select already pending results because
failed replacement does not reset it. Full execution behavior is not established
by these tests. Per-callback invalidation is sequential control flow only; it
does not serialize uploads, descriptor reads or trace execution across threads.

The next independent correction should enforce validated preparation at trace
entry, with host-only rejection tests. Preparation-failure cleanup/readiness and
input validity need separate coverage. Eventual generation-checked execution must
bind test case, inputs, allocations and result iteration to the same completed
preparation, and check/execute under appropriate synchronization. A read-only flag
or descriptor alone cannot provide this guarantee. No such protocol is added here.

## B3.3c.2 sequential trace admission

The sole production change is `ASSERT(tc_ready && inputs_ready, "trace_show")`
before the existing pointer/completion checks in `main.c:trace_show()`. The real
`ASSERT` macro returns `-EIO`, consistent with the existing trace-interface
assertions, and logs the failed condition. Local integer initialization is the
only preceding work: no experiment, result formatting, cursor update or write to
`unfinished_call` has occurred. Both new measurement and pending-result paths
pass this guard. A rejection preserves even an already true `unfinished_call`;
it neither repairs existing execution-error state nor discards stored results.

The extractor now includes the actual `trace_show()` body and a thin adapter.
Its only new dependencies are existing production headers and host storage for
`inputs_ready`, `unfinished_call` and `measurements`. It uses **real libc
`sprintf`**, not a replacement formatter, to write into an exact 4096-byte owned
buffer. The entire buffer starts with a sentinel pattern; rejection must leave
all bytes unchanged. Returned output is reported as hex, independently checked
against expected ASCII bytes by Python. A counted `trace_test_case()` stub always
succeeds and seeds at most 64 owned `measurement_t` records. It deliberately
does not enforce readiness itself, so it cannot hide callback admission defects.

This is a separate bounded harness mode, not a simulated preparation protocol:

```text
parser-baseline trace TC_READY INPUTS_READY UNFINISHED execute|pending|paginate
```

The flags are explicit synthetic fixture state. Actual parser completion
predicates are idle/true in these tests; no successful preparation is implied.
`execute` starts with cursor -1 and two measurements; `pending` starts with cursor
1 and preloaded results. `paginate` first permits a real callback invocation with
64 records, then applies the selected flags before calling it again. There is
no test-case execution, kernel access or new compatibility emulation. Each
scenario runs in its own process with the existing five-second timeout and
requires zero tracked parser bytes at teardown.

Six additional test methods cover:

- All three unready flag combinations for execution and pending results, each
  with `unfinished_call` initially false and true (12 independent subcases).
- Both flags true: one measurement-stub call and the exact descending result
  format, plus `done\n`.
- Ready pending results: the same output without another measurement-stub call.
- Successful two-page output: 64 twenty-digit synthetic measurements produce
  a 4032-byte first page (cursor 31) and a 4037-byte final page (cursor -1).
  Concatenated bytes must exactly match the independent expected output.
- Invalidation after the first page, for all three unready combinations: return
  -EIO, no output write, unchanged cursor 31 and no additional stub call.

All 15 rejection subcases failed against the original callback before the guard
was applied. Old execution reached the stub; invalidated pagination returned
4037 bytes instead of -EIO. This is evidence from the compiled production
callback with synthetic resources, not a source-only prediction. The existing
upload/parser regressions and earlier historical defect evidence are retained.

On x86-64 WSL2/GCC 13.3.0, all 18 test methods passed ordinarily and in each
separate ASan and UBSan build, with no sanitizer findings. The existing
LeakSanitizer limitation remains. All 102 input-format, descriptor, preparation,
coverage and resource-lifetime regressions also passed. Full module compilation
was unavailable locally because kernel development trees and an ARM64 compiler
are absent; the existing native ARM64 build configuration was not changed or run.

### Input readiness and remaining identity limits

Source inspection of `main.c:test_case_store()` shows it never clears
`inputs_ready`. A successful replacement can therefore make both flags true
while the input batch still belongs to the preceding test case. The new guard
cannot detect that association or an actor-count mismatch introduced by later
test-case replacement. Actual batch reuse needs an explicit validity policy.

`main.c:inputs_store()` clears `inputs_ready` **after** calling the parser and
sets it true solely from `finished`, without an explicit negative-return guard.
In the current `input_parser.c:parse_input_buffer()`, negative returns occur on
batch-start failure and return before setting `finished`; the callback initializes
that flag false. Unlike RCBF's final validator, no negative-return/finished-true
input path has been demonstrated here. Thus a returned ordinary parser error
clears input readiness in the current sequential path. The missing explicit
error check is a defensive gap, not a newly confirmed reproduction of the RCBF
bug. Completion also performs no final semantic validation of uploaded metadata.
The input callback itself is not compiled/exercised by this stage's tests.

During input parsing, the old input-readiness value remains visible until the
parser returns. Both callbacks and trace entry still share globals without an
executor-wide lock. The guard establishes **sequential Boolean admission only**;
it cannot make readiness checks atomic with execution or verify generation
identity. Pending results are blocked while a flag is false but are not erased
or tagged, so later flag restoration alone cannot establish their provenance.

Next steps remain separate: establish input invalidation on test-case replacement
and robust input-error publication, characterize preparation failures/cleanup,
then bind test case, inputs, allocations and result pagination to a common
generation under synchronization. Host-stub results do not establish loaded-
kernel or M3 compatibility. CI, serialization and 16 KB execution are unchanged.
