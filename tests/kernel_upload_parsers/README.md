# Host upload-parser baseline

The B3.3d.3 [explicit parser-reset implementation and results](PARSER_RESET.md)
extend this baseline. The legacy interrupted-RDBF expected failure remains unresolved.
The B3.3d.4a [host-only attempt-bound adapter](ATTEMPT_UPLOAD.md) combines the
real state component and parsers behind explicit boundaries; live callbacks remain unchanged.

This runs the repository's production `test_case_parser.c` and `input_parser.c` as host C code.
It also compiles the exact `test_case_store()`, `inputs_store()`,
`check_test_case_compat()` and `trace_show()` definitions extracted from `main.c`,
with counted stubs for preparation and measurement. Preparation stubs default to
success and have selectable bounded errors in the failure scenarios below.
It does not load a module, execute test-case instructions, access sysfs or model
kernel concurrency. Descriptor publication, generations and real allocator
failure injection remain outside this stage.

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
`--wrap=parse_test_case_buffer` and `--wrap=parse_input_buffer` record the real
parsers' returns and `finished` flags, including inside callbacks. The wrappers call the respective `__real_`
parser and return its result unchanged. Accepted writes call the parser once;
input writes rejected before parsing report `parser_ret=null`. RDBF supports
both direct and callback modes; preparation scenarios load a test case first.

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

Memory bounds are 512 KiB per fixture, 2 MiB of tracked live parser allocations,
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
At that stage each fixture was bounded to 128 KiB; the process/call/time limits
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

### Input readiness and remaining identity limits at B3.3c.2

These were the pre-B3.3c.3 source findings. Sequential invalidation and input
admission are corrected below; synchronization and generation limits remain.

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

## B3.3c.3 input readiness and result invalidation

Production changes are limited to the two upload callbacks in `main.c`:

- `test_case_store()` clears `tc_ready`, `inputs_ready` and the pending result
  cursor (`next_measurement_id=-1`) before parsing. Successful preparation sets
  only `tc_ready`; inputs must be uploaded again. The existing parser-error guard
  and preparation checks remain.
- `inputs_store()` clears `inputs_ready` and the result cursor before checking
  `tc_ready` and before parsing. An unprepared test case yields -EIO without a
  parser call. A negative parser return is propagated unchanged; only nonnegative
  completion can restore input readiness. All positive short returns are preserved.

Invalidation happens on every supplied write chunk, so interrupted and failed
uploads cannot retain readiness or a previous pagination cursor. Result buffers
are not erased: with cursor -1, a subsequent admitted trace must invoke measurement
again rather than resume those buffers. `unfinished_call` is not reset here.

### Inspected Python compatibility

No legitimate inputs-before-completed-test-case path was found in the inspected
Python hardware executor flows. `rvzr/executor.py:258-280` writes RCBF synchronously
via `save_rcbf()`; `:304-318` writes RDBF, verifies input readiness, then reads traces.
Both serializers finish their `with open(..., 'wb')` block before returning
(`rvzr/tc_components/test_case_binary.py:136` and `test_case_data.py:182`).
Normal rounds load the executor at `rvzr/fuzzer.py:137` before hardware collection
at `:262`. Architectural mismatch checking loads at `:383` and traces at `:392`.
ARM64 filtering loads then traces both original and fenced cases
(`rvzr/arch/arm64/fuzzer.py:66-67,95-96`). `ARM64Executor` inherits these upload
methods unchanged. Architectural differential testing follows the same order at
`rvzr/fuzzer.py:920-938`. Every non-skipped `trace_test_case()` call reuploads inputs;
an empty/all-ignored call returns without reading hardware. No Python change is
required. Direct sysfs clients that previously preloaded inputs before preparing
code, or reused inputs after replacing code, must instead load code then inputs.
Repetitions and successive result pages without intervening uploads are unchanged.

### Actual callback regressions

The extractor now also compiles the exact production `inputs_store()`. Both parser
wrappers capture readiness and cursor **before** the actual parser call, together
with original returns and completion flags. They never change parser outcomes.
The seven new fixed scenarios use actual callback sequences, without driver-set
readiness or parser reinitialization between uploads. They cover normal loading,
successful code replacement and input reupload, partial replacement inputs,
actor-count mismatch, early input rejection, and pending results discarded by
either upload callback.

Preparation mode records expected upload errors and then checks trace rejection;
a zero driver exit means observation/teardown completed, not that those rejected
uploads succeeded. Negative callback returns remain explicit in JSON and tests.

The one-actor 33-input fixture is 405536 bytes, generated by the existing RDBF
serializer. It produces a real 4032-byte first result page with cursor zero and
one stubbed measurement invocation. This motivated raising the owned-file bound
from 128 to **512 KiB**; the 2 MiB allocation, 4096-call and five-second subprocess
bounds remain. Measurements are still owned/stubbed, not hardware observations.

| Observed transition | `tc_ready` / `inputs_ready` | Result cursor / measurement calls |
| --- | --- | --- |
| Initial complete RCBF | true / false | -1 / 0 |
| Initial complete RDBF | true / true | -1 / 0 |
| First page from 33 inputs | true / true | 0 / 1 |
| New RCBF, at parser entry | false / false | -1 / 1 |
| Successful replacement RCBF | true / false | -1 / 1 |
| Trace before input reupload | true / false; returns -EIO | unchanged -1 / 1 |
| Valid one-input reupload | true / true | -1 / 1 |
| Admitted trace after reupload | true / true | -1 / **2**; fresh 17-byte result |
| Partial/error replacement RDBF | true / false | -1 / 1; subsequent trace rejected |

The last two result-invalidation cases also replace inputs without replacing
code. Both require a new stub call after successful reupload, with exact
`1,1,1,1,1,1\ndone\n` formatting, rather than the old 131-byte pending page.
The direct/parser and upload tests retain their existing positive short-return
sequences. The normal-load test passed before correction; six new regressions
failed against the old callbacks, then passed after the scoped production change.

The deterministic error uses a fully serialized two-actor RDBF header after a
one-actor test case. The real actor-count assertion fails; `parse_input_buffer()`
returns -1 with `finished=false`, and `inputs_store()` returns that same -1.
Readiness and cursor were already invalidated at parser entry. Diagnostics and
`consumed=null` are retained; no invalid payload digest is read. Input-before-code
rejection is separately -EIO, with `parser_ret=null` and zero parser calls.

This error also exposes an existing parser-state concern: the input cursor becomes
18446744073709551611 (unsigned -5) because the parser adds the batch-start error
before returning -1 (`input_parser.c:100-103`). This is not an ASan/UBSan finding;
the parser arithmetic is unchanged, and the wrapped value is not used as a harness
memory offset. The tests stop that input stream and verify trace rejection, not
error rollback or retry correctness.

On WSL2/GCC 13.3.0, all **25** host tests passed ordinarily and in separate ASan
and UBSan builds, with no sanitizer findings. All 102 existing input-format,
descriptor, preparation, coverage and resource-lifetime regressions passed.
Flake8, strict mypy, Pylint and `git diff --check` passed. The existing
LeakSanitizer limitation remains. Full kernel-module builds were unavailable
locally because kernel development trees and an ARM64 compiler are absent;
the existing ARM64 CI configuration was not modified or invoked.

### Remaining limits and next step

Completed predecessor inputs cannot satisfy both readiness flags after the tested
replacement sequences, and old pages cannot resume after those reuploads. This
is not a proof for arbitrary interrupted-stream histories. Callback invalidation
does not cancel/reset private parser receiving state; abandoning partial RDBF
and switching test cases remains a separate source-derived reset/association risk.
No parser rollback, allocation/code-loader failure recovery, old resource cleanup
or transactional preparation is implemented. Actual production preparation and
measurement functions are still stubbed here.

The smallest next task is bounded characterization of abort/retry and preparation
failure cleanup, retaining the real callbacks and independently safe observations.
That should establish which failures leave each parser and allocator reusable
before designing recovery transitions. Generations must eventually bind code,
inputs, allocations and result iteration, with synchronization between publication,
trace admission and execution. Shared globals are still unlocked, and simultaneous
callbacks can race; these sequential tests cannot establish atomicity. No loaded-
kernel, M3 or 16 KB runtime claim follows from this change.

## B3.3c.4a interrupted uploads and parser-error recovery

This stage changes **only host tests and documentation**. The three fixed recovery
scenarios reuse the production parsers and extracted upload/trace callbacks. The
same process retains its actual parser state throughout a scenario; no driver
sets readiness, resets a parser, or loads/executes code. The only measurement
function is the counted host stub. All existing size/call/time limits remain.

```text
parser-baseline recover rdbf-interrupted|rdbf-error|rcbf-interrupted RCBF RDBF WRONG_ACTOR_RDBF
```

### Source state and upload boundaries

`input_parser.c:21-27` retains receiving, cursor, allocation high-water counts
and backing allocations. Batch start resets cursor and replaces the batch object
(`:31-40`); successful completion clears receiving but leaves the end cursor and
backing allocations (`:133-143`). Initial setup and teardown are at `:183-203`.

`test_case_parser.c:24-32` retains receiving, cursor, sizes and allocations;
`:193-195` also retains three function-local static section variables. Successful
completion resets those section variables and clears receiving before final
validation (`:283-296`); the end cursor remains until the next batch start. Header
and oversized-section errors do not perform a uniform complete-state reset.
Initialization (`:336-353`) does not reset the function-local section variables
or all allocation high-water counts, and cleanup (`:356-363`) frees resources
rather than providing a stream abort. Calling free/init is not an established
in-process recovery API.

Neither parser clears receiving merely because the sender stops writing. Their
only new-header discriminator is `!receiving`. The upload callbacks receive
buffers/counts, not an upload identity or file-open boundary. There is no exposed
parser abort/reset operation (`main.c:694-695,764-765` calls init/free for module
lifetime). RCBF/RDBF serializers open and close their paths for each upload;
`Executor.load_test_case()` / `trace_test_case()` invoke them at
`rvzr/executor.py:275,308`. Closing and reopening does not reset this parser state.

### Bounded retry method and observed results

For interrupted streams, the first upload stops eight bytes before its payload
ends. The retry is a header-first attempt using the first **16 actual bytes** of
the corresponding valid serialized fixture. The driver observes that one response
and stops: it does not discard a short return, resubmit the remaining eight bytes
as an incomplete new header, or claim the whole fresh file was processed. This
keeps the boundary ambiguity visible without launching additional parsing or
allocation scenarios. Error recovery instead supplies the mismatch fixture's
16-byte header, then attempts the complete valid one-actor RDBF stream.

| Scenario | State before retry | Retry parser / callback returns | State after retry | Preparation allocate/load calls | Measurement calls before/after final trace |
| --- | --- | --- | --- | --- | --- |
| Interrupted RDBF | cursor 12312, receiving true, inputs unready | **8 / 8**, from 16 supplied bytes | cursor 12320, finished true, receiving false, **inputs ready** | 1 / 1, from initial RCBF only | **0 / 1** |
| RDBF actor mismatch | error -1, cursor 18446744073709551611, receiving false, inputs unready | 16, 16, 4096, 4096, 4096; callback equals parser each time | header resets cursor to 16; final cursor 12320, inputs ready | 1 / 1, from initial RCBF only | 0 / 1, after successful recovery |
| Interrupted RCBF | cursor 212, receiving true, code unready | **-EIO / -EIO**, from 16 supplied bytes | cursor 220, finished true, receiving false; both readiness flags false | **0 / 0** | **0 / 0** |

Interrupted RDBF **does not restart**: the parser copies the new header's first
eight bytes into the old payload tail and marks that old batch complete.
The callback then publishes input readiness. The independently bounded payload
digest equals `old_payload[:-8] + new_header[:8]` and differs from the valid input
digest. This confirms mixed old/new data, not just a readiness-flag observation.
The first trace before retry is rejected, but the trace after this unsuccessful
restart is admitted and calls the measurement stub. This is a functional safety
defect; no hardware instructions or real measurement run.

Interrupted RCBF likewise treats the new header as old section data. After eight
bytes it finishes the old section, then its `consumed_bytes == count` assertion
fails (`test_case_parser.c:295-296`). The actual parser returns -EIO with
`finished=true`; the corrected callback propagates that error without preparing
code. Both trace attempts are rejected and no measurement stub runs. This is
safe rejection of the **tested 16-byte retry**, not recognition of a new stream
or a guarantee for other chunk boundaries. Another full retry after this error
was not tested, although the receiving predicate is now idle.

### Why the cursor wraps, and why this header-error retry succeeds

The actor-count assertion in `start_batch_input_parsing()` returns -EIO (-5).
That routine had just set unsigned cursor to zero. `parse_input_buffer()` adds
the negative result to cursor **before** checking it (`input_parser.c:100-103`),
yielding `2^64 - 5`, then returns -1. The receiving flag is still false: the
assignment to true at line 105 was not reached. On the next valid header, the
batch-start routine is entered again and resets cursor to zero before consuming
16 bytes. The subsequent valid batch completes byte-for-byte correctly, restores
input readiness, and its trace is admitted. No explicit reset was needed for
this specific failure/retry sequence. The wrapped value is not used as an index
on that path. Other error locations and allocation failures are not covered.

The arithmetic wrap is defined unsigned behavior, so a clean UBSan run does not
make it a sensible parser-state policy. Checking the batch-start return before
adding it would remove that dirty cursor, but would **not** solve interrupted-
stream ambiguity. No production correction is implemented here.

### Tests, evidence and the unfulfilled safety requirement

Three passing characterization tests record the outcomes above, including exact
returns, cursors, completion/receiving state, readiness, payload digest and counted
preparation/measurement calls. The RDBF defect test is explicitly named
`test_recovery_legacy_risk_interrupted_rdbf_header_completes_old_batch`; it does
not declare false admission acceptable.

`test_recovery_interrupted_rdbf_safety_invariant` asserts the desired invariant:
no mixed-data readiness, trace rejection and zero measurement calls. It is an
explicit **expected failure** until recovery is corrected. Its subprocess,
timeout, JSON and teardown checks run in `setUp`, outside unittest's expected-
failure scope, so an ASan/UBSan abort or process failure is a real test failure.
The ordinary characterization independently checks the full observed behavior.
Future recovery work must update the legacy expectation and remove the expected-
failure marker; a newly passing invariant otherwise produces an unexpected-success
failure, making the pending requirement visible.

Ordinary, separate ASan and separate UBSan runs each report **29 tests: 28 passed
and 1 expected failure**. No sanitizer diagnostic appeared. All 102 existing
input-format, descriptor, preparation, coverage and resource-lifetime regressions
passed, as did Flake8, strict mypy, Pylint and `git diff --check`. The existing
LeakSanitizer environment limitation remains. Diagnostic code never indexes memory
with a parser cursor; digest reads check actual tracked allocations. No source
fix, new kernel ABI, CI change, allocation-failure injection or loaded-kernel
experiment is part of this stage.

### Smallest deterministic recovery design and B3.3d requirements

The existing byte stream cannot distinguish an abandoned upload's continuation
from a fresh upload starting with the same bytes. Resetting on every write would
break valid multiwrite parsing; scanning for plausible headers would interpret
ordinary payload as control. Existing callbacks alone cannot infer sender intent.

The minimal protocol addition is an **explicit abort/begin boundary before a
fresh retry**, with its eventual transport/ABI still to be designed. Reset must
cover receiving, cursor, section indices/bounds and partial semantic state for
the selected parser; invalidate dependent readiness and result pagination; and
leave resource ownership safe for a new batch. It must not assume current
init/free functions provide that reset. Allocation-failure cleanup still needs
separate characterization before a failure-safe implementation is specified.

B3.3d should bind begin, continuation, completion and abort to a preparation
generation, reject late chunks from an older attempt, prevent aborted/failed
attempts from publishing readiness, and bind inputs/results to their completed
test-case generation. Trace admission and pagination must enforce the same
identity under synchronization. A generation descriptor alone does not delimit
streams or make shared globals atomic. Endpoint names, ownership and locking are
not implemented by this characterization stage.

## B3.3c.4b preparation failure returns and ownership

The production resource audit is in
[RESOURCE_OWNERSHIP.md](RESOURCE_OWNERSHIP.md). It documents acquisition, apparent
ownership, release paths, partial failure and reuse for utility/data pages and
mapping, page arrays, code/executable permissions, sandbox aliases/descriptor,
PTE caches/snapshots, code/fault-handler metadata, parser buffers and results.
It distinguishes explicit source control flow from untested kernel behavior.

Actual allocator/code-loader functions remain stubbed: native pages, vmap/PTE
walking and executable-permission APIs are not host facilities, and loading the
real ARM64 template/macro implementation would require native architecture
dependencies. No replacement memory-manager model is introduced. The same actual
`test_case_store()` is compiled; the stubs only count calls and return configured
results. The bounded mode is:

```text
parser-baseline failure allocation|code first|replacement RCBF RDBF PAGED_RDBF
```

`allocation` makes `allocate_sandbox()` return -ENOMEM. `code` makes allocation
return zero and `load_sandbox_code()` return -EINVAL. These are synthetic
function-return conditions, not reproduction of a specific native allocation or
macro-expansion failure. The callback uses its production `CHECK_ERR` macro and
returns **-EIO** for either nonzero preparation result, after successful parsing.
The final parser return is 36 with `finished=true`; earlier returns remain
16, 48, 96 and 24. JSON distinguishes this from the callback's final -EIO and
`consumed=null`. The decoded-payload digest remains correct: parsing success is
not preparation readiness.

The replacement scenarios first prepare code and a real 33-input batch, then
use actual `trace_show()` with a successful measurement stub to leave result
cursor zero after its 4032-byte first page. Failed replacement invalidates that
pending cursor before parsing. Each scenario then clears **only** the stub error
and uploads a fresh valid RCBF in the same process, without resetting parser
state, flags or counters. Before uploading fresh inputs, a second trace probe
must still be rejected even though code preparation has now succeeded.

| Failure point | When | Cumulative allocation / code calls at failure | Calls after successful code retry | Measurement calls before / after failure probe / after input reupload and trace |
| --- | --- | --- | --- | --- |
| Allocation returns -ENOMEM | First preparation | 1 / **0** | 2 / 1 | 0 / 0 / 1 |
| Code loading returns -EINVAL | First preparation | 1 / 1 | 2 / 2 | 0 / 0 / 1 |
| Allocation returns -ENOMEM | Replacement | 2 / **1** | 3 / 2 | 1 / 1 / 2 |
| Code loading returns -EINVAL | Replacement | 2 / 2 | 3 / 3 | 1 / 1 / 2 |

In all four failure cases the callback returns -EIO, both readiness flags are
false, cursor is -1, and the trace probe returns -EIO without changing cursor,
`unfinished_call` or the output buffer. Failed allocation skips code loading.
Following successful code retry, only `tc_ready` is true. Reuploading valid inputs
restores both flags and admits fresh stubbed measurement with the exact expected
17-byte single-input output. No old result page resumes in these sequences.
The new `sandbox_ret` / `code_ret` fields record each function's **last actual
stub return**, or null if never called; invocation counts distinguish a skipped
code loader from a retained earlier successful return.

Four new test methods cover these failures and a subsequent successful callback
retry after **each** one. Ordinary, separate ASan and separate UBSan runs each
report **33 tests: 32 passed and the existing 1 expected failure**. No sanitizer
finding appeared; the LeakSanitizer limitation remains. All 102 existing
input-format, descriptor, preparation, coverage and resource-lifetime regressions
passed, along with Flake8, strict mypy, Pylint and `git diff --check`.

No production source, CI or interrupted-RDBF safety test was changed. That
expected failure still records a real unresolved safety requirement; it is not
a passing safety assertion. The failed native preparation may already have freed,
replaced, zeroed or partially overwritten resources that these stubs never own.
Consequently successful host retry proves parser/callback sequencing only, not
native retry safety or resource cleanup. Those responsibilities and the smallest
proposed B3.3d milestone are listed in the ownership audit.
