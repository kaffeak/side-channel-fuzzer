# Host upload-parser baseline

This runs the repository's production `test_case_parser.c` and `input_parser.c` as host C code.
It does not load a module, execute test-case instructions, access sysfs or model
kernel concurrency. Only direct-parser mode is present; callback extraction,
readiness publication, generations and failure injection are outside this stage.

From a checkout with Revizor's Python dependencies and a native compiler:

```sh
python -m unittest tests.unit_kernel_upload_parsers -v
RVZR_PARSER_VERBOSE=1 python -m unittest tests.unit_kernel_upload_parsers -v
```

`CC` may select a native compiler/flags. Each scenario runs a fresh executable
process with a five-second timeout. Compilation has a 30-second timeout per
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
No kernel upload callbacks or readiness flags are tested.

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
`parse_input_buffer()`; there is no replacement parser or linker wrapping.

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
visible in verbose mode. Harness warnings remain fatal. `-O0` makes source-level
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
silently broaden the fix. Neither clean sanitizer output nor these seven
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

Header bounds, abort/retry reset, validation-failure signaling, callback error
propagation, allocation failures and concurrency remain separate work. The next
callback task should compile the actual `test_case_store()` with counted
allocation/code-loading stubs and characterize the negative-return/finished-true
combination, rather than infer its behavior from a replacement callback.
