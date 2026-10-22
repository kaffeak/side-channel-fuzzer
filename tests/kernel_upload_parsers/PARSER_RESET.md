# B3.3d.3: explicit production parser reset

`reset_test_case_parser()` and `reset_input_parser()` are explicit, destructive
parser-only operations. Neither is called by the existing sysfs callbacks or the
passive preparation-state component. There are no new upload boundaries, locks,
devices, readiness publication or hardware operations in this stage.

## State and ownership inventory

| Parser state | Existing lifetime | Successful explicit-reset postcondition |
| --- | --- | --- |
| RCBF `_is_receiving_test_case`, `_cursor` | Receiving persists after partial input; cursor remains at the end after completion or semantic failure. | False and zero. |
| RCBF `curr_section_id`, `curr_section_start`, `curr_section_end` | Previously function-static; section state can survive interrupted reception, including an index beyond actor zero. Moved to file-private variables without changing parsing logic. | All zero. |
| RCBF `n_actors`, `n_symbols`, `actors` | Updated on accepted headers; actor alias borrows the private actor allocation. | Counts zero, alias NULL. Input-parser state is not changed. |
| RCBF root `test_case` | Separately owned object; parser reads its size fields even before deciding that a call contains a new header. | Retained, fully zeroed root: all four sizes zero, all table/section aliases NULL, all feature flags false. A missing root is allocated zeroed. |
| RCBF `_allocated_actor_table`, `_allocated_symbol_table`, `_allocated_metadata`, `_allocated_data` | The actual owning pointers; root fields are borrowed aliases and may be partially installed after errors. | All released with their matching kfree/vfree operations and set NULL. Root aliases and `actors` are cleared first. |
| RCBF `highest_n_actors`, `highest_n_symbols` | Capacity high-water counters, separate from current logical counts; init/free do not reset them as a complete stream-reset contract. | Both zero, consistent with no retained payload allocation. |
| RDBF `is_receiving_inputs`, `cursor` | Receiving persists after interruption. A failed actor-count header leaves a wrapped unsigned cursor on the existing error path. | False and zero, including after that header error. |
| RDBF `n_inputs` | Current declared batch count; not receiving alone does not indicate validity. | Zero. |
| RDBF root `inputs` | Separately owned; a header failure can leave newly allocated root fields uninitialized. | Retained and fully zeroed: metadata/data sizes zero and aliases NULL. Missing root allocated zeroed. Reset does not read old root fields. |
| RDBF `allocated_metadata`, `allocated_data` | Private owning pointers, independent of whether root aliases were installed. | Both freed and NULL. |
| RDBF `highest_n_actors`, `highest_n_inputs` | Allocation high-water counters. | Both zero, matching released backing storage. |
| RDBF dependency `n_actors` | Owned by the TC parser and checked when accepting an input header. | **Unchanged by input reset**. A new input upload still requires its prepared parent TC. |

Source: [TC private state](../../rvzr/executor_km/test_case_parser.c#L24),
[TC reset](../../rvzr/executor_km/test_case_parser.c#L357),
[input private state](../../rvzr/executor_km/input_parser.c#L22), and
[input reset](../../rvzr/executor_km/input_parser.c#L198).
All other parsing temporaries, including the caller's `finished` output, are
per-call values. A caller must continue initializing `finished=false` for each
parse call; reset does not modify a previously returned output variable.

## Valid idle state and allocation policy

After a successful reset there is a nonnull empty root, no receiving stream,
zero cursor/capacity/logical counts and no payload allocations or aliases. RCBF
also has zero section state and features. The input parser preserves its external
TC actor-count dependency. Not receiving means idle, **not validated readiness**.

This deliberately differs from the legacy constructors' placeholder allocations:
TC initialization creates one-actor dummy sizes/backing storage, and input
initialization allocates one fragment/metadata entry with zero logical sizes.
Constructors/destructors are unchanged. Do not use free/init as an implicit
reset, or call init again on an already initialized parser. Reset is the explicit
operation for discarding an existing stream.

Reset frees every privately owned payload buffer rather than retaining ambiguous
high-water capacity. The next valid header allocates new backing storage through
the existing parser logic. Only the small root is retained; repeated resets of
an existing root allocate nothing. The next ordinary batch-start may replace that
root as before. This trades capacity reuse for an easily checked ownership
contract at explicit boundaries; legacy uploads that never call reset are unchanged.

If no root exists, reset allocates one using `CHECKED_ZALLOC`. A failed allocation
returns `-ENOMEM` after retiring stream state/backing storage, leaving the root
NULL. That is **not successful reset**: do not feed the parser until reset succeeds.
Tests cover successful root recreation after free; they do not inject allocation
failure or establish native allocator recovery. The error contract follows the
existing checked-allocation macro and requires future coordinator handling.

The helpers are safe under exclusive access to valid parser ownership state,
including successful parsing, partial reception and the tested parser failures.
They cannot repair arbitrary memory corruption, invalidate copies of pointers
held by consumers, or safely race parsing/execution. Invalidate preparation and
exclude consumers before calling them. TC reset does not clear input readiness,
`n_inputs` or an existing input batch; full preparation invalidation must also
retire/reset the input parser. No sandbox, code allocation, PTE, permission or
fault-handler state is touched.

## Real-parser host tests

The existing host executable compiles both production parser sources, calls the
actual public reset helpers directly, then feeds serializer-generated fixtures.
Read-only accessors appended in the separate parser translation units verify
all private reset fields and aliases; they do not change state. Reset scenarios
use direct parsing, with no callback invocation, readiness assignment or hardware.
For RDBF, the parent actor count comes from a real parsed RCBF.

Fourteen additional tests cover:

- Interrupted RCBF and RDBF -> reset -> complete valid input.
- Repeated reset before reception, in each format.
- Reset after successful parsing, including three actors and a 33-input batch,
  followed by a smaller valid object.
- RCBF missing-end semantic failure and RDBF actor-count mismatch -> reset -> retry.
  The semantic fixture includes start and does not depend on uninitialized `has_start`.
- Three interrupted/reset cycles per format without reinitializing the process.
- Interrupted later-actor RCBF section -> reset -> one actor, and the reverse
  one-actor -> reset -> valid three-actor case.
- Free -> reset recreates a valid root -> valid parsing, for each format.

The driver advances by positive **actual** consumption and resubmits only the
unconsumed tail. Tests require the existing return sequences, continuous total
consumption, final-only `finished=true`, and exact final cursor. For example,
one-actor recovery returns RCBF `[16,48,96,24,36]` and RDBF
`[16,16,4096,4096,4096]`, including positive short returns. Recovered payloads
are compared **byte-for-byte** against separate expected-payload files generated
from the fixture inputs, not reconstructed by a second parser. Comparisons check
tracked allocation ranges, section capacities and expected-file bounds before
reading. Existing FNV diagnostic comparisons remain as an additional check.

Reset records check a retained root and unchanged allocation-attempt count
(except successful recreation of a missing root). After resetting both parsers,
tracked live bytes equal precisely their two root allocations. Final teardown
must leave zero tracked allocations. Existing process, file, allocation, call and
timeout bounds remain in force; no artificial allocation padding is added.

Run:

```sh
python -m unittest -f tests.unit_kernel_upload_parsers -v
RVZR_PARSER_SANITIZER=address python -m unittest -f tests.unit_kernel_upload_parsers -v
RVZR_PARSER_SANITIZER=undefined python -m unittest -f tests.unit_kernel_upload_parsers -v
```

On x86-64 WSL2/GCC 13.3.0: **47 tests per configuration: 46 passed and the existing
one expected failure**, in ordinary, ASan and UBSan builds. No sanitizer finding
appeared. The existing LeakSanitizer environment limitation still applies;
allocation tracking independently checks teardown, not Linux allocator behavior.
The 148 passive-state, geometry/parity, input-format, descriptor, preparation,
coverage and model-lifetime regressions passed, including the 20 passive-state tests.
Flake8, strict mypy, Pylint (10/10) and whitespace checks passed. The expanded test
module retains a single shared compiler fixture and has a file-length-only Pylint
waiver; complex reset assertions are split into focused methods.

GCC `-fanalyzer` compiled the actual parsers, harness and extracted callbacks.
It reported the **pre-existing** `has_start` uninitialized read in the TC validator
([declaration](../../rvzr/executor_km/test_case_parser.c#L119),
[use](../../rvzr/executor_km/test_case_parser.c#L156)), plus existing signedness and
unused-callback-parameter warnings. No analyzer diagnostic names a new reset helper.
The analyzer pass retained warnings without `-Werror`; the ordinary build keeps
the existing narrow signedness/unused-parameter exceptions. This is not a clean
whole-parser static-analysis result. The validator issue remains separate work.
Full local diagnostics were recorded at `/tmp/rvzr-parser-reset-analyzer.txt`.
No native kernel/ARM64 module build or hardware execution was performed.

## Legacy defect and future coordinator

`test_recovery_interrupted_rdbf_safety_invariant` remains unchanged and expected
to fail. Untagged legacy callbacks do not call these resets: a new header can
still finish an interrupted old payload. Calling reset on every write would also
destroy valid streams. A successful explicit reset does not solve delayed chunks,
concurrency, validation completeness or preparation identity.

Future integration with [the passive state component](PREPARATION_STATE.md) must:

1. Restrict `rvzr_prep_init()` to fresh executor-instance construction. It must
   never reset a live instance or escape `UNRECOVERABLE`.
2. On accepted TC BEGIN, withdraw old eligibility/results and exclude consumers.
   Retire sandbox/code/PTE resources using their own ownership records **before**
   discarding parser metadata they might still require. Reset input and TC parsers;
   acknowledge cleanup only after both return zero and all native cleanup obligations
   hold. Only then permit the reserved attempt to enter/feed `TC_RX`.
3. On accepted input BEGIN, reset only the input parser before its first feed,
   retaining the named committed TC. Serialize the boundary so the passive
   component's `INPUT_RX` label cannot authorize a concurrent feed before reset.
   Failure invalidates the entire preparation under the conservative policy.
4. On valid ABORT/failure, revoke the attempt first, retire partial native resources
   under exclusion, then reset both parsers before declaring clean retry possible.
   Do not report cleanup success on a reset error. Unproven cleanup safety requires
   the terminal policy rather than a forced reinitialization or old-preparation rollback.
5. Before **every** parser call, check instance, bound attempt, kind/parent and
   receiving phase (`TC_RX` or `INPUT_RX`). `rvzr_prep_check_attempt()` alone accepts
   other active phases and is not feed authorization. Reject stale operations
   before calling reset or parsing, preserving a newer preparation unchanged.

The smallest next task is a host-only, attempt-bound adapter test: combine the
passive state component with these real reset/parser functions, using explicitly
limited native-cleanup stubs. Verify BEGIN/reset ordering, phase-gated feeding,
ABORT/reset and old-handle rejection before parser entry, including delayed chunks
after a newer BEGIN. Do not expose a device or wire callbacks yet. Such tests can
establish the adapter's logical/parser contract; actual ownership cleanup, locking,
generation-checked execution and legacy-interface gating remain later work.
