# B3.3c.4b preparation resource ownership

This is a **source-based assessment**, primarily of the ARM64 host-actor path.
The callback tests compile actual parsers and callbacks but replace both
preparation functions with counted return-value stubs. No allocator, executable
mapping, code expansion or native cleanup behavior is established by those tests.
References below point to the production sources inspected for this stage.

## Ownership and release matrix

| Resource / apparent owner | Acquisition or mutation | Release | Partial-failure guarantee and reuse |
| --- | --- | --- | --- |
| Contiguous utility/data backing pages; sandbox manager's private `util_data` | [`sandbox_manager.c:85-113`](../../rvzr/executor_km/sandbox_manager.c#L85): frees previous resources, computes order, `alloc_pages`, records pages | [`:32-44`](../../rvzr/executor_km/sandbox_manager.c#L32): `__free_pages(page_array[0], recomputed_order)`; called on replacement and manager teardown | Page-array failure explicitly frees the just-acquired block; vmap failure frees it too. Old backing was already released. Failure after successful helper return has no enclosing rollback. Reused when no growth is requested. |
| Page-pointer array; sandbox manager | [`:105-113`](../../rvzr/executor_km/sandbox_manager.c#L105): `kmalloc`, filled from backing block | `kfree` in `safe_free_util_data`; also explicit vmap-failure cleanup at `:118-123` | Helper-local cleanup exists for those branches. Array is not a second owner of independent pages: cleanup uses the first page and block order. Actual allocator behavior is not emulated. |
| Utility/data virtual mapping and aligned interior address; sandbox manager | [`:116-128`](../../rvzr/executor_km/sandbox_manager.c#L116): `vmap`, then aligned alias | `vunmap` of **unaligned mapping base**, then aliases cleared in `safe_free_util_data` | External `sandbox->data/util` aliases are not cleared there. No-growth preparation zeroes reused memory at `:192`, so even retained allocations do not preserve the prior utility/data contents. |
| Code allocation and executable-page extent; sandbox manager | [`:139-150`](../../rvzr/executor_km/sandbox_manager.c#L139): frees old code, `vmalloc`, NOP/RET initialization, updates `old_x_size`, requests executable permissions | [`:48-54`](../../rvzr/executor_km/sandbox_manager.c#L48): requests NX, `vfree`, clears private code pointer and entry alias | X and NX return values are ignored. Allocation failure leaves no replacement code. Loader failures do not revoke X or free the code. Actual resulting permissions are unverified. Code is reused and overwritten on later loads unless the resize branch runs. |
| `sandbox_t` descriptor and its borrowed data/code/util pointers; sandbox manager | [`:59-68`](../../rvzr/executor_km/sandbox_manager.c#L59): `kmalloc` once, assigns aliases only after helper allocation | No matching descriptor `kfree` found. [`free_sandbox_manager():294-299`](../../rvzr/executor_km/sandbox_manager.c#L294) releases backing allocations but not the descriptor | A missing release is a source finding, not a measured native leak. Old aliases can survive backing release until a later successful `init_sandbox_pointers`. Reused whenever nonnull. |
| Host PTE-pointer arrays and container; page-table manager | [`page_tables_host.c:208-249`](../../rvzr/executor_km/page_tables_host.c#L208): replaces arrays on growth, fills borrowed PTE addresses; initialized at `:451-454` | [`:466-485`](../../rvzr/executor_km/page_tables_host.c#L466): `free_page_table_manager` frees metadata | Data-array allocation may succeed before code-array failure. PTE walking can stop after partial filling. No `allocate_sandbox` failure unwind invalidates those borrowed pointers. Later preparation recaches, but not transactionally. |
| Original permission snapshots and faulty-PTE scratch state; page-table manager | [`:440-456`](../../rvzr/executor_km/page_tables_host.c#L440): initial allocations; [`:255-290`](../../rvzr/executor_km/page_tables_host.c#L255) resizes/captures at execution setup | `free_page_table_manager`; permission restoration uses [`:312 onward`](../../rvzr/executor_km/page_tables_host.c#L312) | These are separate from page ownership. Snapshot restoration is not part of upload-error handling. Reusing/restoring snapshots after a mapping is retired must not dereference obsolete PTE pointers. Upload stubs exercise none of this. |
| Entry pointer, fault-handler alias, main prologue metadata; code loader / macro expansion / fault handler | [`sandbox_manager.c:67`](../../rvzr/executor_km/sandbox_manager.c#L67) publishes `loaded_test_case_entry`; loader clears/sets aliases at [`code_loader.c:80-82,128,155`](../../rvzr/executor_km/code_loader.c#L80). Prologue size is set at `:106`, held in [`macro_expansion.c:22-34`](../../rvzr/executor_km/macro_expansion.c#L22). ARM fault macros can also assign `fault_handler` at [`arm64/macros.c:337-346`](../../rvzr/executor_km/arm64/macros.c#L337) | Entry is cleared by `safe_free_code` **if code is nonnull**, and inside main loading. No loader rollback clears all aliases; [`free_code_loader():251`](../../rvzr/executor_km/code_loader.c#L251) and [`arm64/free_fault_handler():82`](../../rvzr/executor_km/arm64/fault_handler.c#L82) are no-ops | Scalars and borrowed addresses, not separately freed code allocations. An error before main-loader alias reset can leave old values; an error after main success can leave a published main entry with incomplete secondary sections. Fault-handler and prologue state can remain partially updated. |
| ARM64 guest-related preparation | [`arm64/page_tables_guest.c:54`](../../rvzr/executor_km/arm64/page_tables_guest.c#L54): allocation helper returns zero without allocating; mapping at `:23-27` is unimplemented and returns -ENOSYS | `free_guest_page_tables` is a no-op at `:56` | The VM-actor branch in `allocate_sandbox():198-203` can fail **after** host preparation. There is no ARM guest resource ownership to prove here. x86 has additional guest resources and needs a separate architecture-specific audit. |
| Parsed test case, actor/symbol/section buffers and input batch/backing buffers; respective parsers | Test-case parser batch creation and input parser batch-start functions; these can replace parser-owned objects independently of sandbox ownership | [`test_case_parser.c:356-363`](../../rvzr/executor_km/test_case_parser.c#L356), [`input_parser.c:198-203`](../../rvzr/executor_km/input_parser.c#L198) | Preparation callback errors do not call parser free or abort. Completed parsing is idle, so the tested stub-failure retries can parse a new RCBF. Interrupted-stream safety remains unresolved and is not repaired by freeing sandbox memory. |
| Measurement buffer and pagination cursor; measurement manager / main callback | [`measurement.c:348-364`](../../rvzr/executor_km/measurement.c#L348): initial vmalloc; growth updates count, frees old buffer, allocates replacement. Cursor is managed by `main.c` | [`free_measurements():369`](../../rvzr/executor_km/measurement.c#L369); uploads invalidate the cursor, not this allocation | No measurement allocation happens during the tested failed upload. The separate measurement allocator commits its size counter before allocation, so failure/retry needs its own audit. Old buffer contents can remain allocated while the cursor is invalid. |

The code loader owns code-content publication, not the backing allocation.
None of these host tests allocates a real `sandbox_t`, `struct page`,
executable region, PTE array or fault-vector resource.

## Verified source control flow and failure windows

1. **Destructive replacement, not candidate-and-commit.**
   [`allocate_sandbox():174-205`](../../rvzr/executor_km/sandbox_manager.c#L174)
   uses `old_n_actors` to choose a growth branch. `allocate_util_and_data` frees
   the previous mapping/pages **before** obtaining new ones. `allocate_code`
   similarly frees code before allocating replacement. Only after both succeed
   does pointer setup refresh `sandbox` aliases. The outer function returns on
   each error without rolling back earlier helpers. Same-count or decreasing-count
   preparation skips those allocation helpers but still zeroes utility/data and
   recaches PTEs. Thus a stubbed function-level failure does not prove that the
   real function attempted an allocation for the same actor count.

2. **Retry safety depends on which stage failed.**
   If data replacement fails after freeing the previous data, external aliases
   still name the old data while private aligned storage is null. The outer
   `old_n_actors` changes only after complete success. A later request that skips
   the growth branch can reach `memset` without rebuilding that state. If data
   succeeds but code allocation fails, new data remains owned, code may be null,
   and `sandbox` aliases have not yet been refreshed. If PTE caching fails later,
   the new sandbox may be installed while cache metadata is partial. These are
   source-derived failure paths; no native use-after-free, null dereference or
   successful allocator recovery was executed or measured.

3. **Code loading overwrites live storage before all sections succeed.**
   [`load_sandbox_code():39-54`](../../rvzr/executor_km/code_loader.c#L39)
   resets the allocation, then ORs section results while continuing to later
   actors. Expansion writes bytes before later assertions can fail
   (`:181-241`, [`macro_expansion.c:305-341`](../../rvzr/executor_km/macro_expansion.c#L305)).
   There is no saved old image or loader failure unwind. The main owner assertion
   at `code_loader.c:72` precedes clearing the entry/fault aliases at `:80-82`.
   Main success publishes entry at `:155` before secondary loading is known to
   succeed. An overall failure can therefore leave a null entry, an old entry
   into overwritten storage, or a nonnull main entry with incomplete remaining
   sections. No executable-permission revocation occurs in the loader error path.

4. **Readiness is an admission flag, not resource cleanup.**
   [`test_case_store():316-346`](../../rvzr/executor_km/main.c#L316)
   invalidates readiness/cursor, but `CHECK_ERR` simply returns -EIO on either
   preparation error ([`shortcuts.h:98-102`](../../rvzr/executor_km/include/shortcuts.h#L98)).
   No cleanup/rebinding is called. The trace guard rejects sequential execution
   while unready, but other interfaces are not a general liveness gate:
   [`main.c:349-360`](../../rvzr/executor_km/main.c#L349) copies code using the entry
   pointer without checking readiness, and `:400-407` reports base aliases.
   Reachability through those source paths is not a native fault reproduction.

5. **Existing teardown is not a validated abort operation.**
   Manager helpers clean some immediately acquired objects but provide no whole-
   preparation rollback. `free_sandbox_manager` does not free the descriptor or
   clear all its aliases; the code-loader destructor is empty. Page-cache metadata
   has a separate lifetime. Module initialization at `main.c:689-706` accumulates
   errors and has no explicit cleanup branch there; destructor calls are in
   `executor_exit():751 onward`. Init-failure unwind and in-place reinitialization
   are therefore additional source concerns, not properties inferred from Linux
   allocator behavior. No assumptions about automatic OS cleanup, page reuse or
   successful permission changes are made in this assessment.

## What the callback tests prove

The harness configures its two counted functions to return -ENOMEM or -EINVAL,
without allocating/filling/freeing native sandbox resources. The actual callback
turns either nonzero preparation result into -EIO. It leaves both readiness flags
false, result cursor -1, and rejects the trace probe. Code loading is skipped
when the allocation stub fails. A replacement first has a valid input batch and
an actual callback-generated pending result page; that cursor is invalidated.

After disabling only the simulated error, a fresh valid RCBF can be parsed and
prepared again with successful stubs. This restores `tc_ready` but not input
readiness. Only a successful RDBF reupload admits the final measurement stub.
This proves the **callback/parser sequence**, not native cleanup, rollback or
recoverability of `allocate_sandbox()` / `load_sandbox_code()` internals.

## Responsibilities for deterministic abort/begin

- Invalidate code/input readiness, pending results and all externally accessible
  code/fault/base aliases for the retiring attempt before any execution/read path
  can use them; define which diagnostic interfaces may inspect an unready state.
- Keep an explicit ownership/capacity record for every allocation, mapping and
  borrowed alias. Track actual initialized stages, not just the last successful
  actor/input counts. Release each acquired object once; support cleanup after
  every acquisition stage, including permission-change failure.
- Retire cached PTE pointers and generation-specific permission snapshots before
  unmapping their underlying resources; never restore permissions through stale
  pointers. Check executable/NX transition results where they determine safety.
- Either stage a complete candidate then publish it, or explicitly discard the
  previous preparation and leave a clean, inert, retryable state on any error.
  In-place overwrite cannot promise rollback to the old test case.
- Reset complete parser stream state at the explicit boundary, not every write;
  reject delayed chunks and prevent aborted/failed attempts from publishing
  readiness. Fixing cursor arithmetic alone does not delimit uploads.
- Bind parser completion, allocator/code publication, input validation, trace
  admission and pagination to the same generation under synchronization. Boolean
  readiness and a read-only descriptor do not provide atomic identity.

The smallest B3.3d implementation milestone should be an **isolated preparation
state/ownership representation with host tests for begin, failed-stage cleanup
accounting, abort and commit**. Keep it passive until concrete cleanup helpers
have an explicit partial-initialization contract. Integrating it with parser
boundaries and live allocations must be a later atomic change; publishing a
generation around the current destructive allocator alone would not establish
safe recovery. The mixed-RDBF expected failure remains unresolved throughout.
