# B3.3d.5a–5b: native sandbox ownership and unpublished release

Stage 5a records actual acquisitions in
[sandbox_manager.c](../../rvzr/executor_km/sandbox_manager.c). Stage 5b uses that
record for the two unpublished acquisition-failure releases. Neither establishes
failure-safe published cleanup, safe retry, synchronized admission or activates
the [kernel integration plan](KERNEL_INTEGRATION_PLAN.md). No kernel allocator
is emulated by the host parser tests.

## Existing relationships, before the record

- `allocate_util_and_data()` first calls `safe_free_util_data()`, then obtains a
  contiguous `alloc_pages()` block, a `kmalloc()` page-pointer array and a `vmap()`
  address. The array refers to pages within that one block; it does not own each
  page separately. The physical block can be larger than the mapped page count
  because allocation uses an order, while `vmap()` uses the rounded request.
- `vaddr_unaligned` owns the mapping. `vaddr_aligned` is an interior, borrowed
  alias and must never be passed to `vunmap()`. The usable extent begins after
  that alignment prefix. `sandbox->util` and `sandbox->data` borrow from it.
- `allocate_code()` first calls `safe_free_code()`, then `vmalloc()` and requests
  X permissions on a PAGE_SIZE-rounded extent. The private code pointer owns
  that allocation; `sandbox->code`, `loaded_test_case_entry` and loader/fault
  aliases borrow it. X/NX return values were ignored, including NX before free.
- The global `sandbox` pointer owns a separately `kmalloc()`-allocated descriptor;
  its members are borrowed pointers. Current teardown does not free that
  descriptor or clear all borrowed aliases. This stage preserves that behavior.
- `old_n_actors` decides whether replacement helpers run. It is the last
  successful preparation count, not surviving ownership or capacity. Lower-count
  and repeated-count calls can reuse larger allocations; a later increase can
  allocate again even if the existing allocation would fit.

## Private record and update points

The public `sandbox_t`, `actor_data_t`, `actor_code_t` and `util_t` are unchanged.
The record is private, has no getter, and authorizes no operation.

Source update points: private record type at :21, current record at :32 and code
record at :40;
[utility/data acquisition](../../rvzr/executor_km/sandbox_manager.c#L115) and
[legacy published release](../../rvzr/executor_km/sandbox_manager.c#L52);
[code acquisition](../../rvzr/executor_km/sandbox_manager.c#L189) and
[release](../../rvzr/executor_km/sandbox_manager.c#L73).
Alias publication at :89, growth decisions at :230, initialization at :314 and
teardown at :350 keep their existing behavior. Stage 5b does not change code
storage, loading or permission calls.

`struct util_data_allocation` is now used both for the function-local `acquired`
record during acquisition and for `util_data` after successful mapping. There is
one definition of the fields, no second manager. In the table, utility/data field
semantics also apply to `acquired` before the ownership handoff.

| Record / field | Meaning and validity |
| --- | --- |
| `util_data.backing_head`, `backing_order` | Original contiguous page-block owner and acquired order. Order is meaningful only while the head is nonnull; backing capacity is `PAGE_SIZE * 2^order`. |
| `util_data.page_array`, `num_pages` | Owned pointer array and its initialized entry count. These describe the subset prepared for mapping, not the entire order-sized backing block. |
| `util_data.vaddr_unaligned` | Original owned `vmap()` mapping, when nonnull; its extent is `num_pages * PAGE_SIZE`. |
| `util_data.vaddr_aligned`, `usable_size`, `actor_capacity` | Borrowed aligned alias, mapped bytes remaining after its prefix, and whole actor records fitting after `sizeof(util_t)`. Capacity is derived from the acquired mapped extent, not the latest requested actor count. Zero when no mapping exists. |
| `code_data.base`, `size`, `actor_capacity` | Owned `vmalloc()` pointer, successfully requested object-byte capacity, and complete actor-code records fitting in it. Bytes in allocator page padding are not advertised as additional object capacity. |
| `code_data.permission_pages` | PAGE_SIZE-rounded extent used by the existing X/NX calls. It describes their requested range, not proven permissions or additional whole actor slots. |
| `code_data.last_permission_request`, `last_permission_result` | Most recent completed X/NX call and its raw return value. NOT_REQUESTED means no observed call for the new allocation; result is then not meaningful. Retained after free as last-call diagnostics, not evidence of live executable storage. |
| `sandbox` | Existing descriptor owner; its public members remain borrowed aliases, potentially stale after failed replacement. No extra duplicate descriptor-owner pointer is necessary. |

On page-block success record its head/order immediately in `acquired`, not the
shared current record. On page-array success,
initialize its entries and record the count before mapping. On mapping success,
record the original address, then derive the interior alias, remaining bytes and
actor capacity. Then transfer ownership to `util_data` by structure assignment;
the local record is never released after that handoff. Until then, no new pointer
is passed to sandbox publication, PTE caching, code expansion or execution.
On every actual local release clear the corresponding owner and extent;
clearing metadata never dereferences released storage.

On code allocation success record byte/actor capacity and mark permission status
NOT_REQUESTED. Preserve the existing reset/X-call sequence. Capture the raw X
result and request kind without branching on them. Before code free, capture
the raw NX result, still perform the existing free, then clear owned capacities.
Keep the last completed transition result for diagnosis. This is not a claim
that all PTEs have known permissions: other code changes PTEs, a failed call may
have partial effects, and no permission verification is introduced.

## Partial failures: before and after

| Path | Existing effect, preserved | Additional record after this stage |
| --- | --- | --- |
| `alloc_pages()` fails | Old utility/data mapping and pages have already been released. Return `-ENOMEM`; code may still be the previous allocation. | No utility/data owners or usable capacity; old public aliases are still uncorrected. |
| Page-array allocation fails | Free newly acquired backing block; return `-ENOMEM`. | Stage 5b releases the local recorded head/order, then clears them. No array/map/capacity and no handoff to `util_data`. |
| `vmap()` fails | Free array, then block; return `-ENOMEM`. | Stage 5b frees the local owned array, clears its count, releases the recorded head/order and clears them. No mapping/capacity or handoff. |
| Code `CHECKED_VMALLOC` fails | Old code was freed; macro returns `-ENOMEM` from `allocate_code()`. Newly acquired utility/data may remain owned; aliases have not been refreshed. | No code owner/capacity; preceding NX call status remains historical. Utility/data ownership remains recorded independently. |
| X or NX call returns an error | Error remains ignored by existing control flow; allocation success or free continues. | Raw error is recorded, never converted into a success flag. No permission rollback or safe-free guarantee is added. |
| Descriptor allocation fails | Already acquired utility/data and code remain allocated; return through the existing error path. | Those owners/capacities remain recorded; `sandbox` remains null. |
| Initial layout assertion fails | Acquired resources remain allocated; no enclosing cleanup is added. | Acquired owners remain recorded independently of initialization success. |
| PTE caching or later guest setup fails | Current allocations/aliases can exist alongside partial PTE metadata; `old_n_actors` is not advanced. | Owned storage remains accurately recorded; validity of borrowed PTEs, snapshots and published aliases is outside this record. |
| Same/decreased actor count | Reuse and zero existing utility/data, then recache; no allocation helper runs. | Actual acquired capacities remain unchanged. A failed prior growth can still make this legacy path unsafe. |
| Normal release / teardown | Same `vunmap`, page release, array release, NX and code-free order. Descriptor and some aliases remain. | Released owners/counts/extents are zeroed; descriptor ownership and historical permission result remain. |

The **published** `safe_free_util_data()` remains unchanged: it uses
`page_array[0]` and `get_order(num_pages * PAGE_SIZE)`, with the existing unmap /
page-free / array-free order. Code release and X/NX handling also remain unchanged.
Only the page-array-allocation and vmap failure branches now consume the local
recorded backing head/order, with the existing array-before-block order on vmap
failure. Those orders come directly from the successful `alloc_pages()` call;
they are not reconstructed from capacities or multiplied page counts. A null or
partially initialized page array is never dereferenced to recover the owner.

The two branches are reached only after that local block's successful acquisition.
The vmap branch additionally follows a successful array allocation and a null
mapping result. Each branch returns immediately after its one release sequence;
no later published-resource destructor receives those local owners. There is no
caller-supplied safety Boolean. Capacity values cannot authorize these releases:
they are not consulted at all. Existing unchecked request arithmetic is **not**
fixed or used as a new release gate. Input-bound/overflow validation remains a
separate prerequisite for a safe allocator as a whole.

The fields are updated synchronously at their acquisition/release points. They
are not a coherent concurrent snapshot, do not track external borrowers, and
cannot establish PTE restoration, absence of execution, instruction-cache state
or descriptor liveness for readers. Existing races and alias lifetime problems
remain. No previous executable preparation is restored on failure.
There is no stable diagnostic ABI or promise of debugger-visible retention;
compilers may elide fields that have no consumer yet. Future checked retirement
must consume the ownership record rather than treating it as an external snapshot.

## Validation and next gate

Stage 5a results, recorded locally on x86-64 WSL2, Python 3.12 / GCC 13.3.0:

| Check | Result |
| --- | --- |
| Parser/callback/attempt-upload suite, ordinary / ASan / UBSan | 59 per configuration: 58 passed, one unchanged expected failure. |
| Passive preparation-state suite, ordinary / ASan / UBSan | 20 passed per configuration. |
| Geometry and C/Python parity, input format, descriptor, preparation/model/coverage/lifetime, test-case components and traces | 175 passed. |
| Whitespace and bounded source comparison | Passed. The suffix from `allocate_sandbox()` onward is unchanged, as are reset instructions after owner renaming, explicit returns and allocation/release call order. This comparison is not C type analysis. |
| GCC `-fanalyzer -Wall -Wextra -Werror` on standalone production `preparation_state.c` | Compiled without diagnostics; does not cover the changed manager. |
| Direct GCC `-fsyntax-only -fanalyzer` attempt on `sandbox_manager.c` | Blocked by missing kernel build environment: userspace Linux headers lack required kernel typedefs, then `asm/cpu.h` is missing. No substitute kernel-memory shim was added. |
| Native ARM64 Ubuntu with/without VMBUILD; Asahi 16 KiB module builds | Not run locally: no AArch64 compiler or configured kernel build tree is installed. Existing CI build configurations are unchanged; results from earlier commits do not validate this patch. |

The ordinary 79-test parser/state baseline also passed before the production
edit, with the same expected failure. The ASan runs retain the existing
`detect_leaks=0` WSL2 setting; bounds checking and host allocation tracking remain
enabled. Host parser/attempt/state sanitizers validate their actual compiled
sources, not this native memory manager. No mock physical-page allocator or vmap
test is added, and no new native function requires an isolated function test.

Reproduction (the test wrappers already bound compile and scenario execution):

```sh
python -m unittest -f tests.unit_kernel_upload_parsers tests.unit_preparation_state -v
RVZR_PARSER_SANITIZER=address RVZR_PREPARATION_SANITIZER=address \
  python -m unittest -f tests.unit_kernel_upload_parsers tests.unit_preparation_state -v
RVZR_PARSER_SANITIZER=undefined RVZR_PREPARATION_SANITIZER=undefined \
  python -m unittest -f tests.unit_kernel_upload_parsers tests.unit_preparation_state -v
python -m unittest -f tests.unit_sandbox_geometry tests.unit_sandbox_geometry_c \
  tests.unit_input_format tests.unit_sandbox_descriptor tests.unit_preparation_lifecycle \
  tests.unit_model_preparation tests.unit_model_resource_lifetime \
  tests.unit_model_coverage_lifecycle tests.unit_tc_components tests.unit_traces -v
```

## Stage 5b dependency inspection and stopping boundary

### Native consumers and borrowed references

| Consumer and exact source | Ownership / lifetime dependency |
| --- | --- |
| [sandbox manager alias publication](../../rvzr/executor_km/sandbox_manager.c#L89), reuse/zeroing at :230, descriptor initialization at :314 | Public `sandbox->data/util` borrow the current mapping. The global descriptor owns neither backing pages nor mapping. Local temporary pointers in initialization borrow those aliases too. |
| [host PTE caching](../../rvzr/executor_km/page_tables_host.c#L208) | The arrays/container own metadata allocations. Their entries borrow leaf-PTE addresses for utility, actor-data and code VAs; no mapping lease or epoch is acquired. Partial walks can leave only a prefix updated. |
| [permission capture](../../rvzr/executor_km/page_tables_host.c#L255), restore at :312, user access at :346 | `orig_ptes` owns arrays of copied PTE values, not referenced pages. Those values encode old mappings and must be paired with live cached PTE pointers and the same allocation. Restoring permissions leaves the cache populated. |
| [faulty-PTE capture](../../rvzr/executor_km/page_tables_host.c#L385), restore at :409 | `faulty_ptes` owns copied values; updates/restoration dereference the borrowed actor PTEs. No per-capture validity/epoch proves which preparation the saved values belong to. |
| [load_sandbox_data](../../rvzr/executor_km/data_loader.c#L20) | Writes main/faulty/register/padding bytes through actor aliases before every test execution. It needs actual mapped capacity, not merely a nonnull descriptor. |
| [measurement loop](../../rvzr/executor_km/measurement.c#L245) | Touches utility priming memory at :261, loads inputs/changes permissions at :275, passes main data to the entry at :282 and copies utility results at :292. `measurements` is separately owned storage, but populating it requires the live sandbox. |
| [ARM64 entry/exit](../../rvzr/executor_km/arm64/entry_exit_points.h#L37), exit paths at :103/:144 | Registers borrow main/util addresses and save/restore SP through utility memory. Leaving the generated instruction stream is not enough: recovery and epilogue accesses must have completed. |
| [ARM64 register initialization](../../rvzr/executor_km/arm64/asm_snippets.h#L104), [tracing macros](../../rvzr/executor_km/arm64/macros.c#L235) and flush/reload at :295/:311 | Generated code reads register initialization and main payload, and primes/probes utility memory through borrowed base registers. Ordinary generated loads/stores and macro-stack accesses also require the live actor allocation. x86 entry/snippet counterparts use the same borrowed regions. |
| [ARM64 actor-switch expansion](../../rvzr/executor_km/arm64/macros.c#L167), :186/:209 | Code embeds absolute data/util/SP values. Unmapping data while retaining old code/entry/fault aliases can leave executable consumers of old addresses. x86 counterparts are at [x86/macros.c:102](../../rvzr/executor_km/x86/macros.c#L102), :126/:152. |
| [recovery](../../rvzr/executor_km/measurement.c#L212), trace pre/post at :122/:155/:324 | Faulty/special/original permissions are restored after execution. The sandbox wrapper discards the original-PTE restore return. Restoration uses borrowers; it is not cache retirement or proof that every failure path restored state. ARM outer fault recovery also uses [exception.S:185](../../rvzr/executor_km/arm64/exception.S#L185), :243/:264. |
| [legacy trace/readers](../../rvzr/executor_km/main.c#L248), binary code read :349, base reads :400/:405 and debug reads :535/:560 | Admission/results share globals. Base reads export addresses without leases; diagnostics/code reads can outlive failed preparation. Input buffers are separate owners, not sandbox backing. |
| [x86 guest mapping](../../rvzr/executor_km/x86/page_tables_guest.c#L297), [VMX host stack](../../rvzr/executor_km/x86/vmx.c#L722), [x86 permission macro](../../rvzr/executor_km/x86/macros.c#L703) | Additional mappings/SP or embedded PTE-address consumers exist on x86. No shared-manager retirement claim can ignore them. ARM guest mapping remains unimplemented at [arm64/page_tables_guest.c:23](../../rvzr/executor_km/arm64/page_tables_guest.c#L23). |

**No current reliable quiescence/retirement proof exists.** `tc_ready` and
`inputs_ready` gate sequential trace admission, not concurrent callers.
`unfinished_call` is an unlocked Boolean, becomes false after the trace returns,
and can remain true on its error path. It is not checked by allocation, a drain
primitive or proof of CPU/PTE restoration. Local IRQ/preemption disable in
`pre_run()` excludes neither another CPU nor concurrent upload/read callbacks.
No executor-wide lock or PTE-cache retirement API was found in the inspected
manager/measurement/interface paths.

`restore_orig_host_permissions()` restores entries but keeps borrowed pointers.
`free_page_table_manager()` at :466 frees metadata without restoring mappings or
excluding its consumers. It cannot be used as a generic safe retirement operation.
Current module exit ([main.c:751](../../rvzr/executor_km/main.c#L751)) releases
sandbox storage before that metadata and removes the kobject last. Its void early
return is not an unload veto. No safe unload/reload recovery is asserted.

Before published release can change, real production paths must jointly:

1. Exclude/drain trace execution, uploads, recovery and relevant readers through
   the synchronization boundary in the integration plan; withdraw admission and
   results before destructive mutation. The participating functions include
   `test_case_store`, `inputs_store`, `trace_show`, base/debug/binary readers,
   `allocate_sandbox` and module teardown.
2. Establish completed CPU/vector/PTE restoration for the retiring allocation.
   Snapshot/faulty-state validity and capacity must be explicit, and required
   snapshot storage must be reserved before the IRQ-off execution window.
3. Withdraw sandbox/embedded-code/entry borrowers, retire cached PTE references
   and their associated snapshots while mappings still live, then release the
   original mapping and recorded backing owner exactly once. These obligations
   require page-table-manager and loader cooperation, not just a sandbox flag.

Those changes exceed this task and are **not implemented**. The only new cleanup
consumes a local record before handoff, with no successful map on its failure
branches and no new alias/PTE publication by this call. This does not make the
earlier legacy `safe_free_util_data()` call safe, eliminate old stale addresses
(including possible address reuse), serialize global ownership handoff, or prove
the whole function safe during concurrent mutation. No new path claims to retire
published resources. Unknown published safety remains a blocker to activation,
not permission to retry or restore an older executable preparation.

### Concrete failed-growth retry analysis

Start with successfully prepared one-actor data/code, public aliases and cached
PTEs. The manager's `old_n_actors` is 1. Parsing a two-actor TC changes global
`n_actors`; [allocate_sandbox](../../rvzr/executor_km/sandbox_manager.c#L230)
enters growth. The old mapping is released **before** new acquisition. The new
local ownership boundary does not alter that destructive policy.

| Failure during growth to two | Surviving state | Later one-actor request under unchanged code |
| --- | --- | --- |
| Page block, page array or vmap fails | Old utility/data already released; local new resources released if acquired; current utility/data record empty. Old code may survive; public data/util aliases and cached PTEs still describe the old preparation. `old_n_actors=1`. | Growth condition `1 < 1` is false. Zeroing uses the null private aligned pointer. This is a source-derived invalid access path, not a native reproduction. |
| Utility/data succeeds, code allocation fails | Current utility/data capacity supports at least two actors; code owner/capacity is null/zero after old code release. Alias refresh has not run; `old_n_actors=1`. | Growth is skipped despite mismatched owners/capacities. Zeroing private new data may be in bounds, but PTE recaching uses old public aliases; loader can encounter stale code aliases and a null private code owner. Address reuse cannot establish correctness. |
| Both allocations and alias publication succeed, PTE caching or guest setup fails | New data/code owners and aliases exist; PTE metadata can be partial or belong to a different mapping. Manager `old_n_actors` stays 1; PTE manager's separate counters may already be 2. | Growth is skipped. Some recaching may succeed on retry, but this does not establish full cleanup/restoration or consistent metadata. Do not classify every such retry as a demonstrated crash, or as verified safe. |
| `allocate_sandbox()` succeeds, later code loading fails | New allocations/aliases exist and manager `old_n_actors=2`; code contents/entry/fault metadata can be partial. | One actor skips replacement. In-place reloading may proceed, but safe published recovery has not been established. A descriptor-allocation failure is not an additional normal branch in this scenario: the initial one-actor descriptor already exists. |

The corrected TC callback withdraws both readiness flags and results before
parsing and leaves them false on failure ([main.c:321](../../rvzr/executor_km/main.c#L321)).
That prevents a sequential trace immediately after failure; it does not prevent
a smaller retry reaching the inconsistent state, a later flag republish or a
concurrent reader/execution. Minimum future admission is actual serialized
ownership/alias/PTE consistency plus validated completion; requests after failed
replacement must remain rejected until checked cleanup succeeds, or remain
terminal. Neither `old_n_actors`, recorded capacity, `!receiving` nor a new
`safe_to_free` Boolean is sufficient. No retry guard/state integration is added.

### Stage 5b validation and next prerequisite

Fresh x86-64 WSL2 / GCC 13.3.0 results for stage 5b:

| Check | Result |
| --- | --- |
| Ordinary / ASan / UBSan parser-attempt and passive-state runs | Each ran 79: parser/attempt suite 58 passed plus the unchanged expected failure; passive state 20 passed. No sanitizer finding. |
| Selected Python regressions, same modules listed above | 175 passed. |
| `git diff --check` and bounded source comparison against the saved stage-5a working tree | Passed. Published release, alias publication, code/permission helpers, reset instructions and the entire suffix from `allocate_sandbox()` are unchanged; explicit returns and allocation/release call order are preserved. |
| GCC `-fanalyzer` on standalone preparation-state source | Passed without diagnostics; does not cover the changed native manager. |
| Direct GCC syntax/analyzer attempt on the changed manager | Blocked by absent kernel typedefs and `asm/cpu.h`, as in stage 5a. No configured kernel tree or AArch64 compiler is installed; no replacement kernel-memory shim was built. |
| Ubuntu ARM64 VMBUILD / non-VMBUILD and Asahi 16 KiB module builds | **Not run for this patch. Native verification remains pending.** Existing workflow/Kbuild files were not changed. All three existing CI module builds must compile the changed manager before this milestone is considered verified. |

Reproduction uses the existing commands above; separate sanitizer builds retain
their documented WSL2 settings. No new function, host allocator model, failure
injection or hardware test was introduced. The source comparison is not C type
checking, and passing parser/state tests cannot validate the new ownership
handoff or real physical-page/vmap release. Neither old build results nor a
successful 16 KiB compile would establish native retirement or runtime support.

The smallest remaining prerequisite is a real serialization/quiescence boundary
for existing resource consumers, followed by explicit retirement of the PTE
cache/snapshot/faulty-state borrowers. Only then can checked published utility/data
release consume recorded owners and clear public aliases. The current task stops
at unpublished acquisition cleanup; code retirement, protected transport and
safe retry remain unimplemented.
