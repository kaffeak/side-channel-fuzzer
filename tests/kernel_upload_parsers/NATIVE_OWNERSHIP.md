# B3.3d.5a: native sandbox ownership bookkeeping

This stage records actual acquisitions in
[sandbox_manager.c](../../rvzr/executor_km/sandbox_manager.c). It does not add
failure-safe cleanup, establish safe retry, synchronize admission or activate
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

Source update points: private records at :21/:38;
[utility/data acquisition](../../rvzr/executor_km/sandbox_manager.c#L112) and
[release](../../rvzr/executor_km/sandbox_manager.c#L49);
[code acquisition](../../rvzr/executor_km/sandbox_manager.c#L180) and
[release](../../rvzr/executor_km/sandbox_manager.c#L70).
Alias publication at :86, growth decisions at :221, initialization at :305 and
teardown at :341 keep their existing behavior; code-owner references are only
mechanically renamed to `code_data.base`.

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

On page-block success record its head/order immediately. On page-array success,
initialize its entries and record the count before mapping. On mapping success,
record the original address, then derive the interior alias, remaining bytes and
actor capacity. On every actual local release clear the corresponding owner and
extent; clearing metadata never dereferences released storage.

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
| Page-array allocation fails | Free newly acquired backing block; return `-ENOMEM`. | Head/order cleared after free, no array/map/capacity. |
| `vmap()` fails | Free array, then block; return `-ENOMEM`. | Clear array/count and block ownership at their respective releases; no mapping or usable capacity. |
| Code `CHECKED_VMALLOC` fails | Old code was freed; macro returns `-ENOMEM` from `allocate_code()`. Newly acquired utility/data may remain owned; aliases have not been refreshed. | No code owner/capacity; preceding NX call status remains historical. Utility/data ownership remains recorded independently. |
| X or NX call returns an error | Error remains ignored by existing control flow; allocation success or free continues. | Raw error is recorded, never converted into a success flag. No permission rollback or safe-free guarantee is added. |
| Descriptor allocation fails | Already acquired utility/data and code remain allocated; return through the existing error path. | Those owners/capacities remain recorded; `sandbox` remains null. |
| Initial layout assertion fails | Acquired resources remain allocated; no enclosing cleanup is added. | Acquired owners remain recorded independently of initialization success. |
| PTE caching or later guest setup fails | Current allocations/aliases can exist alongside partial PTE metadata; `old_n_actors` is not advanced. | Owned storage remains accurately recorded; validity of borrowed PTEs, snapshots and published aliases is outside this record. |
| Same/decreased actor count | Reuse and zero existing utility/data, then recache; no allocation helper runs. | Actual acquired capacities remain unchanged. A failed prior growth can still make this legacy path unsafe. |
| Normal release / teardown | Same `vunmap`, page release, array release, NX and code-free order. Descriptor and some aliases remain. | Released owners/counts/extents are zeroed; descriptor ownership and historical permission result remain. |

The existing release arguments are intentionally preserved: physical release
still uses `page_array[0]` and `get_order(num_pages * PAGE_SIZE)`, not the new
recorded head/order. These orders agree for valid, nonoverflowing allocations;
changing release to consume checked ownership is the next stage. This patch does
not repair unchecked allocation arithmetic or use capacities to bypass the
existing `old_n_actors` decisions.

The fields are updated synchronously at their acquisition/release points. They
are not a coherent concurrent snapshot, do not track external borrowers, and
cannot establish PTE restoration, absence of execution, instruction-cache state
or descriptor liveness for readers. Existing races and alias lifetime problems
remain. No previous executable preparation is restored on failure.
There is no stable diagnostic ABI or promise of debugger-visible retention;
compilers may elide fields that have no consumer yet. Future checked retirement
must consume the ownership record rather than treating it as an external snapshot.

## Validation and next gate

Recorded locally on x86-64 WSL2, Python 3.12 / GCC 13.3.0:

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

The next production task is checked utility/data retirement: consume the recorded
head/order/extent only after explicit quiescence and borrowed-PTE retirement,
clear public aliases under exclusion, and define partial-initialization release
postconditions. Unknown safety remains terminal. Code X/NX retirement and whole-
preparation retry need separate checked handling before protected activation.
