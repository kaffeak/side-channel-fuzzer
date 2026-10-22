/// File: Sandbox memory management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "hardware_desc.h"

#include "actor.h"
#include "code_loader.h" // loaded_test_case_entry
#include "main.h"        // set_memory_x, set_memory_nx
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

#include "page_tables_guest.h"
#include "page_tables_host.h"

sandbox_t *sandbox = NULL; // Owns descriptor; its members are borrowed aliases.

// Private ownership only: not readiness, retry policy or a synchronized snapshot.
struct util_data_allocation {
    struct page *backing_head; // owns the original order-sized alloc_pages block
    int backing_order;        // valid only while backing_head is nonnull
    struct page **page_array; // owns array, whose entries borrow from the block
    int num_pages;            // initialized array entries, not backing-block size
    void *vaddr_unaligned;    // owns original vmap mapping of num_pages pages
    void *vaddr_aligned;      // borrowed interior alias, aligned to 8KB
    size_t usable_size;       // mapped bytes remaining after the alignment prefix
    size_t actor_capacity;    // whole actor_data_t records after sizeof(util_t)
};

static struct util_data_allocation util_data;

enum code_permission_request {
    CODE_PERMISSION_NOT_REQUESTED,
    CODE_PERMISSION_X,
    CODE_PERMISSION_NX,
};

static struct {
    void *base;               // owns vmalloc object; public code aliases borrow it
    size_t size;              // acquired object bytes, excluding allocator padding
    size_t actor_capacity;    // whole actor_code_t records in the object
    size_t permission_pages;  // extent passed to existing X/NX calls
    // Last completed call only, not verified current permissions; retained on free.
    enum code_permission_request last_permission_request;
    int last_permission_result; // meaningful only when request != NOT_REQUESTED
} code_data;

/// @brief Free util_data allocation (vmap + physical pages)
// Legacy published-resource path: does not establish quiescence or retire PTE references.
static void safe_free_util_data(void)
{
    if (util_data.vaddr_unaligned) {
        vunmap(util_data.vaddr_unaligned);
        util_data.vaddr_unaligned = NULL;
        util_data.vaddr_aligned = NULL;
        util_data.usable_size = 0;
        util_data.actor_capacity = 0;
    }
    if (util_data.page_array) {
        int order = get_order(util_data.num_pages * PAGE_SIZE);
        __free_pages(util_data.page_array[0], order);
        util_data.backing_head = NULL;
        util_data.backing_order = 0;
        kfree(util_data.page_array);
        util_data.page_array = NULL;
        util_data.num_pages = 0;
    }
}

/// @brief Free code allocation (vmalloc)
static void safe_free_code(void)
{
    if (code_data.base) {
        code_data.last_permission_result =
            set_memory_nx((unsigned long)code_data.base, code_data.permission_pages);
        code_data.last_permission_request = CODE_PERMISSION_NX;
        SAFE_VFREE(code_data.base);
        code_data.size = 0;
        code_data.actor_capacity = 0;
        code_data.permission_pages = 0;
        loaded_test_case_entry = NULL;
    }
}

/// @brief Initialize sandbox pointers after allocation
/// @return 0 on success, -ENOMEM on failure
static int init_sandbox_pointers(void)
{
    if (!sandbox) {
        sandbox = CHECKED_MALLOC(sizeof(sandbox_t));
    }
    sandbox->data = (actor_data_t *)((unsigned long)util_data.vaddr_aligned + sizeof(util_t));
    sandbox->code = (actor_code_t *)code_data.base;
    sandbox->util = (util_t *)util_data.vaddr_aligned;
    loaded_test_case_entry = code_data.base;
    return 0;
}

/// @brief Allocate memory for the Util and Data areas of the sandbox
/// @details
/// Constraints:
/// 1. Physical Continuity - Prime+Probe attacks require contiguous physical pages for PIPT caches
/// 2. 4KB Page Tables - Executor must manipulate individual PTEs (impossible with huge pages)
/// 3. 8KB Alignment - Memory must be aligned to 2-page boundary
///
/// Solution: alloc_pages() + vmap()
/// - cannot use kmalloc: physically contiguous BUT uses huge pages in direct mapping
/// - cannot use vmalloc: uses 4KB PTEs BUT not physically contiguous
/// - solution -> alloc_pages + vmap: physically contiguous AND creates new 4KB page tables
///
/// @param n_actors Number of actors
/// @return 0 on success, -ENOMEM on failure
static int allocate_util_and_data(size_t n_actors)
{
    safe_free_util_data();
    // Unpublished per-call owner for the two acquisition-failure cleanup branches.
    struct util_data_allocation acquired = {0};

    // calculate required memory sizes
    const size_t util_mem_size = sizeof(util_t);
    const size_t data_mem_size = n_actors * sizeof(actor_data_t);
    const size_t mem_size = util_mem_size + data_mem_size;
    size_t alloc_size = mem_size + 0x1000; // add 4KB to ensure we can align to 8KB boundary
    int num_pages = (alloc_size + PAGE_SIZE - 1) / PAGE_SIZE;
    int order = get_order(alloc_size);

    // allocate physical pages
    struct page *page = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
    if (!page) {
        PRINT_ERR("Error allocating util_and_data pages\n");
        return -ENOMEM;
    }
    acquired.backing_head = page;
    acquired.backing_order = order;

    // map the pages into kernel virtual address space
    acquired.page_array = kmalloc(num_pages * sizeof(struct page *), GFP_KERNEL);
    if (!acquired.page_array) {
        __free_pages(acquired.backing_head, acquired.backing_order);
        acquired.backing_head = NULL;
        acquired.backing_order = 0;
        PRINT_ERR("Error allocating page array\n");
        return -ENOMEM;
    }

    for (int i = 0; i < num_pages; i++) {
        acquired.page_array[i] = page + i;
    }
    acquired.num_pages = num_pages;

    acquired.vaddr_unaligned =
        vmap(acquired.page_array, acquired.num_pages, VM_MAP, PAGE_KERNEL);
    if (!acquired.vaddr_unaligned) {
        kfree(acquired.page_array);
        acquired.page_array = NULL;
        acquired.num_pages = 0;
        __free_pages(acquired.backing_head, acquired.backing_order);
        acquired.backing_head = NULL;
        acquired.backing_order = 0;
        PRINT_ERR("Error mapping util_and_data pages\n");
        return -ENOMEM;
    }

    // Align to 2-page (8KB) boundary
    unsigned long addr = (unsigned long)acquired.vaddr_unaligned;
    acquired.vaddr_aligned = (void *)ALIGN(addr, 0x2000);
    size_t mapped_size = (size_t)acquired.num_pages * PAGE_SIZE;
    size_t prefix = (unsigned long)acquired.vaddr_aligned - addr;
    acquired.usable_size = prefix <= mapped_size ? mapped_size - prefix : 0;
    acquired.actor_capacity = acquired.usable_size >= sizeof(util_t)
                                 ? (acquired.usable_size - sizeof(util_t)) / sizeof(actor_data_t)
                                 : 0;

    // Transfer ownership only after acquisition; do not release acquired after this handoff.
    // Publishing sandbox aliases and PTEs still happens later, without synchronization.
    util_data = acquired;

    return 0;
}

/// @brief Allocate memory for the Code area of the sandbox
/// @details
/// Uses vmalloc (physical continuity not required). Provides 4KB page tables for PTE
/// manipulation and executable memory support via set_memory_x().
/// @param n_actors Number of actors (each gets its own code area)
/// @return 0 on success, error code on failure
static int allocate_code(size_t n_actors)
{
    safe_free_code();

    code_data.base = CHECKED_VMALLOC(n_actors * sizeof(actor_code_t));
    code_data.size = n_actors * sizeof(actor_code_t);
    code_data.actor_capacity = code_data.size / sizeof(actor_code_t);
    code_data.last_permission_request = CODE_PERMISSION_NOT_REQUESTED;
    code_data.last_permission_result = 0;
    reset_code_area();

    size_t code_size = n_actors * sizeof(actor_code_t);
    code_data.permission_pages = DIV_ROUND_UP(code_size, PAGE_SIZE);
    code_data.last_permission_result =
        set_memory_x((unsigned long)code_data.base, code_data.permission_pages);
    code_data.last_permission_request = CODE_PERMISSION_X;

    return 0;
}

/// @brief Clears out the code area from previous executions and fills the area with NOPs
/// @param void
/// @return void
void reset_code_area(void)
{
    // fill the code area with NOPs
#if defined(ARCH_X86_64)
    memset(code_data.base, 0x90, sizeof(actor_code_t) * n_actors);
#elif defined(ARCH_ARM)
    for (int i = 0; i < n_actors * sizeof(actor_code_t) / 4; i += 1)
        ((uint32_t *)code_data.base)[i] = 0xd503201f;
#endif

    // initialize the main section with a single ret instruction
#if defined(ARCH_X86_64)
    ((uint8_t *)code_data.base)[0] = '\xC3';
#elif defined(ARCH_ARM)
    ((uint32_t *)code_data.base)[0] = 0xd65f03c0;
#endif
}

int allocate_sandbox(void)
{
    int err = 0;
    static int old_n_actors = 1;

    // Allocate sandbox in host memory
    if (old_n_actors < n_actors) {
        err = allocate_util_and_data(n_actors);
        CHECK_ERR("allocate_util_and_data");

        err = allocate_code(n_actors);
        CHECK_ERR("allocate_code");

        err = init_sandbox_pointers();
        CHECK_ERR("init_sandbox_pointers");
    }

    // Make sure that everything is property initialized
    memset(util_data.vaddr_aligned, 0, sizeof(util_t) + n_actors * sizeof(actor_data_t));

    err = cache_host_pteps();
    CHECK_ERR("cache_host_pteps");

    // when necessary, map the sandbox into guest memory and allocate VM management data structures
    if (test_case->features.includes_vm_actors) {
        err = allocate_guest_page_tables();
        CHECK_ERR("allocate_guest_page_tables");

        err = map_sandbox_to_guest_memory();
        CHECK_ERR("map_sandbox_to_guest_memory");
    }
    old_n_actors = n_actors;

    return err;
}

/// @brief Returns the number of pages allocated for the sandbox, including util area, code and data
/// @param void
/// @return number of pages; -1 on error
int get_sandbox_size_pages(void)
{
    if (!sandbox)
        return -1;

    return DIV_ROUND_UP(sizeof(util_t), PAGE_SIZE) +
           DIV_ROUND_UP(sizeof(actor_data_t) * n_actors, PAGE_SIZE) +
           DIV_ROUND_UP(sizeof(actor_code_t) * n_actors, PAGE_SIZE);
}

/// @brief Sets PTE values for the sandbox based on the current test case configuration
/// @param void
/// @return 0 on success; -1 on error
int set_sandbox_page_tables(void)
{
    int err = store_orig_host_permissions();
    CHECK_ERR("store_orig_host_permissions");

    if (test_case->features.includes_user_actors) {
        err = set_user_pages();
        CHECK_ERR("set_user_pages");
    }
    return 0;
}

void restore_orig_sandbox_page_tables(void) { restore_orig_host_permissions(); }

/// @brief Fast modification of the faulty page PTE; sets the permissions according to
/// actor_t->data_permissions
void set_faulty_page_permissions(void)
{
    set_faulty_page_host_permissions();
    set_faulty_page_guest_permissions();
    set_faulty_page_ept_permissions();
}

/// @brief Fast recovery of original permissions of the faulty page PTE
void restore_faulty_page_permissions(void)
{
    restore_faulty_page_host_permissions();
    restore_faulty_page_guest_permissions();
    restore_faulty_page_ept_permissions();
}

// =================================================================================================
int init_sandbox_manager(void)
{
    int err = allocate_util_and_data(1);
    CHECK_ERR("allocate_util_and_data");

    err = allocate_code(1);
    CHECK_ERR("allocate_code");

    err = init_sandbox_pointers();
    CHECK_ERR("init_sandbox_pointers");

    // ensure that the main_area of the first actor is aligned as expected
    int offset = (unsigned long)sandbox->data[0].main_area % 0x2000;
    ASSERT(offset == 0, "init_sandbox_manager");

    // self-test: To enable offset-based accesses in assembly code, we have to hardcode
    //            the layout of the data structures in sandbox_constants.h;
    //            This naturally creates a risk of mismatches, so we perform sanity checks here
    //            to ensure that the layout is as expected.
    util_t *util = sandbox->util;
    ASSERT(&util->l1d_priming_area[0] - (uint8_t *)util == L1D_PRIMING_OFFSET, "init_sandbox");
    ASSERT((uint8_t *)&util->vars.stored_rsp - (uint8_t *)util == STORED_RSP_OFFSET,
           "init_sandbox");
    ASSERT((uint8_t *)&util->vars.latest_measurement - (uint8_t *)util == MEASUREMENT_OFFSET,
           "init_sandbox");
    actor_data_t *data = &sandbox->data[0];
    ASSERT(&data->main_area[0] - (uint8_t *)util == UTIL_REL_TO_MAIN, "init_sandbox");
    ASSERT(&data->main_area[0] - &data->macro_stack[64] == MACRO_STACK_TOP_OFFSET, "init_sandbox");
    ASSERT(&data->faulty_area[0] - &data->main_area[0] == FAULTY_AREA_OFFSET, "init_sandbox");
    ASSERT(&data->reg_init_area[0] - &data->main_area[0] == REG_INIT_OFFSET, "init_sandbox");
    ASSERT(&data->overflow_pad[0] - &data->main_area[0] == OVERFLOW_PAD_OFFSET, "init_sandbox");
    ASSERT(sizeof(measurement_t) == MEASUREMENT_SIZE, "init_sandbox");

    return 0;
}

void free_sandbox_manager(void)
{
    safe_free_util_data();
    safe_free_code();
    free_guest_page_tables();
}
