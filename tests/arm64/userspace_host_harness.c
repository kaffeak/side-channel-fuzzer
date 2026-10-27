// SPDX-License-Identifier: MIT
// Host-only syscall/ownership tests. Invocation is a mock, NEVER native ARM64 evidence.
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static unsigned acquisitions, releases, protections, invocations, live;
static unsigned fail_acquire, fail_protect, fail_release;
static int saw_rx;
static struct { void *base; size_t span; int prot; } allocations[2];

static void *checked_mmap(void *address, size_t size, int prot, int flags, int fd, off_t offset)
{
    ++acquisitions;
    if (acquisitions == fail_acquire) { errno = ENOMEM; return MAP_FAILED; }
    assert(address == NULL && prot == PROT_NONE);
    assert(size == 3 * 4096 || size == 3 * 16384);
    assert(flags == (MAP_PRIVATE | MAP_ANONYMOUS) && fd == -1 && offset == 0);
    void *allocation = NULL;
    // Owned, zeroed host memory only. Permissions are recorded, not applied:
    // simulate either geometry independently of the host kernel's page size.
    assert(posix_memalign(&allocation, 16384, size) == 0);
    memset(allocation, 0, size);
    unsigned slot = allocations[0].base == NULL ? 0 : 1;
    assert(allocations[slot].base == NULL);
    allocations[slot].base = allocation;
    allocations[slot].span = size;
    ++live;
    return allocation;
}

static int checked_mprotect(void *address, size_t size, int prot)
{
    ++protections;
    assert(size == 4096 || size == 16384);
    assert((uintptr_t)address % size == 0);
    unsigned slot;
    for (slot = 0; slot < 2; ++slot) {
        if (allocations[slot].base != NULL &&
            address == (unsigned char *)allocations[slot].base + size &&
            allocations[slot].span == 3 * size) break;
    }
    assert(slot < 2); // Exact owned middle page, never a guard or an out-of-bounds range.
    assert(prot == (protections == 3 ? (PROT_READ | PROT_EXEC) : (PROT_READ | PROT_WRITE)));
    if (protections == fail_protect) { errno = EACCES; return -1; }
    if (prot == (PROT_READ | PROT_EXEC)) saw_rx = 1;
    allocations[slot].prot = prot;
    return 0;
}

static int checked_munmap(void *address, size_t size)
{
    ++releases;
    if (releases == fail_release) { errno = EIO; return -1; }
    assert(size == 3 * 4096 || size == 3 * 16384);
    assert(live > 0);
    unsigned slot = allocations[0].base == address ? 0 : 1;
    assert(allocations[slot].base == address && allocations[slot].span == size);
    allocations[slot].base = NULL;
    free(address);
    --live;
    return 0;
}

#define RVZR_ARCH_HOST_TEST
#define mmap checked_mmap
#define mprotect checked_mprotect
#define munmap checked_munmap
#define main unused_native_main
#include "../../tools/arm64_architectural_smoke.c"
#undef main
#undef mmap
#undef mprotect
#undef munmap

// Explicit nonexecuted stand-ins: no architectural measurements are manufactured.
const unsigned char rvzr_fixture[FIXTURE_BYTES] = {0};
const size_t rvzr_fixture_size = sizeof(rvzr_fixture);
void rvzr_arch_invoke(void *code, void *main, uint64_t selector, arch_state_t *state)
{
    (void)selector; (void)state;
    assert(saw_rx && live == 2);
    assert(main == (unsigned char *)allocations[0].base + allocations[0].span / 3);
    assert(code == (unsigned char *)allocations[1].base + allocations[1].span / 3);
    assert(allocations[0].prot == (PROT_READ | PROT_WRITE));
    assert(allocations[1].prot == (PROT_READ | PROT_EXEC));
    ++invocations;
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    unsigned scenario = (unsigned)strtoul(argv[1], NULL, 10);
    size_t span = 0;
    assert(region_span(4096, 36, &span) == 0 && span == 12288);
    assert(region_span(16384, 4096, &span) == 0 && span == 49152);
    assert(region_span(4096, 4097, &span) == -1);
    assert(region_span(16384, 16385, &span) == -1);
    assert(region_span(4096, 0, &span) == -1);
    assert(region_span(8192, 36, &span) == -1);
    assert(region_span(SIZE_MAX, 36, &span) == -1);
    if (scenario == 9 || scenario == 10) {
        pid_t child = fork();
        assert(child >= 0);
        if (child == 0) {
            if (scenario == 9) _exit(7);
            for (;;) pause(); // No fixture invocation; parent must bound and reap this child.
        }
        int status = 0, timed_out = 0;
        assert(wait_bounded(child, &status, &timed_out) == 0);
        assert(timed_out == (scenario == 10));
        if (scenario == 9) assert(WIFEXITED(status) && WEXITSTATUS(status) == 7);
        else assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        assert(waitpid(child, &status, WNOHANG) == -1 && errno == ECHILD);
    } else if (scenario == 11) {
        return failure("host_mock", EACCES, SIGTERM, 1, -1);
    } else if (scenario == 7) {
        region_t region = {0};
        assert(region_open(&region, 4096, 4096) == 0);
        assert(region_open(&region, 4096, 4096) == -1 && acquisitions == 1);
        fail_release = 1;
        assert(region_close(&region) == -1 && region.reservation != NULL && live == 1);
        fail_release = 0;
        assert(region_close(&region) == 0 && region.reservation == NULL && live == 0);
        assert(region_close(&region) == 0 && releases == 2); // idempotent cleanup
    } else {
        if (scenario == 1 || scenario == 2) fail_acquire = scenario;
        if (scenario >= 3 && scenario <= 5) fail_protect = scenario - 2;
        if (scenario == 6) fail_release = 1;
        result_t result = {0};
        size_t page = scenario == 8 ? 16384 : 4096;
        int error = execute_fixed(&result, page, 0, 7);
        assert(error == ((scenario == 0 || scenario == 8) ? 0 : 1));
        assert(invocations == ((scenario == 0 || scenario == 6 || scenario == 8) ? 1U : 0U));
        assert(result.stage == COMPLETE || result.error != 0);
        assert(live == (scenario == 6 ? 1U : 0U));
        if (scenario == 6) {
            assert(releases == 2 && result.stage == CLEANUP);
            // Verify retained mock ownership, then reclaim host test memory. For
            // production mmap reservations, child exit is the final backstop.
            for (unsigned slot = 0; slot < 2; ++slot) free(allocations[slot].base);
        }
    }
    printf("host-only geometry/cleanup scenario %u passed\n", scenario);
    return 0;
}
