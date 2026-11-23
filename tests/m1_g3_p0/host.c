// SPDX-License-Identifier: MIT
// Synthetic backend ONLY. Never links probe.S or the native identity backend.
#define _GNU_SOURCE
#include "worker.h"
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
const int p0_synthetic_backend = 1;
static unsigned chosen, cpu_calls, mask_calls, attempts, maps;
static int mode(const char *name)
{
    const char *value = getenv("P0_HOST_FAULT");
    return value && strcmp(value, name) == 0;
}
int p0_platform(const p0_plan *plan, cpu_set_t *allowed, p0_identity *id)
{
    if (mode("platform")) { errno = EINVAL; return -1; }
    if (mode("limits")) {
        struct rlimit cpu;
        struct itimerval wall;
        if (getrlimit(RLIMIT_CPU, &cpu) || getitimer(ITIMER_REAL, &wall)) return -1;
        fprintf(stderr, "limits:%lu:%lu:%ld\n", (unsigned long)cpu.rlim_cur,
                (unsigned long)cpu.rlim_max, (long)wall.it_value.tv_sec);
    }
    CPU_ZERO(allowed);
    for (unsigned i = 0; i < 8; ++i) CPU_SET(i, allowed);
    memset(id, 0, sizeof(*id));
    strcpy(id->kernel, plan->field[KERNEL]);
    strcpy(id->compatible[0], "apple,j293"); strcpy(id->compatible[1], "apple,t8103");
    strcpy(id->like[0], "fedora"); id->nlike = 1; id->ncompatible = 2;
    id->midr = plan->cpu == 0 ? 0x611f0221 : 0x611f0231;
    return 0;
}
int p0_pin(unsigned cpu)
{
    if (mode("affinity")) { errno = EINVAL; return -1; }
    chosen = cpu; return 0;
}
int p0_mask(cpu_set_t *mask)
{
    CPU_ZERO(mask); CPU_SET(chosen, mask);
    if (++mask_calls == 2 && mode("mask_after")) CPU_SET(chosen ? 0 : 4, mask);
    return 0;
}
int p0_cpu(void)
{
    ++cpu_calls;
    if ((mode("cpu_before") && cpu_calls == 3) || (mode("cpu_after") && cpu_calls == 4))
        return chosen ? 0 : 4;
    return (int)chosen;
}
void *p0_map(size_t bytes, int protection)
{
    if (++maps == 2 && mode("allocation")) { errno = ENOMEM; return MAP_FAILED; }
    size_t extra = P0_PAGE;
    char *raw = mmap(NULL, bytes + extra, protection, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED) return raw;
    char *aligned = (char *)(((uintptr_t)raw + P0_PAGE - 1) & ~(uintptr_t)(P0_PAGE - 1));
    size_t leading = (size_t)(aligned - raw), trailing = extra - leading;
    if (leading && munmap(raw, leading) != 0) abort();
    if (trailing && munmap(aligned + bytes, trailing) != 0) abort();
    return aligned;
}
int p0_protect(void *address, size_t bytes, int protection)
{
    if (mode("protection")) { errno = EACCES; return -1; }
    return mprotect(address, bytes, protection);
}
void p0_clear_old(void) { }
static void attempt(volatile uint64_t *address, uint64_t value, p0_capture *capture, unsigned op)
{
    ++attempts;
    if (attempts == 3 && mode("trap")) raise(SIGILL);
    if (attempts == 3 && mode("hard_kill")) raise(SIGKILL);
    if (attempts == 3 && mode("timeout")) raise(SIGALRM);
    if (mode("no_status")) return; // Must retain invalid prefilled status, never fabricate zero.
    capture->loaded = *address;
    capture->status = op == 1 || (op == 0 && mode("adjacent_fail"));
    if (mode("clear_success")) capture->status = 0;
    if (mode("bad_status")) capture->status = 2;
    if (capture->status == 0) *address = value;
    capture->after = *address;
    if (mode("bad_value")) ++capture->loaded;
    if (mode("bad_canary")) address[1] ^= 1;
}
void p0_adjacent(volatile uint64_t *p, uint64_t v, p0_capture *c) { attempt(p, v, c, 0); }
void p0_clear(volatile uint64_t *p, uint64_t v, p0_capture *c) { attempt(p, v, c, 1); }
void p0_sham(volatile uint64_t *p, uint64_t v, p0_capture *c) { attempt(p, v, c, 2); }
