// SPDX-License-Identifier: MIT
#ifndef P0_WORKER_H
#define P0_WORKER_H
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sched.h>
#define P0_PAGE 16384U
#define P0_BLOCKS 64U
#define P0_TRIALS (6U * P0_BLOCKS)
#define P0_JSON (512U * 1024U)
#define P0_STACK 65536U
#define P0_ALTSTACK 32768U
#define P0_INITIAL UINT64_C(0x1122334455667788)
#define P0_ATTEMPTED UINT64_C(0x8877665544332211)
#define P0_LEFT UINT64_C(0x13579bdf2468ace0)
#define P0_RIGHT UINT64_C(0xfedcba9876543210)
#define P0_PROTOCOL "m1-g3-p0-exclusive-v1"
#define P0_SCHEDULE "xorshift32-fy6-v1"
typedef struct {
    uint32_t cpu, seed, blocks, phase, synthetic;
    char field[11][129];
} p0_plan;
enum { RUN, SESSION, COHORT, TARGET, KERNEL, COMMIT, SOURCE, BINARY, DISASSEMBLY, BUILD, FROZEN };
typedef struct { uint64_t loaded, after; uint32_t status, padding; } p0_capture;
typedef struct {
    const char *json;
    size_t length;
    uint32_t completed;
} p0_prefix;
typedef struct {
    p0_prefix prefix;
    p0_capture capture;
    uint64_t before, left_before, right_before, left_after, right_after;
    int cpu_before, cpu_after;
    uint32_t condition;
} p0_record;
_Static_assert(sizeof(uintptr_t) == 8, "64-bit pointers required");
_Static_assert(offsetof(p0_capture, status) == 16 && sizeof(p0_capture) == 24, "Assembly capture ABI");
_Static_assert(sizeof(p0_record) <= 128 && sizeof(p0_prefix) <= 128, "Result geometry capacity");
_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "Signal-safe publication requires lock-free pointers");
void p0_adjacent(volatile uint64_t *, uint64_t, p0_capture *);
void p0_clear(volatile uint64_t *, uint64_t, p0_capture *);
void p0_sham(volatile uint64_t *, uint64_t, p0_capture *);
void p0_clear_old(void);
void p0_order(unsigned order[6], uint32_t *state);
size_t p0_results_bytes(unsigned blocks);
int p0_read_plan(int fd, p0_plan *plan);
/* Native backend is fixed at link time; no runtime synthetic/environment switch. */
typedef struct {
    char kernel[129], compatible[16][129], like[16][129];
    unsigned ncompatible, nlike;
    uint64_t midr;
} p0_identity;
extern const int p0_synthetic_backend;
int p0_platform(const p0_plan *, cpu_set_t *allowed, p0_identity *identity);
int p0_pin(unsigned cpu);
int p0_cpu(void);
int p0_mask(cpu_set_t *mask);
void *p0_map(size_t bytes, int protection);
int p0_protect(void *address, size_t bytes, int protection);
#endif
