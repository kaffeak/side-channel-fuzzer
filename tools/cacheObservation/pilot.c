// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#if (!defined(__aarch64__) && !defined(__arm64__)) || \
    (!defined(__linux__) && !defined(__APPLE__))
#error "AArch64 Linux/macOS required; no emulated/alternate-clock measurement path"
#endif
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Little-endian AArch64 required"
#endif
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "platform.h"
#include "schedule.h"

enum { MAX_BLOCKS = 1024, SLOTS = 8, MAX_BYTES = 8388608 };
#define TARGET UINT64_C(0x1122334455667788)
typedef struct { uint64_t start, end, value; } timing_t;
typedef struct { timing_t time; unsigned slot, invalid; } sample_t;
_Static_assert(offsetof(timing_t, value) == 16 && sizeof(timing_t) == 24, "assembly ABI");
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "shared progress must be lock-free");
typedef struct {
    _Atomic unsigned completed;
    int stage, error, cpu_start, cpu_end;
    uint64_t frequency;
    uintptr_t target, buffer;
    sample_t samples[MAX_BLOCKS * SLOTS];
} result_t;
typedef struct {
    unsigned blocks, seed, bytes, stride;
    int cpu;
    const char *session, *commit, *binary_hash, *source_hash;
} config_t;
extern void g3_probe(const uint64_t *, timing_t *);
extern void g3_empty(const uint64_t *, timing_t *);
extern void g3_trial(const uint64_t *, const uint64_t *, size_t, size_t, timing_t *, unsigned);
extern uint64_t g3_frequency(void);
static const char *const series[] = {"ordered", "null", "repeat", "overhead"};
static const char *const stages[] = {"setup", "frequency", "counter", "measurement", "cleanup"};

static int64_t milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static int wait_worker(pid_t child, int limit_ms, int *sig, int *timeout)
{
    int status = 0;
    int64_t first = milliseconds();
    *sig = 0; *timeout = 0;
    for (;;) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) break;
        if (waited < 0 && errno != EINTR) return -1;
        int64_t now = milliseconds();
        if (first < 0 || now < first || now - first >= limit_ms) {
            *timeout = 1;
            if (kill(child, SIGKILL) != 0 && errno != ESRCH) return -1;
            while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return -1;
            break;
        }
        struct timespec pause = {0, 10000000};
        (void)nanosleep(&pause, NULL);
    }
    if (WIFSIGNALED(status)) { *sig = WTERMSIG(status); return 128 + *sig; }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
static int limits(void)
{
    struct rlimit core = {0, 0}, cpu;
    if (setrlimit(RLIMIT_CORE, &core) != 0 || getrlimit(RLIMIT_CPU, &cpu) != 0) return -1;
    if (cpu.rlim_cur > 5) cpu.rlim_cur = 5;
    if (cpu.rlim_max > 5) cpu.rlim_max = 5;
    return setrlimit(RLIMIT_CPU, &cpu);
}
static int measure(result_t *result, const config_t *cfg, size_t page)
{
    // This frame and the assembly leaf's (zero) stack needs are touched before probing.
    volatile unsigned char stack[65536];
    for (size_t i = 0; i < sizeof(stack); ++i) stack[i] = (unsigned char)i;
    if (stack[0] != 0) return 10;
    for (unsigned i = 0; i < cfg->blocks * SLOTS; ++i)
        result->samples[i] = (sample_t){0}; // Prefault from the measuring child too.
    uint64_t *target = mmap(NULL, page, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANON, -1, 0);
    uint64_t *buffer = mmap(NULL, cfg->bytes, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANON, -1, 0);
    if (target == MAP_FAILED || buffer == MAP_FAILED) {
        result->error = errno;
        if (target != MAP_FAILED) (void)munmap(target, page);
        if (buffer != MAP_FAILED) (void)munmap(buffer, cfg->bytes);
        return 10;
    }
    // Volatile stores initialize every word, not merely one byte per page.
    for (size_t i = 0; i < page / 8; ++i) ((volatile uint64_t *)target)[i] = TARGET;
    for (size_t i = 0; i < cfg->bytes / 8; ++i) ((volatile uint64_t *)buffer)[i] = i + 1;
    result->target = (uintptr_t)target; result->buffer = (uintptr_t)buffer;
    result->cpu_start = g3_cpu();
    result->stage = 2;
    timing_t probe;
    g3_empty(target, &probe); // Explicit access check; no synthetic timer or signal recovery.
    uint64_t previous = probe.end, first = probe.start;
    uint32_t random_state = cfg->seed;
    int failure = probe.end < probe.start ? 11 : 0;
    result->stage = 3;
    for (unsigned block = 0; block < cfg->blocks && !failure; ++block) {
        unsigned order[SLOTS];
        g3_order(order, &random_state);
        for (unsigned position = 0; position < SLOTS; ++position) {
            unsigned index = block * SLOTS + position, slot = order[position];
            sample_t *sample = &result->samples[index];
            sample->slot = slot;
            if (slot / 2 == 3) g3_empty(target, &sample->time);
            else g3_trial(target, buffer, cfg->bytes, cfg->stride, &sample->time,
                          slot == 1 ? 1U : 0U);
            // No arithmetic, result store or C/compiler action inside the assembly window.
            if (sample->time.end < sample->time.start || sample->time.start < previous)
                sample->invalid = 1;
            else if (sample->time.value != (slot / 2 == 3 ? 0 : TARGET)) sample->invalid = 2;
            previous = sample->time.end;
            atomic_store_explicit(&result->completed, index + 1, memory_order_release);
            if (sample->invalid) { failure = 11; break; }
        }
    }
    result->cpu_end = g3_cpu();
    if (!failure && previous <= first) failure = 12;
    if (!failure && cfg->cpu >= 0 &&
        (result->cpu_start != cfg->cpu || result->cpu_end != cfg->cpu)) failure = 13;
    if (!failure) result->stage = 4;
    int released_target = munmap(target, page), released_buffer = munmap(buffer, cfg->bytes);
    if (released_target != 0 || released_buffer != 0) { result->error = errno; failure = 14; }
    return failure;
}
static int number(const char *text, unsigned *output)
{
    if (!*text || strspn(text, "0123456789") != strlen(text)) return -1;
    errno = 0;
    char *end;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || *end || value > UINT32_MAX) return -1;
    *output = (unsigned)value;
    return 0;
}
static int token(const char *text, size_t length, const char *alphabet)
{
    return strlen(text) == length && strspn(text, alphabet) == length;
}
static int arguments(int argc, char **argv, config_t *cfg)
{
    *cfg = (config_t){64, 1, 1048576, 128, -1, NULL, NULL, NULL, NULL};
    unsigned seen = 0;
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 == argc) return -1;
        const char *key = argv[i], *value = argv[i + 1];
        unsigned bit = 0;
        if (!strcmp(key, "--session")) { bit = 1; cfg->session = value; }
        else if (!strcmp(key, "--commit")) { bit = 2; cfg->commit = value; }
        else if (!strcmp(key, "--binary-sha256")) { bit = 4; cfg->binary_hash = value; }
        else if (!strcmp(key, "--source-sha256")) { bit = 8; cfg->source_hash = value; }
        else {
            unsigned parsed;
            if (number(value, &parsed) != 0) return -1;
            if (!strcmp(key, "--blocks")) { bit = 16; cfg->blocks = parsed; }
            else if (!strcmp(key, "--seed")) { bit = 32; cfg->seed = parsed; }
            else if (!strcmp(key, "--prep-bytes")) { bit = 64; cfg->bytes = parsed; }
            else if (!strcmp(key, "--stride")) { bit = 128; cfg->stride = parsed; }
            else if (!strcmp(key, "--cpu") && parsed <= 1023) { bit = 256; cfg->cpu = (int)parsed; }
            else return -1;
        }
        if (seen & bit) return -1;
        seen |= bit;
    }
    const char *hex = "0123456789abcdef";
    if ((seen & 15) != 15 || !cfg->session[0] || strlen(cfg->session) > 40 ||
        strspn(cfg->session, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
            != strlen(cfg->session) || !token(cfg->commit, 40, hex) ||
        !token(cfg->binary_hash, 64, hex) || !token(cfg->source_hash, 64, hex)) return -1;
    return cfg->blocks < 1 || cfg->blocks > MAX_BLOCKS || cfg->seed == 0 ||
        cfg->bytes < 16384 || cfg->bytes > MAX_BYTES || cfg->stride < 8 || cfg->stride > 4096 ||
        cfg->stride % 8 || cfg->bytes % cfg->stride ||
        (uint64_t)6 * cfg->blocks * (cfg->bytes / cfg->stride) > UINT64_C(33554432) ? -1 : 0;
}
static void string(const char *value)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 32) printf("\\u%04x", (unsigned)*p);
        else putchar(*p);
    }
    putchar('"');
}
int main(int argc, char **argv)
{
    config_t cfg;
    long page = sysconf(_SC_PAGESIZE);
    struct utsname system;
    if (geteuid() == 0 || arguments(argc, argv, &cfg) != 0 || page < 4096 || page > 65536 ||
        (page & (page - 1)) || cfg.bytes % (unsigned)page || uname(&system) != 0) {
        puts("{\"kind\":\"error\",\"status\":\"failed\",\"stage\":\"arguments_or_environment\"}");
        return 2;
    }
    result_t *result = mmap(NULL, sizeof(*result), PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANON, -1, 0); // Only this parent and its child.
    if (result == MAP_FAILED) { perror("owned results mmap"); return 1; }
    memset(result, 0, sizeof(*result));
    atomic_init(&result->completed, 0);
    result->cpu_start = result->cpu_end = -1;
    pid_t frequency = fork();
    if (frequency == 0) {
        if (limits() != 0 || g3_pin(cfg.cpu) != 0) _exit(10);
        result->frequency = g3_frequency();
        _exit(0);
    }
    int freq_signal = 0, freq_timeout = 0;
    int freq_exit = frequency < 0 ? -1 : wait_worker(frequency, 2000, &freq_signal, &freq_timeout);
    pid_t worker = fork();
    if (worker == 0) {
        if (limits() != 0 || g3_pin(cfg.cpu) != 0) { result->error = errno; _exit(10); }
        _exit(measure(result, &cfg, (size_t)page));
    }
    int signal_number = 0, timed_out = 0;
    int worker_exit = worker < 0 ? -1 : wait_worker(worker, 10000, &signal_number, &timed_out);
    unsigned count = atomic_load_explicit(&result->completed, memory_order_acquire);
    int ok = worker_exit == 0 && !timed_out && count == cfg.blocks * SLOTS;
    printf("{\"kind\":\"metadata\",\"version\":1,\"experiment\":\"g3a-order-v1\","
           "\"session\":\"%s\",\"platform\":\"%s\",\"commit\":\"%s\","
           "\"binary_sha256\":\"%s\",\"source_sha256\":\"%s\",\"compiler\":",
           cfg.session, g3_platform(), cfg.commit, cfg.binary_hash, cfg.source_hash);
    string(__VERSION__);
    printf(",\"kernel\":"); string(system.release);
    printf(",\"machine\":"); string(system.machine);
    printf(",\"page_size\":%ld,\"blocks\":%u,\"seed\":%u,\"prep_bytes\":%u,"
           "\"stride\":%u,\"access_bytes\":8,\"selected_cpu\":", page, cfg.blocks, cfg.seed,
           cfg.bytes, cfg.stride);
    if (cfg.cpu < 0) printf("null"); else printf("%d", cfg.cpu);
    printf(",\"cpu_start\":");
    if (result->cpu_start < 0) printf("null"); else printf("%d", result->cpu_start);
    printf(",\"cpu_end\":");
    if (result->cpu_end < 0) printf("null"); else printf("%d", result->cpu_end);
    printf(",\"frequency_hz\":");
    if (freq_exit == 0 && result->frequency) printf("\"%" PRIu64 "\"", result->frequency);
    else printf("null");
    printf(",\"frequency_exit\":%d,\"frequency_signal\":%d,\"frequency_timeout\":%s,"
           "\"target_address\":\"0x%" PRIxPTR "\",\"buffer_address\":\"0x%" PRIxPTR "\"}\n",
           freq_exit, freq_signal, freq_timeout ? "true" : "false", result->target, result->buffer);
    for (unsigned i = 0; i < count && i < MAX_BLOCKS * SLOTS; ++i) {
        const sample_t *sample = &result->samples[i];
        unsigned slot = sample->slot;
        printf("{\"kind\":\"sample\",\"index\":%u,\"block\":%u,\"series\":\"%s\","
               "\"label\":%u,\"condition\":\"%s\",\"status\":\"%s\","
               "\"start_ticks\":\"%" PRIu64 "\",\"end_ticks\":\"%" PRIu64 "\",\"delta_ticks\":",
               i, i / SLOTS, series[slot / 2], slot % 2,
               slot / 2 == 3 ? "none" : (slot == 1 ? "target_before_sweep" : "target_last"),
               sample->invalid == 1 ? "counter_reversal" :
                   (sample->invalid == 2 ? "value_mismatch" : "ok"),
               sample->time.start, sample->time.end);
        if (sample->time.end < sample->time.start) printf("null");
        else printf("\"%" PRIu64 "\"", sample->time.end - sample->time.start);
        printf(",\"value\":\"%" PRIu64 "\"}\n", sample->time.value);
    }
    printf("{\"kind\":\"%s\",\"status\":\"%s\",\"samples\":%u,\"stage\":\"%s\","
           "\"errno\":%d,\"worker_exit\":%d,\"signal\":%d,\"timeout\":%s}\n",
           ok ? "complete" : "error", ok ? "ok" : "failed", count, stages[result->stage],
           result->error, worker_exit, signal_number, timed_out ? "true" : "false");
    int released = munmap(result, sizeof(*result));
    return fflush(stdout) == 0 && !ferror(stdout) && released == 0 && ok ? 0 : 1;
}
