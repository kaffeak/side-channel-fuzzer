// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include "worker.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

static const char *const labels[6] = {
    "adjacent_a", "adjacent_b", "clear_a", "clear_b", "sham_a", "sham_b"
};
static const char *const field_names[11] = {
    "run_id", "session_id", "cohort_id", "target_id", "kernel_release", "source_commit",
    "source_sha256", "binary_sha256", "disassembly_sha256", "build_manifest_sha256",
    "frozen_calibration_sha256"
};
static _Atomic(p0_prefix *) published;
static volatile sig_atomic_t emitting, sent;
typedef struct { char *data; size_t used, line_start; int failed; } output;

size_t p0_results_bytes(unsigned blocks)
{
    if (blocks == 0 || blocks > P0_BLOCKS) return 0;
    return (128U + blocks * 6U * 128U + P0_PAGE - 1U) / P0_PAGE * P0_PAGE;
}
void p0_order(unsigned order[6], uint32_t *state)
{
    for (unsigned i = 0; i < 6; ++i) order[i] = i;
    for (unsigned i = 5; i; --i) {
        *state ^= *state << 13; *state ^= *state >> 17; *state ^= *state << 5;
        unsigned j = *state % (i + 1), save = order[i];
        order[i] = order[j]; order[j] = save;
    }
}
static int exact(int fd, unsigned char *out, size_t bytes)
{
    while (bytes) {
        ssize_t n = read(fd, out, bytes);
        if (n <= 0) { if (n == 0) errno = EPIPE; return -1; }
        out += n; bytes -= (size_t)n;
    }
    return 0;
}
static int u32(int fd, uint32_t *value)
{
    unsigned char b[4];
    if (exact(fd, b, 4) != 0) return -1;
    *value = (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
    return 0;
}
int p0_read_plan(int fd, p0_plan *plan)
{
    const unsigned char magic[8] = {'M','1','G','3','P','0',0,1};
    unsigned char input[8];
    memset(plan, 0, sizeof(*plan));
    if (exact(fd, input, 8) || memcmp(input, magic, 8) || u32(fd, &plan->cpu) ||
        u32(fd, &plan->seed) || u32(fd, &plan->blocks) || u32(fd, &plan->phase) ||
        u32(fd, &plan->synthetic)) return -1;
    if ((plan->cpu != 0 && plan->cpu != 4) || !p0_results_bytes(plan->blocks) || plan->phase > 1 ||
        plan->synthetic > 1 || plan->synthetic != (unsigned)p0_synthetic_backend ||
        (plan->phase == 0 && plan->seed != 101 && plan->seed != 102) ||
        (plan->phase == 1 && plan->seed != 201 && plan->seed != 202)) return -1;
    for (unsigned i = 0; i < 11; ++i) {
        unsigned char bytes[2];
        if (exact(fd, bytes, 2)) return -1;
        unsigned length = bytes[0] | (unsigned)bytes[1] << 8;
        unsigned maximum = i < 4 ? 64 : i == KERNEL ? 128 : i == COMMIT ? 40 : 64;
        if (length > maximum || (!length && (i != FROZEN || plan->phase != 0)) ||
            (i == FROZEN && plan->phase == 0 && length != 0)) return -1;
        if (exact(fd, (unsigned char *)plan->field[i], length)) return -1;
        for (unsigned j = 0; j < length; ++j) {
            unsigned char c = (unsigned char)plan->field[i][j];
            if (i < 4) {
                if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '-' || c == '_')) return -1;
            } else if (i == KERNEL) {
                if (c < 32 || c == 127) return -1; // Actual uname must also match.
            } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return -1;
        }
        if (i >= COMMIT && i != FROZEN && length != maximum) return -1;
        if (i == FROZEN && plan->phase && length != 64) return -1;
    }
    unsigned char extra;
    if (read(fd, &extra, 1) != 0) return -1; // EOF is mandatory; wall alarm bounds stalled input.
    return 0;
}
static int write_all(int fd, const char *text, size_t length)
{
    while (length) {
        ssize_t n = write(fd, text, length);
        if (n <= 0) return -1;
        text += n; length -= (size_t)n;
    }
    return 0;
}
static char *decimal(char *out, unsigned value)
{
    char digits[16]; unsigned n = 0;
    do { digits[n++] = (char)('0' + value % 10); value /= 10; } while (value);
    while (n) *out++ = digits[--n];
    return out;
}
static char *literal(char *out, const char *text)
{
    while (*text) *out++ = *text++;
    return out;
}
static void emit_error(const char *stage, unsigned error, unsigned sig)
{
    /* Only immutable, allocated-storage prefixes are read by the signal handler.
       Lock-free release/acquire publication excludes unexecuted or partial slots. */
    p0_prefix *prefix = atomic_load_explicit(&published, memory_order_acquire);
    unsigned completed = prefix ? prefix->completed : 0;
    int was_emitting = emitting;
    emitting = 1;
    if (!was_emitting && prefix && prefix->length > (size_t)sent)
        (void)write_all(STDOUT_FILENO, prefix->json + sent, prefix->length - (size_t)sent);
    char message[512], *end = message;
    if (was_emitting) *end++ = '\n';
    end = literal(end, "{\"kind\":\"error\",\"stage\":\"");
    end = literal(end, stage);
    end = literal(end, "\",\"message\":\"worker stopped; preserve partial evidence\",\"errno\":");
    end = decimal(end, error);
    end = literal(end, ",\"signal\":"); end = decimal(end, sig);
    end = literal(end, ",\"samples_emitted\":"); end = decimal(end, completed);
    end = literal(end, "}\n");
    (void)write_all(STDOUT_FILENO, message, (size_t)(end - message));
    (void)write_all(STDERR_FILENO, message, (size_t)(end - message));
}
static void trapped(int sig)
{
    /* No recovery/retry. Bound failure-output handling before restoring fatal delivery. */
    struct sigaction action = {0};
    action.sa_handler = SIG_DFL;
    if (sigaction(SIGALRM, &action, NULL) != 0) _exit(1);
    alarm(2);
    sigset_t mask;
    sigemptyset(&mask); sigaddset(&mask, SIGALRM);
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0) _exit(1);
    emit_error(sig == SIGALRM ? "wall_timeout" : sig == SIGXCPU ? "cpu_limit" :
               sig == SIGILL || sig == SIGBUS || sig == SIGSEGV || sig == SIGFPE ?
               "instruction_trap" : "interrupt", 0, (unsigned)sig);
    if (kill(getpid(), sig) != 0) _exit(1);
    /* SA_RESETHAND and return deliver the pending signal with its default action. */
}
static int handlers(void *stack)
{
    stack_t alternate = {.ss_sp = stack, .ss_size = P0_ALTSTACK};
    struct sigaction action = {0};
    action.sa_handler = trapped;
    action.sa_flags = SA_RESETHAND | SA_ONSTACK;
    sigfillset(&action.sa_mask);
    if (sigaltstack(&alternate, NULL) != 0) return -1;
    const int signals[] = {SIGILL, SIGSEGV, SIGBUS, SIGFPE, SIGXCPU, SIGALRM,
                           SIGINT, SIGTERM, SIGHUP, SIGPIPE};
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i)
        if (sigaction(signals[i], &action, NULL) != 0) return -1;
    return 0;
}
static void append(output *out, const char *format, ...)
{
    if (out->failed) return;
    va_list args;
    va_start(args, format);
    int n = vsnprintf(out->data + out->used, P0_JSON - out->used, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= P0_JSON - out->used) { out->failed = 1; return; }
    out->used += (size_t)n;
}
static void string(output *out, const char *text)
{
    append(out, "\"");
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\') append(out, "\\%c", *p);
        else if (*p < 32) append(out, "\\u%04x", *p);
        else append(out, "%c", *p);
    }
    append(out, "\"");
}
static void mask_json(output *out, const cpu_set_t *mask)
{
    append(out, "["); int first = 1;
    for (unsigned cpu = 0; cpu < CPU_SETSIZE; ++cpu) if (CPU_ISSET(cpu, mask)) {
        append(out, "%s%u", first ? "" : ",", cpu); first = 0;
    }
    append(out, "]");
}
static int singleton(const cpu_set_t *mask, unsigned cpu)
{
    return CPU_COUNT(mask) == 1 && CPU_ISSET(cpu, mask);
}
static void plan_json(output *out, const p0_plan *p)
{
    append(out, "{\"schema_version\":1,\"protocol\":\"" P0_PROTOCOL "\","
                "\"schedule_version\":\"" P0_SCHEDULE "\",\"cpu\":%u,\"seed\":%u,\"blocks\":%u,"
                "\"phase\":\"%s\",\"evidence_kind\":\"%s\"", p->cpu, p->seed, p->blocks,
           p->phase ? "held_out" : "calibration", p->synthetic ? "synthetic" : "physical");
    for (unsigned i = 0; i < 11; ++i) {
        append(out, ",\"%s\":", field_names[i]);
        if (i == FROZEN && !p->phase) append(out, "null");
        else string(out, p->field[i]);
    }
    append(out, "}");
}
static void canaries(output *out, uint64_t left, uint64_t right)
{
    append(out, "[\"%" PRIu64 "\",\"%" PRIu64 "\"]", left, right);
}
static int flush_output(output *out)
{
    emitting = 1;
    int code = write_all(STDOUT_FILENO, out->data + sent, out->used - (size_t)sent);
    if (code == 0) sent = (sig_atomic_t)out->used;
    emitting = 0;
    return code;
}
static int commit(output *out, p0_prefix *prefix, unsigned count)
{
    if (out->failed || out->used - out->line_start > 8192) return -1;
    prefix->json = out->data; prefix->length = out->used; prefix->completed = count;
    atomic_store_explicit(&published, prefix, memory_order_release);
    out->line_start = out->used;
    return 0;
}
static void metadata(output *out, const p0_plan *plan, const p0_identity *id,
                     const cpu_set_t *allowed, const cpu_set_t *mask, int cpu,
                     void *target, void *results, size_t bytes, size_t owned)
{
    append(out, "{\"kind\":\"metadata\",\"plan\":"); plan_json(out, plan);
    append(out, ",\"architecture\":\"aarch64\",\"system\":\"Linux\",\"byte_order\":\"little\","
                "\"page_size\":16384,\"kernel_release\":"); string(out, id->kernel);
    append(out, ",\"os_id\":\"fedora-asahi-remix\",\"os_version\":\"45\",\"os_id_like\":[");
    for (unsigned i = 0; i < id->nlike; ++i) { if (i) append(out, ","); string(out, id->like[i]); }
    append(out, "],\"compatible\":[");
    for (unsigned i = 0; i < id->ncompatible; ++i) {
        if (i) append(out, ",");
        string(out, id->compatible[i]);
    }
    append(out, "],\"midr\":\"0x%016" PRIx64 "\",\"allowed_cpus\":", id->midr);
    mask_json(out, allowed); append(out, ",\"affinity_start\":"); mask_json(out, mask);
    append(out, ",\"cpu_start\":%d,\"worker_pid\":%ld,\"target_page\":\"0x%016" PRIxPTR "\","
                "\"target_address\":\"0x%016" PRIxPTR "\",\"results_base\":\"0x%016" PRIxPTR "\","
                "\"results_bytes\":%zu,\"owned_bytes\":%zu}\n", cpu, (long)getpid(),
           (uintptr_t)target, (uintptr_t)target + P0_PAGE / 2, (uintptr_t)results, bytes, owned);
}
static void sample_json(output *out, const p0_record *r, unsigned index)
{
    append(out, "{\"kind\":\"sample\",\"index\":%u,\"block\":%u,\"condition\":\"%s\","
                "\"operation\":\"%s\",\"stxr_status\":%u,\"store_succeeded\":%s,"
                "\"memory_before\":\"%" PRIu64 "\",\"loaded_value\":\"%" PRIu64 "\","
                "\"attempted_value\":\"%" PRIu64 "\",\"memory_after\":\"%" PRIu64 "\","
                "\"cpu_before\":%d,\"cpu_after\":%d,\"canaries_before\":",
           index, index / 6, labels[r->condition],
           r->condition / 2 == 0 ? "adjacent" : r->condition / 2 == 1 ? "clear" : "sham",
           r->capture.status, r->capture.status == 0 ? "true" : "false", r->before,
           r->capture.loaded, P0_ATTEMPTED, r->capture.after, r->cpu_before, r->cpu_after);
    canaries(out, r->left_before, r->right_before); append(out, ",\"canaries_after\":");
    canaries(out, r->left_after, r->right_after); append(out, "}\n");
}
static int valid(const p0_record *r, unsigned cpu)
{
    return r->capture.status <= 1 && r->before == P0_INITIAL && r->capture.loaded == P0_INITIAL &&
        r->capture.after == (r->capture.status ? P0_INITIAL : P0_ATTEMPTED) &&
        (r->condition / 2 != 1 || r->capture.status == 1) && r->cpu_after == (int)cpu &&
        r->left_before == P0_LEFT && r->right_before == P0_RIGHT &&
        r->left_after == P0_LEFT && r->right_after == P0_RIGHT;
}
static int measure(const p0_plan *plan, output *out, void *results, volatile uint64_t *target)
{
    volatile unsigned char stack[P0_STACK];
    for (size_t i = 0; i < sizeof(stack); ++i) stack[i] = (unsigned char)i;
    if (stack[0] != 0) return -1;
    uint32_t state = plan->seed;
    void (*const operations[3])(volatile uint64_t *, uint64_t, p0_capture *) = {
        p0_adjacent, p0_clear, p0_sham
    };
    for (unsigned block = 0; block < plan->blocks; ++block) {
        unsigned order[6]; p0_order(order, &state);
        for (unsigned slot = 0; slot < 6; ++slot) {
            unsigned index = block * 6 + slot;
            p0_record *r = (void *)((char *)results + 128 + index * 128);
            r->condition = order[slot];
            p0_clear_old();
            *target = P0_INITIAL;
            r->before = *target; r->left_before = target[-1]; r->right_before = target[1];
            r->cpu_before = p0_cpu();
            if (r->cpu_before != (int)plan->cpu || r->left_before != P0_LEFT ||
                r->right_before != P0_RIGHT) return -1; // No unexecuted sample serialized.
            operations[r->condition / 2](target, P0_ATTEMPTED, &r->capture);
            r->left_after = target[-1]; r->right_after = target[1]; r->cpu_after = p0_cpu();
            sample_json(out, r, index);
            if (commit(out, &r->prefix, index + 1) != 0 || flush_output(out) != 0 ||
                !valid(r, plan->cpu)) return -1;
        }
    }
    return 0;
}
int main(int argc, char **argv)
{
    (void)argv;
    struct rlimit no_core = {0, 0}, cpu;
    int failure = 1;
    const char *stage = "setup";
    /* No fork: the independently supervised PID is the measurement PID. All
       mappings have process lifetime and are reclaimed on exit, including traps. */
    long minimum_stack = sysconf(_SC_MINSIGSTKSZ);
    if (minimum_stack <= 0 || minimum_stack > P0_ALTSTACK) {
        emit_error("signal_stack", EINVAL, 0); return 1;
    }
    void *alternate = p0_map(P0_ALTSTACK, PROT_READ | PROT_WRITE);
    if (alternate == MAP_FAILED) { emit_error("allocation", (unsigned)errno, 0); return 1; }
    memset(alternate, 0, P0_ALTSTACK);
    if (handlers(alternate) != 0 || setrlimit(RLIMIT_CORE, &no_core) != 0 ||
        getrlimit(RLIMIT_CPU, &cpu) != 0) goto failed;
    if (cpu.rlim_cur > 2) cpu.rlim_cur = 2;
    if (cpu.rlim_max > 2) cpu.rlim_max = 2;
    if (setrlimit(RLIMIT_CPU, &cpu) != 0) goto failed;
    alarm(10);
    p0_plan plan;
    stage = "input";
    if (argc != 1 || p0_read_plan(STDIN_FILENO, &plan) != 0) { errno = EINVAL; goto failed; }
    p0_identity identity;
    cpu_set_t allowed, mask;
    stage = "platform";
    if (p0_platform(&plan, &allowed, &identity) != 0) goto failed;
    stage = "affinity";
    if (p0_pin(plan.cpu) != 0 || p0_mask(&mask) != 0 || !singleton(&mask, plan.cpu) ||
        p0_cpu() != (int)plan.cpu) goto failed;
    size_t bytes = p0_results_bytes(plan.blocks);
    size_t owned = 3 * P0_PAGE + bytes + P0_JSON + P0_STACK + P0_ALTSTACK;
    stage = "allocation";
    if (owned > 1024 * 1024) { errno = EOVERFLOW; goto failed; }
    void *guarded = p0_map(3 * P0_PAGE, PROT_NONE);
    if (guarded == MAP_FAILED) goto failed;
    void *target_page = (char *)guarded + P0_PAGE;
    if ((uintptr_t)target_page % P0_PAGE ||
        p0_protect(target_page, P0_PAGE, PROT_READ | PROT_WRITE) != 0) goto failed;
    void *results = p0_map(bytes, PROT_READ | PROT_WRITE);
    char *json = p0_map(P0_JSON, PROT_READ | PROT_WRITE);
    if (results == MAP_FAILED || json == MAP_FAILED || (uintptr_t)results % P0_PAGE) goto failed;
    /* Volatile prefault writes are retained even at -O2. */
    for (size_t i = 0; i < bytes; ++i) ((volatile unsigned char *)results)[i] = 0;
    for (size_t i = 0; i < P0_JSON; ++i) ((volatile unsigned char *)json)[i] = 0;
    for (size_t i = 0; i < P0_PAGE; ++i) ((volatile unsigned char *)target_page)[i] = 0;
    for (unsigned i = 0; i < plan.blocks * 6; ++i) {
        p0_record *r = (void *)((char *)results + 128 + i * 128);
        r->capture.status = UINT32_MAX;
    }
    volatile uint64_t *target = (void *)((char *)target_page + P0_PAGE / 2);
    target[-1] = P0_LEFT; target[1] = P0_RIGHT;
    output out = {.data = json};
    metadata(&out, &plan, &identity, &allowed, &mask, p0_cpu(), target_page, results, bytes, owned);
    if (commit(&out, results, 0) != 0 || flush_output(&out) != 0) goto failed;
    stage = "capture";
    if (measure(&plan, &out, results, target) != 0) { errno = EIO; goto failed; }
    int end = p0_cpu();
    stage = "affinity";
    if (p0_mask(&mask) != 0 || !singleton(&mask, plan.cpu) || end != (int)plan.cpu) goto failed;
    append(&out, "{\"kind\":\"complete\",\"status\":\"ok\",\"samples_emitted\":%u,"
                 "\"cpu_end\":%d,\"affinity_end\":", plan.blocks * 6, end);
    mask_json(&out, &mask);
    append(&out, ",\"worker_pid\":%ld,\"canaries\":", (long)getpid());
    canaries(&out, target[-1], target[1]); append(&out, "}\n");
    stage = "output";
    if (out.failed || out.used - out.line_start > 8192) goto failed;
    if (flush_output(&out) != 0) goto failed;
    failure = 0;
failed:
    if (failure) emit_error(stage, (unsigned)(errno > 0 ? errno : EIO), 0);
    alarm(0);
    return failure;
}
