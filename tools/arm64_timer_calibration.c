// SPDX-License-Identifier: MIT
// Standalone timer calibration, not a cache-state classifier or Revizor backend.
#define _GNU_SOURCE
#if !defined(__linux__) || !defined(__aarch64__)
#error "Build this utility for AArch64 Linux; there is no simulated timer fallback."
#endif

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

enum { MAX_SAMPLES = 100000, MAX_LOADS = 256, BUFFER_WORDS = 64, SERIES_COUNT = 3 };
enum { STAGE_FREQUENCY, STAGE_COUNTER, STAGE_ADJACENT, STAGE_EMPTY, STAGE_BUFFER };
enum { WORKER_SETUP = 10, BACKWARDS, NO_ADVANCE, WRONG_CPU };
static const char *const stages[] = {
    "frequency_probe", "counter_probe", "adjacent_reads", "empty_window", "owned_buffer"
};
static const char *const series_names[] = {"adjacent_reads", "empty_window", "owned_buffer"};

typedef struct { uint64_t start, end; } sample_t;
typedef struct {
    uint64_t frequency, checksum;
    int stage, cpu_start, cpu_end;
    sample_t samples[];
} results_t;

static inline uint64_t read_counter(void)
{
    uint64_t value;
    // ISBs bracket the read; "memory" prevents compiler motion across it.
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0\n\tisb" : "=r"(value) : : "memory");
    return value;
}

static inline uint64_t window_counter(void)
{
    // Conservative completion of earlier normal-memory accesses before sampling.
    // These are unprivileged barriers, not cache maintenance.
    __asm__ volatile("dsb ish" : : : "memory");
    return read_counter();
}

static int calibrate(results_t *result, unsigned samples, unsigned loads, int cpu)
{
    volatile uint64_t buffer[BUFFER_WORDS];
    uint64_t checksum = 0;
    for (unsigned j = 0; j < BUFFER_WORDS; ++j)
        buffer[j] = j + 1;
    for (unsigned j = 0; j < BUFFER_WORDS; ++j)
        checksum += buffer[j]; // Prior access, NOT proof of L1 residency.

    result->cpu_start = sched_getcpu();
    if (result->cpu_start != cpu)
        return WRONG_CPU;
    result->stage = STAGE_COUNTER;
    uint64_t first = read_counter(); // A trap here is reported by the parent.
    uint64_t previous = first;

    result->stage = STAGE_ADJACENT;
    for (unsigned i = 0; i < samples; ++i) {
        uint64_t end = read_counter();
        if (end < previous)
            return BACKWARDS;
        result->samples[i] = (sample_t){previous, end};
        previous = end; // Recording and loop overhead occur between successive reads.
    }

    result->stage = STAGE_EMPTY;
    for (unsigned i = 0; i < samples; ++i) {
        uint64_t start = window_counter();
        uint64_t end = window_counter();
        if (start < previous || end < start)
            return BACKWARDS;
        result->samples[samples + i] = (sample_t){start, end};
        previous = end;
    }

    result->stage = STAGE_BUFFER;
    for (unsigned i = 0; i < samples; ++i) {
        uint64_t start = window_counter();
        for (unsigned j = 0; j < loads; ++j)
            checksum += buffer[j % BUFFER_WORDS];
        uint64_t end = window_counter();
        if (start < previous || end < start)
            return BACKWARDS;
        result->samples[2 * samples + i] = (sample_t){start, end};
        previous = end;
    }
    result->checksum = checksum;
    result->cpu_end = sched_getcpu();
    if (result->cpu_end != cpu)
        return WRONG_CPU;
    return previous == first ? NO_ADVANCE : 0;
}

// Separate children contain register traps without signal recovery or timer substitution.
// Shared, prefaulted results are read only after waitpid confirms successful completion.
static int run_worker(results_t *result, int frequency_only, unsigned samples,
                      unsigned loads, int cpu, int *signal_number)
{
    *signal_number = 0;
    result->stage = frequency_only ? STAGE_FREQUENCY : STAGE_COUNTER;
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        struct rlimit no_core = {0, 0};
        if (setrlimit(RLIMIT_CORE, &no_core) != 0)
            _exit(WORKER_SETUP);
        if (frequency_only) {
            if (sched_getcpu() != cpu)
                _exit(WRONG_CPU);
            __asm__ volatile("isb\n\tmrs %0, cntfrq_el0\n\tisb"
                             : "=r"(result->frequency) : : "memory");
            _exit(0);
        }
        _exit(calibrate(result, samples, loads, cpu));
    }
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    if (WIFSIGNALED(status)) {
        *signal_number = WTERMSIG(status);
        return 128 + *signal_number;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : WORKER_SETUP;
}

static void json_string(const char *value)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p == '"' || *p == '\\')
            printf("\\%c", *p);
        else if (*p < 0x20)
            printf("\\u%04x", (unsigned)*p);
        else
            putchar(*p);
    }
    putchar('"');
}

static int error_report(const char *stage, int error_number, int signal_number, int worker_exit)
{
    printf("{\"kind\":\"error\",\"status\":\"error\",\"stage\":");
    json_string(stage);
    printf(",\"errno\":%d,\"signal\":%d,\"worker_exit\":%d}\n",
           error_number, signal_number, worker_exit);
    fprintf(stderr, "Calibration failed at %s (errno=%d, signal=%d, worker_exit=%d).\n",
            stage, error_number, signal_number, worker_exit);
    return EXIT_FAILURE;
}

static void print_summary(const char *series, const sample_t *data, unsigned count)
{
    uint64_t minimum = UINT64_MAX, positive = UINT64_MAX, maximum = 0;
    unsigned zeros = 0;
    for (unsigned i = 0; i < count; ++i) {
        uint64_t delta = data[i].end - data[i].start;
        if (delta < minimum) minimum = delta;
        if (delta > maximum) maximum = delta;
        if (delta == 0) ++zeros;
        else if (delta < positive) positive = delta;
    }
    printf("{\"kind\":\"summary\",\"series\":\"%s\",\"samples\":%u,"
           "\"zero_deltas\":%u,\"min_delta_ticks\":\"%" PRIu64 "\","
           "\"max_delta_ticks\":\"%" PRIu64 "\",\"min_positive_observed_delta_ticks\":",
           series, count, zeros, minimum, maximum);
    if (zeros == count) printf("null");
    else printf("\"%" PRIu64 "\"", positive);
    puts("}");
}

static void usage(FILE *stream, const char *program)
{
    fprintf(stream, "Usage: %s [--cpu ID] [--samples N] [--loads N]\n"
            "AArch64 Linux timer calibration; JSON Lines on stdout.\n"
            "Defaults: first allowed CPU, 10000 samples/series, 1 load/window.\n"
            "Limits: samples 1..%d; loads 1..%d; owned buffer %zu bytes.\n",
            program, MAX_SAMPLES, MAX_LOADS, BUFFER_WORDS * sizeof(uint64_t));
}

static int parse_number(const char *text, unsigned minimum, unsigned maximum, unsigned *value)
{
    if (*text == '\0' || strspn(text, "0123456789") != strlen(text))
        return -1;
    errno = 0;
    char *end;
    unsigned long number = strtoul(text, &end, 10);
    if (errno || *end || number < minimum || number > maximum)
        return -1;
    *value = (unsigned)number;
    return 0;
}

int main(int argc, char **argv)
{
    static const struct option options[] = {
        {"cpu", required_argument, NULL, 'c'}, {"samples", required_argument, NULL, 'n'},
        {"loads", required_argument, NULL, 'l'}, {"help", no_argument, NULL, 'h'}, {0, 0, 0, 0}
    };
    unsigned samples = 10000, loads = 1, cpu_argument = 0;
    int selected_cpu = -1, option;
    while ((option = getopt_long(argc, argv, "c:n:l:h", options, NULL)) != -1) {
        if (option == 'h') { usage(stdout, argv[0]); return 0; }
        int invalid = 1;
        if (option == 'c') {
            invalid = parse_number(optarg, 0, CPU_SETSIZE - 1, &cpu_argument);
            selected_cpu = (int)cpu_argument;
        } else if (option == 'n') {
            invalid = parse_number(optarg, 1, MAX_SAMPLES, &samples);
        } else if (option == 'l') {
            invalid = parse_number(optarg, 1, MAX_LOADS, &loads);
        }
        if (invalid) { usage(stderr, argv[0]); return 2; }
    }
    if (optind != argc) { usage(stderr, argv[0]); return 2; }

    cpu_set_t allowed, pinned;
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0)
        return error_report("get_affinity", errno, 0, 0);
    if (selected_cpu < 0) {
        for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu)
            if (CPU_ISSET(cpu, &allowed)) { selected_cpu = cpu; break; }
    }
    if (selected_cpu < 0 || !CPU_ISSET(selected_cpu, &allowed))
        return error_report("cpu_not_allowed", 0, 0, 0);
    CPU_ZERO(&pinned);
    CPU_SET(selected_cpu, &pinned);
    if (sched_setaffinity(0, sizeof(pinned), &pinned) != 0)
        return error_report("set_affinity", errno, 0, 0);
    if (sched_getaffinity(0, sizeof(pinned), &pinned) != 0)
        return error_report("verify_affinity", errno, 0, 0);
    if (CPU_COUNT(&pinned) != 1 || !CPU_ISSET(selected_cpu, &pinned))
        return error_report("affinity_changed", 0, 0, 0);

    struct utsname system;
    if (uname(&system) != 0)
        return error_report("uname", errno, 0, 0);
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
        return error_report("page_size", errno, 0, 0);
    size_t bytes = sizeof(results_t) + SERIES_COUNT * (size_t)samples * sizeof(sample_t);
    results_t *result = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (result == MAP_FAILED)
        return error_report("allocate_results", errno, 0, 0);
    memset(result, 0, bytes); // Prefault the result storage before either child starts.
    int frequency_signal, counter_signal;
    int frequency_exit = run_worker(result, 1, samples, loads, selected_cpu, &frequency_signal);
    if (frequency_exit < 0) {
        int saved_errno = errno;
        munmap(result, bytes);
        return error_report("frequency_worker", saved_errno, 0, 0);
    }
    int counter_exit = run_worker(result, 0, samples, loads, selected_cpu, &counter_signal);
    if (counter_exit != 0) {
        int saved_errno = counter_exit < 0 ? errno : 0;
        int stage = result->stage;
        munmap(result, bytes);
        return error_report(counter_exit < 0 ? "counter_worker" : stages[stage],
                            saved_errno, counter_signal, counter_exit);
    }

    // Emit measurements only after the entire worker succeeds. Wide tick values
    // are decimal strings so JSON consumers need not round them to binary64.
    printf("{\"kind\":\"metadata\",\"schema_version\":1,\"counter\":\"CNTVCT_EL0\","
           "\"frequency_register\":\"CNTFRQ_EL0\",\"reported_frequency_hz\":");
    if (frequency_exit == 0 && result->frequency != 0)
        printf("%" PRIu64, result->frequency);
    else printf("null");
    printf(",\"frequency_probe_exit\":%d,\"frequency_probe_signal\":%d,"
           "\"page_size_bytes\":%ld,\"selected_cpu\":%d,\"cpu_start\":%d,\"cpu_end\":%d,"
           "\"samples_per_series\":%u,\"loads_per_window\":%u,\"buffer_bytes\":%zu,"
           "\"checksum\":\"%" PRIu64 "\",\"kernel_release\":",
           frequency_exit, frequency_signal, page_size, selected_cpu, result->cpu_start,
           result->cpu_end, samples, loads, BUFFER_WORDS * sizeof(uint64_t), result->checksum);
    json_string(system.release);
    printf(",\"machine\":"); json_string(system.machine);
    printf(",\"initial_allowed_cpus\":[");
    int separator = 0;
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (CPU_ISSET(cpu, &allowed)) {
            printf("%s%d", separator ? "," : "", cpu);
            separator = 1;
        }
    }
    puts("]}");
    for (unsigned series = 0; series < SERIES_COUNT; ++series) {
        const sample_t *data = result->samples + series * samples;
        for (unsigned i = 0; i < samples; ++i)
            printf("{\"kind\":\"sample\",\"series\":\"%s\",\"index\":%u,"
                   "\"start_ticks\":\"%" PRIu64 "\",\"end_ticks\":\"%" PRIu64 "\","
                   "\"delta_ticks\":\"%" PRIu64 "\"}\n",
                   series_names[series], i, data[i].start, data[i].end,
                   data[i].end - data[i].start);
        print_summary(series_names[series], data, samples);
    }
    printf("{\"kind\":\"complete\",\"status\":\"ok\",\"samples_emitted\":%u}\n",
           SERIES_COUNT * samples);
    munmap(result, bytes);
    if (fflush(stdout) != 0 || ferror(stdout)) {
        perror("write calibration output");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
