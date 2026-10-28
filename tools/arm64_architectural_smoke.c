// SPDX-License-Identifier: MIT
// Reviewed fixed body or MOVZ-immediate family. No general code loader or HTrace output.
#define _GNU_SOURCE
#if !defined(__linux__) || (!defined(__aarch64__) && !defined(RVZR_ARCH_HOST_TEST))
#error "Native AArch64 Linux required; RVZR_ARCH_HOST_TEST is for the mock unit harness only."
#endif
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "This fixed fixture requires little-endian payloads."
#endif

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { MAIN_BYTES = 4096, FIXTURE_BYTES = 36, DEADLINE_MS = 2000,
       FRAGMENT_BYTES = 12288, SELECTOR_OFFSET = 8192 };
#define INPUT_FORMAT "rvzr-inputdata-raw-v1"
#define PROGRAM_FORMAT "rvzr-b34a-body-v1"
#define FAMILY_FORMAT "rvzr-b34a-movz16-v1"
typedef enum { EXACT_PROGRAM, MOVZ16_FAMILY } program_policy_t;
typedef struct { unsigned char bytes[FRAGMENT_BYTES]; } input_t;
_Static_assert(MAIN_BYTES <= SELECTOR_OFFSET && SELECTOR_OFFSET + 8 <= FRAGMENT_BYTES,
               "serialized field bounds");
enum { SETUP = 1, DATA_MAPPING, CODE_MAPPING, PUBLICATION, INVOCATION, CLEANUP, COMPLETE };
static const char *const stages[] = {
    "parent", "setup", "data_mapping", "code_mapping", "publication",
    "invocation", "cleanup", "complete"
};
typedef struct {
    uint64_t regs[8], nzcv, sp_mod16;
} arch_state_t;
_Static_assert(sizeof(void *) == 8 && sizeof(size_t) == 8, "LP64 required");
_Static_assert(offsetof(arch_state_t, nzcv) == 64, "assembly NZCV offset");
_Static_assert(offsetof(arch_state_t, sp_mod16) == 72, "assembly SP offset");
_Static_assert(sizeof(arch_state_t) == 80, "assembly result extent");
typedef struct {
    arch_state_t state;
    uintptr_t data_base, code_base;
    int stage, error;
    unsigned char main[MAIN_BYTES];
} result_t;
typedef struct {
    void *reservation;
    unsigned char *payload;
    size_t span;
} region_t;

extern const unsigned char rvzr_fixture[];
extern const size_t rvzr_fixture_size;
extern void rvzr_arch_invoke(void *code, void *main, uint64_t selector, arch_state_t *state);

static uint64_t read_le64(const unsigned char *bytes)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)bytes[i] << (8 * i);
    return value;
}

// Concrete encoding gate, NOT instruction decoding or a mnemonic allowlist.
// Recheck at execution entry as well as at transport admission. No fallback.
static int validate_program(const unsigned char *program, size_t size, program_policy_t policy)
{
    if (size != FIXTURE_BYTES || size % 4 != 0 || rvzr_fixture_size != FIXTURE_BYTES ||
        (policy != EXACT_PROGRAM && policy != MOVZ16_FAMILY)) goto rejected;
    for (size_t offset = 0; offset < FIXTURE_BYTES; offset += 4) {
        uint32_t word = 0, reference = 0;
        for (unsigned j = 0; j < 4; ++j) {
            word |= (uint32_t)program[offset + j] << (8 * j);
            reference |= (uint32_t)rvzr_fixture[offset + j] << (8 * j);
        }
        // Only imm16 bits [20:5] at the two MOVZ X1, #imm16, LSL #0 sites.
        uint32_t variable = policy == MOVZ16_FAMILY && (offset == 8 || offset == 16)
            ? UINT32_C(0x001fffe0) : 0;
        if ((word & ~variable) != (reference & ~variable)) goto rejected;
    }
    return 0;
rejected:
    errno = ENOTSUP;
    return -1;
}

// Three pages: inaccessible guard / one payload page / inaccessible guard.
// No borrowed aliases, MAP_FIXED, shared code, or page-table manipulation.
static int region_span(size_t page, size_t bytes, size_t *span)
{
    if ((page != 4096 && page != 16384) || bytes == 0 || bytes > page ||
        page > SIZE_MAX / 3) {
        errno = EINVAL;
        return -1;
    }
    *span = page * 3;
    return 0;
}

static int region_close(region_t *region)
{
    if (region->reservation == NULL)
        return 0;
    if (munmap(region->reservation, region->span) != 0)
        return -1; // Retain ownership metadata on failure; child exit is the backstop.
    *region = (region_t){0};
    return 0;
}

static int region_open(region_t *region, size_t page, size_t bytes)
{
    size_t span;
    if (region->reservation != NULL) {
        errno = EINVAL;
        return -1;
    }
    if (region_span(page, bytes, &span) != 0)
        return -1;
    void *reservation = mmap(NULL, span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reservation == MAP_FAILED)
        return -1;
    *region = (region_t){reservation, (unsigned char *)reservation + page, span};
    if (mprotect(region->payload, page, PROT_READ | PROT_WRITE) != 0)
        return -1; // Caller owns and closes even a partially initialized region.
    return 0;
}

static int execute_fixed(result_t *result, size_t page, const input_t *input,
                         const unsigned char *program, program_policy_t policy)
{
    if (validate_program(program, FIXTURE_BYTES, policy) != 0) {
        result->error = errno;
        result->stage = CODE_MAPPING;
        return 1; // No allocations, protection changes, or invocation.
    }
    region_t data = {0}, code = {0};
    int error = 0;
    result->stage = DATA_MAPPING;
    if (region_open(&data, page, MAIN_BYTES) != 0)
        goto failed;
    memcpy(data.payload, input->bytes, MAIN_BYTES);
    result->stage = CODE_MAPPING;
    if (rvzr_fixture_size != FIXTURE_BYTES) {
        errno = EINVAL;
        goto failed;
    }
    if (region_open(&code, page, rvzr_fixture_size) != 0)
        goto failed;
    memcpy(code.payload, program, FIXTURE_BYTES);
    result->stage = PUBLICATION;
    // GCC's target-supported cache synchronization, including required barriers.
    // This is not cache eviction for measurement; it publishes newly written code.
    __builtin___clear_cache((char *)code.payload, (char *)code.payload + rvzr_fixture_size);
    if (mprotect(code.payload, page, PROT_READ | PROT_EXEC) != 0)
        goto failed;
    result->data_base = (uintptr_t)data.payload;
    result->code_base = (uintptr_t)code.payload;
    result->stage = INVOCATION;
    rvzr_arch_invoke(code.payload, data.payload, read_le64(input->bytes + SELECTOR_OFFSET),
                     &result->state);
    memcpy(result->main, data.payload, MAIN_BYTES);
    // The sole allowed write is [main, main+8); also inspect 16K-page padding.
    for (size_t i = 8; i < page; ++i) {
        unsigned char expected = i < MAIN_BYTES ? input->bytes[i] : 0;
        if (data.payload[i] != expected) {
            errno = EPROTO;
            goto failed;
        }
    }
    result->stage = CLEANUP;
    goto cleanup;
failed:
    error = errno;
cleanup:
    // Both regions are attempted even if one release fails.
    if (region_close(&code) != 0 && error == 0)
        error = errno;
    if (region_close(&data) != 0 && error == 0)
        error = errno;
    result->error = error;
    if (error == 0)
        result->stage = COMPLETE;
    return error == 0 ? 0 : 1;
}

static int64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

// Fixed-size packets only. The caller supplies expected+1 bytes of owned space.
// Read at most one excess byte, require EOF, and bound a stalled pipe.
static int read_packet(int fd, unsigned char *wire, size_t expected)
{
    if (expected != FRAGMENT_BYTES && expected != FRAGMENT_BYTES + FIXTURE_BYTES) {
        errno = EINVAL;
        return -1;
    }
    size_t used = 0;
    int64_t start = monotonic_ms();
    for (;;) {
        int64_t now = monotonic_ms();
        if (start < 0 || now < start) { errno = EIO; return -1; }
        int64_t elapsed = now - start;
        if (elapsed >= DEADLINE_MS) { errno = ETIMEDOUT; return -1; }
        struct pollfd pending = {fd, POLLIN, 0};
        int ready = poll(&pending, 1, DEADLINE_MS - (int)elapsed);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return -1;
        if (ready == 0) { errno = ETIMEDOUT; return -1; }
        if (pending.revents & POLLNVAL) { errno = EBADF; return -1; }
        ssize_t count = read(fd, wire + used, expected + 1 - used);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count < 0) return -1;
        if (count == 0) break;
        used += (size_t)count; // read() returns at most the requested remaining capacity.
        if (used == expected + 1) { errno = E2BIG; return -1; }
    }
    if (used != expected) { errno = EINVAL; return -1; }
    return 0;
}

static int decode_input(const unsigned char *wire, input_t *input)
{
    for (size_t i = MAIN_BYTES; i < FRAGMENT_BYTES; ++i) {
        if (i >= SELECTOR_OFFSET && i < SELECTOR_OFFSET + 8) continue;
        if (wire[i] != 0) { errno = ENOTSUP; return -1; }
    }
    memcpy(input->bytes, wire, FRAGMENT_BYTES); // Publish only a completely validated snapshot.
    return 0;
}

static int read_input(int fd, input_t *input)
{
    unsigned char wire[FRAGMENT_BYTES + 1];
    if (read_packet(fd, wire, FRAGMENT_BYTES) != 0) return -1;
    return decode_input(wire, input);
}

// No length/count/address fields: exactly 36 approved code bytes, then the
// unchanged 12288-byte raw input. Neither output is published on rejection.
static int read_program_input(int fd, unsigned char *program, input_t *input,
                              program_policy_t policy)
{
    unsigned char wire[FIXTURE_BYTES + FRAGMENT_BYTES + 1];
    input_t validated;
    if (read_packet(fd, wire, FIXTURE_BYTES + FRAGMENT_BYTES) != 0 ||
        validate_program(wire, FIXTURE_BYTES, policy) != 0 ||
        decode_input(wire + FIXTURE_BYTES, &validated) != 0) return -1;
    memcpy(program, wire, FIXTURE_BYTES);
    *input = validated;
    return 0;
}

// Only the owned child PID is killed/reaped. No recovery, retries or signal continuation.
static int wait_bounded(pid_t child, int *status, int *timed_out)
{
    int64_t start = monotonic_ms();
    int saved = 0;
    *timed_out = 0;
    for (;;) {
        pid_t waited = waitpid(child, status, WNOHANG);
        if (waited == child)
            return 0;
        if (waited < 0 && errno != EINTR) {
            if (errno == ECHILD)
                return -1; // No owned child remains; never signal a potentially reused PID.
            saved = errno;
            break;
        }
        int64_t now = monotonic_ms();
        if (start < 0 || now < 0) {
            saved = EIO;
            break;
        }
        if (now - start >= DEADLINE_MS) {
            *timed_out = 1;
            break;
        }
        struct timespec pause = {0, 10000000};
        (void)nanosleep(&pause, NULL);
    }
    if (kill(child, SIGKILL) != 0 && errno != ESRCH && saved == 0)
        saved = errno;
    while (waitpid(child, status, 0) < 0) {
        if (errno != EINTR) {
            if (saved == 0) saved = errno;
            break;
        }
    }
    errno = saved;
    return saved == 0 ? 0 : -1;
}

static void json_string(const char *value)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 0x20) printf("\\u%04x", (unsigned)*p);
        else putchar(*p);
    }
    putchar('"');
}

static int failure(const char *stage, int error, int signal_number, int timed_out, int exit_code)
{
    printf("{\"kind\":\"error\",\"status\":\"error\",\"stage\":");
    json_string(stage);
    printf(",\"errno\":%d,\"signal\":%d,\"timeout\":%s,\"child_exit\":%d}\n",
           error, signal_number, timed_out ? "true" : "false", exit_code);
    (void)fflush(stdout);
    return 1;
}

static int runner_main(int argc, char **argv)
{
    if ((argc != 3 && argc != 5) || strcmp(argv[1], "--input-format") != 0)
        return failure("arguments: --input-format rvzr-inputdata-raw-v1 required", EINVAL, 0, 0, 0);
    if (strcmp(argv[2], INPUT_FORMAT) != 0)
        return failure("unsupported_input_format", ENOTSUP, 0, 0, 0);
    int generated = argc == 5;
    program_policy_t policy = EXACT_PROGRAM;
    if (generated && (strcmp(argv[3], "--program-format") != 0 ||
                      (strcmp(argv[4], PROGRAM_FORMAT) != 0 &&
                       strcmp(argv[4], FAMILY_FORMAT) != 0)))
        return failure("unsupported_program_format", ENOTSUP, 0, 0, 0);
    if (generated && strcmp(argv[4], FAMILY_FORMAT) == 0) policy = MOVZ16_FAMILY;
    input_t input;
    unsigned char received[FIXTURE_BYTES];
    const unsigned char *program = rvzr_fixture;
    if (generated) {
        if (read_program_input(STDIN_FILENO, received, &input, policy) != 0)
            return failure("program_request", errno, 0, 0, 0);
        program = received;
    } else if (read_input(STDIN_FILENO, &input) != 0)
        return failure("input", errno, 0, 0, 0);
    long page_value = sysconf(_SC_PAGESIZE);
    size_t span;
    if (page_value <= 0 || region_span((size_t)page_value, MAIN_BYTES, &span) != 0)
        return failure("unsupported_page_size", EINVAL, 0, 0, 0);
    size_t page = (size_t)page_value;
    struct utsname system;
    if (uname(&system) != 0)
        return failure("uname", errno, 0, 0, 0);
    result_t *result = mmap(NULL, sizeof(*result), PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (result == MAP_FAILED)
        return failure("result_mapping", errno, 0, 0, 0);
    printf("{\"kind\":\"metadata\",\"fixture\":\"b34a-fixed-body-v1\","
           "\"input_format\":\"" INPUT_FORMAT "\","
           "\"program_source\":\"%s\",\"program_format\":\"%s\",\"architecture\":\"aarch64\","
           "\"page_size\":%zu,\"kernel\":", generated ? "approved-generated" : "embedded-reference",
           policy == MOVZ16_FAMILY ? FAMILY_FORMAT : PROGRAM_FORMAT,
           page);
    json_string(system.release);
    puts("}");
    int outcome = 0;
    // One snapshot per process; every break reaches shared-result cleanup below.
    do {
        uint64_t selector = read_le64(input.bytes + SELECTOR_OFFSET);
        uint64_t word = read_le64(input.bytes);
        memset(result, 0, sizeof(*result));
        result->stage = SETUP;
        if (fflush(stdout) != 0) {
            outcome = 1;
            break;
        }
        pid_t child = fork();
        if (child < 0) {
            outcome = failure("fork", errno, 0, 0, 0);
            break;
        }
        if (child == 0) {
            struct rlimit no_core = {0, 0};
            int persona = personality(0xffffffffUL); // Read only: never change protections.
            if (persona < 0) {
                result->error = errno;
                _exit(1);
            }
            if ((persona & READ_IMPLIES_EXEC) != 0) {
                result->error = EPERM;
                _exit(1);
            }
            if (setrlimit(RLIMIT_CORE, &no_core) != 0) {
                result->error = errno;
                _exit(1);
            }
            _exit(execute_fixed(result, page, &input, program, policy));
        }
        int status = 0, timed_out = 0;
        int wait_error = wait_bounded(child, &status, &timed_out);
        if (wait_error != 0 || timed_out || !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
            result->stage != COMPLETE || result->error != 0) {
            const char *stage = result->stage >= SETUP && result->stage <= COMPLETE
                ? stages[result->stage] : "invalid_child_state";
            outcome = failure(stage, wait_error != 0 ? errno : result->error,
                              WIFSIGNALED(status) ? WTERMSIG(status) : 0, timed_out,
                              WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            break;
        }
        printf("{\"kind\":\"architectural_state\",\"status\":\"ok\",\"input\":0,"
               "\"selector\":%" PRIu64 ",\"initial_word\":%" PRIu64 ","
               "\"data_base\":\"0x%" PRIxPTR "\",\"code_base\":\"0x%" PRIxPTR "\","
               "\"x0_x7\":[", selector, word, result->data_base, result->code_base);
        for (unsigned j = 0; j < 8; ++j)
            printf("%s%" PRIu64, j == 0 ? "" : ",", result->state.regs[j]);
        printf("],\"nzcv\":%" PRIu64 ",\"sp_mod16\":%" PRIu64 ",\"main_hex\":\"",
               result->state.nzcv, result->state.sp_mod16);
        for (unsigned j = 0; j < MAIN_BYTES; ++j) printf("%02x", result->main[j]);
        puts("\"}");
    } while (0);
    if (munmap(result, sizeof(*result)) != 0)
        return failure("result_cleanup", errno, 0, 0, 0);
    if (outcome == 0) puts("{\"kind\":\"complete\",\"status\":\"ok\",\"cases\":1}");
    return fflush(stdout) == 0 && !ferror(stdout) ? outcome : 1;
}

#ifndef RVZR_ARCH_HOST_TEST
int main(int argc, char **argv)
{
    return runner_main(argc, argv);
}
#endif
