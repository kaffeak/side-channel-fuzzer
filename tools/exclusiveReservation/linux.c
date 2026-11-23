// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#if !defined(__linux__) || !defined(__aarch64__)
#error "Native backend must be built for AArch64 Linux"
#endif
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Little-endian target required"
#endif
#include "worker.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>
const int p0_synthetic_backend = 0;
static int read_file(const char *path, char *out, size_t capacity)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t count = 0;
    int failed = 0;
    while (count < capacity) {
        ssize_t n = read(fd, out + count, capacity - count);
        if (n < 0) { failed = 1; break; }
        if (n == 0) break;
        count += (size_t)n;
    }
    int saved = errno;
    if (close(fd) != 0 && !failed) return -1;
    errno = saved;
    if (failed) return -1;
    if (count == 0 || count >= capacity) { errno = EIO; return -1; }
    out[count] = 0;
    return (int)count;
}
static int value(char *text, const char *key, char *out, size_t capacity)
{
    int found = 0;
    size_t length = strlen(key);
    for (char *line = text; line && *line;) {
        char *next = strchr(line, '\n');
        if (next) *next++ = 0;
        if (strncmp(line, key, length) == 0 && line[length] == '=') {
            if (found++) return -1;
            char *start = line + length + 1;
            size_t n = strlen(start);
            if (n >= 2 && (start[0] == '"' || start[0] == '\'')) {
                if (start[n - 1] != start[0]) return -1;
                start[n - 1] = 0; ++start; n -= 2;
            }
            if (n == 0 || n >= capacity || strpbrk(start, "\\\r\"'")) return -1;
            memcpy(out, start, n + 1);
        }
        line = next;
    }
    return found == 1 ? 0 : -1;
}
int p0_mask(cpu_set_t *mask) { return sched_getaffinity(0, sizeof(*mask), mask); }
int p0_cpu(void) { return sched_getcpu(); }
int p0_pin(unsigned cpu)
{
    cpu_set_t mask;
    if (p0_mask(&mask) != 0 || cpu >= CPU_SETSIZE || !CPU_ISSET(cpu, &mask)) return -1;
    CPU_ZERO(&mask); CPU_SET(cpu, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) != 0 || p0_mask(&mask) != 0 ||
        CPU_COUNT(&mask) != 1 || !CPU_ISSET(cpu, &mask)) { errno = EINVAL; return -1; }
    return 0;
}
int p0_platform(const p0_plan *plan, cpu_set_t *allowed, p0_identity *identity)
{
    struct utsname uts;
    char source[4097], copy[4097], id[128], version[128], like[128], path[160];
    if (geteuid() == 0 || sysconf(_SC_PAGESIZE) != P0_PAGE || uname(&uts) != 0 ||
        strcmp(uts.sysname, "Linux") || strcmp(uts.machine, "aarch64") ||
        strcmp(uts.release, plan->field[KERNEL]) ||
        p0_mask(allowed) != 0 || !CPU_ISSET(plan->cpu, allowed)) { errno = EINVAL; return -1; }
    memset(identity, 0, sizeof(*identity));
    memcpy(identity->kernel, uts.release, strlen(uts.release) + 1);
    int n = read_file("/proc/device-tree/compatible", source, sizeof(source));
    if (n < 0 || source[n - 1] != 0) return -1;
    int t8103 = 0;
    for (int i = 0; i < n; i += (int)strlen(source + i) + 1) {
        size_t size = strlen(source + i);
        if (size == 0 || size > 128 || identity->ncompatible == 16) return -1;
        for (unsigned j = 0; j < identity->ncompatible; ++j)
            if (!strcmp(identity->compatible[j], source + i)) return -1;
        memcpy(identity->compatible[identity->ncompatible++], source + i, size + 1);
        if (strcmp(source + i, "apple,t8103") == 0) t8103 = 1;
    }
    if (!t8103 || read_file("/etc/os-release", source, sizeof(source)) < 0) return -1;
    strcpy(copy, source);
    if (value(copy, "ID", id, sizeof(id)) != 0) return -1;
    strcpy(copy, source);
    if (value(copy, "VERSION_ID", version, sizeof(version)) != 0) return -1;
    strcpy(copy, source);
    if (value(copy, "ID_LIKE", like, sizeof(like)) != 0 || strcmp(id, "fedora-asahi-remix") ||
        strcmp(version, "45")) return -1;
    int fedora = 0;
    for (char *token = strtok(like, " \t"); token; token = strtok(NULL, " \t")) {
        if (identity->nlike == 16) return -1;
        for (unsigned j = 0; j < identity->nlike; ++j)
            if (!strcmp(identity->like[j], token)) return -1;
        strcpy(identity->like[identity->nlike++], token);
        if (strcmp(token, "fedora") == 0) fedora = 1;
    }
    if (!fedora) { errno = EINVAL; return -1; }
    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%u/regs/identification/midr_el1",
             plan->cpu);
    if (read_file(path, source, sizeof(source)) < 0) return -1;
    if (strncmp(source, "0x", 2) != 0) { errno = EINVAL; return -1; }
    size_t digits = 0;
    while ((source[2 + digits] >= '0' && source[2 + digits] <= '9') ||
           (source[2 + digits] >= 'a' && source[2 + digits] <= 'f') ||
           (source[2 + digits] >= 'A' && source[2 + digits] <= 'F')) ++digits;
    if (digits == 0 || digits > 16) { errno = EINVAL; return -1; }
    errno = 0;
    char *end;
    unsigned long long midr = strtoull(source, &end, 16);
    while (*end == '\n' || *end == ' ' || *end == '\t') ++end;
    if (errno || *end || midr != (plan->cpu == 0 ? 0x611f0221ULL : 0x611f0231ULL)) {
        errno = EINVAL; return -1;
    }
    identity->midr = midr;
    return 0;
}
void *p0_map(size_t bytes, int protection)
{
    return mmap(NULL, bytes, protection, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}
int p0_protect(void *address, size_t bytes, int protection)
{
    return mprotect(address, bytes, protection);
}
