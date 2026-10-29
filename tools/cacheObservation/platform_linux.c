// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include "platform.h"
int g3_pin(int cpu)
{
    if (cpu == -1) return 0;
    cpu_set_t mask;
    if (cpu < 0 || cpu >= CPU_SETSIZE) { errno = EINVAL; return -1; }
    if (sched_getaffinity(0, sizeof(mask), &mask) != 0) return -1;
    if (!CPU_ISSET(cpu, &mask)) { errno = EINVAL; return -1; }
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) != 0 ||
        sched_getaffinity(0, sizeof(mask), &mask) != 0) return -1;
    if (CPU_COUNT(&mask) != 1 || !CPU_ISSET(cpu, &mask)) { errno = EINVAL; return -1; }
    return 0;
}
int g3_cpu(void) { return sched_getcpu(); }
const char *g3_platform(void) { return "linux"; }
