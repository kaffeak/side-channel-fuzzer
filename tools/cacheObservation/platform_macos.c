// SPDX-License-Identifier: MIT
#include <errno.h>
#include "platform.h"
int g3_pin(int cpu)
{
    if (cpu != -1) { errno = ENOTSUP; return -1; }
    return 0; // No QoS/affinity claim; physical core and migration remain unknown.
}
int g3_cpu(void) { return -1; }
const char *g3_platform(void) { return "macos"; }
