// SPDX-License-Identifier: MIT
#ifndef G3_PLATFORM_H
#define G3_PLATFORM_H
int g3_pin(int cpu);       // -1 means leave affinity unchanged.
int g3_cpu(void);          // -1 means identity unavailable, not CPU zero.
const char *g3_platform(void);
#endif
