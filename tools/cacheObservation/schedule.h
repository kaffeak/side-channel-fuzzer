// SPDX-License-Identifier: MIT
#ifndef G3_SCHEDULE_H
#define G3_SCHEDULE_H
#include <stdint.h>
static inline uint32_t g3_random(uint32_t *state)
{
    uint32_t value = *state;
    value ^= value << 13; value ^= value >> 17; value ^= value << 5;
    *state = value;
    return value;
}
static inline void g3_order(unsigned order[8], uint32_t *state)
{
    for (unsigned i = 0; i < 8; ++i) order[i] = i;
    for (unsigned i = 7; i > 0; --i) {
        unsigned j = g3_random(state) % (i + 1), saved = order[i];
        order[i] = order[j]; order[j] = saved;
    }
}
#endif
