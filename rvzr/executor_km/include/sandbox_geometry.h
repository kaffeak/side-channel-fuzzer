// SPDX-License-Identifier: MIT
// Passive actor-data geometry; not included by the active kernel executor.
//
// Only the explicit 4096 and 16384 profiles below are specified. The actor base
// must be kernel-page aligned; these constants do not allocate or align memory.
// The 16 KB profile is a candidate, not validated for runtime use. It cannot
// satisfy the active executor's 8 KB main-address alignment assertion. Its whole
// faulty mapping, including padding, would receive the selected PTE permissions;
// intersecting that mapping does not by itself imply a particular fault.
// Utility/code allocation, input serialization and instruction encodings are
// outside this header. No profile is selected from the host or kernel here.
//
// Keep expressions assembly-safe: integer arithmetic, no types or C suffixes.
// C/Python parity is checked by tests/unit_sandbox_geometry_c.py.

#ifndef RVZR_SANDBOX_GEOMETRY_H
#define RVZR_SANDBOX_GEOMETRY_H

#define RVZR_SG_PAGE_SIZE_4K  4096
#define RVZR_SG_PAGE_SIZE_16K 16384

// Logical sizes are independent of the kernel mapping granularity.
#define RVZR_SG_MAIN_SIZE          4096
#define RVZR_SG_FAULTY_SIZE        RVZR_SG_MAIN_SIZE
#define RVZR_SG_MACRO_STACK_SIZE   64
#define RVZR_SG_UNDERFLOW_PAD_SIZE (RVZR_SG_MAIN_SIZE - RVZR_SG_MACRO_STACK_SIZE)
#define RVZR_SG_REGISTER_INIT_SIZE 320
#define RVZR_SG_OVERFLOW_PAD_SIZE  (RVZR_SG_MAIN_SIZE - RVZR_SG_REGISTER_INIT_SIZE)

// All offsets and half-open mapping endpoints are actor-relative, not main-relative.
#define RVZR_SG_FAULTY_OFFSET(p) \
    (((2 * RVZR_SG_MAIN_SIZE + (p) - 1) / (p)) * (p))
#define RVZR_SG_MAIN_OFFSET(p)         (RVZR_SG_FAULTY_OFFSET(p) - RVZR_SG_MAIN_SIZE)
#define RVZR_SG_MACRO_STACK_OFFSET(p)  (RVZR_SG_MAIN_OFFSET(p) - RVZR_SG_MAIN_SIZE)
#define RVZR_SG_UNDERFLOW_PAD_OFFSET(p) \
    (RVZR_SG_MACRO_STACK_OFFSET(p) + RVZR_SG_MACRO_STACK_SIZE)
#define RVZR_SG_REGISTER_INIT_OFFSET(p) (RVZR_SG_FAULTY_OFFSET(p) + (p))
#define RVZR_SG_OVERFLOW_PAD_OFFSET(p) \
    (RVZR_SG_REGISTER_INIT_OFFSET(p) + RVZR_SG_REGISTER_INIT_SIZE)
#define RVZR_SG_LOCAL_STACK_OFFSET(p) (RVZR_SG_FAULTY_OFFSET(p) - 8)
#define RVZR_SG_ACTOR_STRIDE(p)       (RVZR_SG_REGISTER_INIT_OFFSET(p) + (p))

#define RVZR_SG_MAIN_MAPPING_START(p) ((RVZR_SG_MAIN_OFFSET(p) / (p)) * (p))
#define RVZR_SG_MAIN_MAPPING_END(p)   (RVZR_SG_MAIN_MAPPING_START(p) + (p))
#define RVZR_SG_FAULTY_MAPPING_START(p) RVZR_SG_FAULTY_OFFSET(p)
#define RVZR_SG_FAULTY_MAPPING_END(p)   RVZR_SG_REGISTER_INIT_OFFSET(p)
#define RVZR_SG_REGISTER_MAPPING_START(p) RVZR_SG_REGISTER_INIT_OFFSET(p)
#define RVZR_SG_REGISTER_MAPPING_END(p)   RVZR_SG_ACTOR_STRIDE(p)

#if !defined(__ASSEMBLER__) && !defined(__ASSEMBLY__)

_Static_assert(RVZR_SG_MAIN_SIZE == 4096 && RVZR_SG_FAULTY_SIZE == 4096,
               "logical payload sizes must remain 4 KB");
_Static_assert(RVZR_SG_MACRO_STACK_SIZE == 64 && RVZR_SG_UNDERFLOW_PAD_SIZE == 4032,
               "logical macro-stack/underflow sizes must remain unchanged");
_Static_assert(RVZR_SG_REGISTER_INIT_SIZE == 320 && RVZR_SG_OVERFLOW_PAD_SIZE == 3776,
               "logical register/overflow sizes must remain unchanged");

// Literal expectations are regression assertions, not a second layout definition.
#define RVZR_SG_ASSERT_PROFILE(p, macro, main, faulty, registers, stride) \
    _Static_assert(RVZR_SG_MACRO_STACK_OFFSET(p) == (macro), "macro-stack offset"); \
    _Static_assert(RVZR_SG_MAIN_OFFSET(p) == (main), "main offset"); \
    _Static_assert(RVZR_SG_FAULTY_OFFSET(p) == (faulty), "faulty offset"); \
    _Static_assert(RVZR_SG_REGISTER_INIT_OFFSET(p) == (registers), "register offset"); \
    _Static_assert(RVZR_SG_ACTOR_STRIDE(p) == (stride), "actor stride"); \
    _Static_assert(RVZR_SG_MACRO_STACK_OFFSET(p) >= 0, "macro-stack fits actor"); \
    _Static_assert(RVZR_SG_UNDERFLOW_PAD_OFFSET(p) + RVZR_SG_UNDERFLOW_PAD_SIZE == \
                   RVZR_SG_MAIN_OFFSET(p), "underflow ends at main"); \
    _Static_assert(RVZR_SG_MAIN_OFFSET(p) + RVZR_SG_MAIN_SIZE == \
                   RVZR_SG_FAULTY_OFFSET(p), "main/faulty contiguity"); \
    _Static_assert(RVZR_SG_MAIN_MAPPING_START(p) <= RVZR_SG_MAIN_OFFSET(p) && \
                   RVZR_SG_MAIN_OFFSET(p) + RVZR_SG_MAIN_SIZE <= \
                   RVZR_SG_MAIN_MAPPING_END(p), "main payload fits mapping"); \
    _Static_assert(RVZR_SG_MAIN_MAPPING_START(p) % (p) == 0 && \
                   RVZR_SG_MAIN_MAPPING_END(p) % (p) == 0, "main mapping alignment"); \
    _Static_assert(RVZR_SG_MAIN_MAPPING_END(p) <= RVZR_SG_FAULTY_MAPPING_START(p), \
                   "main/faulty mappings are disjoint"); \
    _Static_assert(RVZR_SG_FAULTY_MAPPING_START(p) % (p) == 0 && \
                   RVZR_SG_FAULTY_MAPPING_END(p) % (p) == 0, "faulty mapping alignment"); \
    _Static_assert(RVZR_SG_FAULTY_OFFSET(p) + RVZR_SG_FAULTY_SIZE <= \
                   RVZR_SG_FAULTY_MAPPING_END(p), "faulty payload fits mapping"); \
    _Static_assert(RVZR_SG_FAULTY_MAPPING_END(p) == RVZR_SG_REGISTER_MAPPING_START(p), \
                   "faulty/register mappings are separate and adjacent"); \
    _Static_assert(RVZR_SG_REGISTER_MAPPING_START(p) % (p) == 0 && \
                   RVZR_SG_REGISTER_MAPPING_END(p) % (p) == 0, "register mapping alignment"); \
    _Static_assert(RVZR_SG_OVERFLOW_PAD_OFFSET(p) + RVZR_SG_OVERFLOW_PAD_SIZE <= \
                   RVZR_SG_ACTOR_STRIDE(p), "registers/overflow fit actor"); \
    _Static_assert(RVZR_SG_ACTOR_STRIDE(p) % (p) == 0, "actor stride alignment"); \
    _Static_assert(RVZR_SG_LOCAL_STACK_OFFSET(p) - RVZR_SG_MAIN_OFFSET(p) == 4088, \
                   "local stack remains at main + 4088")

_Static_assert(RVZR_SG_PAGE_SIZE_4K == 4096 && RVZR_SG_PAGE_SIZE_16K == 16384,
               "only the established 4 KB and candidate 16 KB profiles are specified");
RVZR_SG_ASSERT_PROFILE(RVZR_SG_PAGE_SIZE_4K, 0, 4096, 8192, 12288, 16384);
RVZR_SG_ASSERT_PROFILE(RVZR_SG_PAGE_SIZE_16K, 8192, 12288, 16384, 32768, 49152);
#undef RVZR_SG_ASSERT_PROFILE

#endif // C-only assertions
#endif // RVZR_SANDBOX_GEOMETRY_H
