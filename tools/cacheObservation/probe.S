// SPDX-License-Identifier: MIT
#if !defined(__aarch64__) && !defined(__arm64__)
#error "Native AArch64 only"
#endif
#ifdef __APPLE__
#define SYM(x) _##x
#else
#define SYM(x) x
#endif
.text
.p2align 2
.globl SYM(g3_probe)
SYM(g3_probe):
    dsb ish
    isb
    mrs x2, cntvct_el0
    isb
    ldr x4, [x0]              // Exactly one fixed-width target load in the window.
    dsb ish
    isb
    mrs x3, cntvct_el0
    isb
    stp x2, x3, [x1]         // All result stores AFTER the ending timestamp/ISB.
    str x4, [x1, #16]
    ret
.p2align 2
.globl SYM(g3_empty)
SYM(g3_empty):
    dsb ish
    isb
    mrs x2, cntvct_el0
    isb
    mov x4, xzr              // Empty reference, not a target-memory access.
    dsb ish
    isb
    mrs x3, cntvct_el0
    isb
    stp x2, x3, [x1]
    str x4, [x1, #16]
    ret
.p2align 2
.globl SYM(g3_trial)
SYM(g3_trial):
    // (target, buffer, bytes, stride, result, order). Leaf; X18/SP/LR untouched.
    cbz w5, 1f
    ldr x8, [x0]             // target_before_sweep: same load, before the sweep.
1:  mov x6, #0
2:  ldr x7, [x1, x6]
    add x6, x6, x3
    cmp x6, x2
    b.lo 2b
    cbnz w5, 3f
    ldr x8, [x0]             // target_last: last memory access before the wrapper.
3:  mov x1, x4
    b SYM(g3_probe)          // Same probe for A/B/null/repeat. No executable allocation.
.p2align 2
.globl SYM(g3_frequency)
SYM(g3_frequency):
    isb
    mrs x0, cntfrq_el0
    isb
    ret
#ifndef __APPLE__
.section .note.GNU-stack,"",%progbits
#endif
