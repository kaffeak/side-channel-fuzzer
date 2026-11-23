// SPDX-License-Identifier: MIT
#if !defined(__linux__) || !defined(__aarch64__)
#error "AArch64 Linux only"
#endif
.text
.p2align 2
.global p0_adjacent
.type p0_adjacent, %function
p0_adjacent:
    dmb ish                     // Reset ordering, outside exclusive interval.
    ldxr x3, [x0]
    stxr w4, x1, [x0]
    dmb ish                     // Completion/readback, after STXR.
    ldr x5, [x0]
    stp x3, x5, [x2]
    str w4, [x2, #16]
    ret
.size p0_adjacent, .-p0_adjacent
.global p0_clear
.type p0_clear, %function
p0_clear:
    dmb ish
    ldxr x3, [x0]
    clrex
    stxr w4, x1, [x0]
    dmb ish
    ldr x5, [x0]
    stp x3, x5, [x2]
    str w4, [x2, #16]
    ret
.size p0_clear, .-p0_clear
.global p0_sham
.type p0_sham, %function
p0_sham:
    dmb ish
    ldxr x3, [x0]
    nop
    stxr w4, x1, [x0]
    dmb ish
    ldr x5, [x0]
    stp x3, x5, [x2]
    str w4, [x2, #16]
    ret
.size p0_sham, .-p0_sham
.global p0_clear_old
.type p0_clear_old, %function
p0_clear_old:
    clrex
    ret
.size p0_clear_old, .-p0_clear_old
.section .note.GNU-stack,"",%progbits
