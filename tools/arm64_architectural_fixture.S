// SPDX-License-Identifier: MIT
// Trusted B3.4a instruction body, with a userspace RET instead of kernel macros.
// No external relocations, stack accesses, indirect branches, or input-derived pointers.
.section .rodata.rvzr_fixture,"a",%progbits
.balign 4
.global rvzr_fixture
.type rvzr_fixture, %object
rvzr_fixture:
    cmp x0, #0
    b.eq .Ltaken
    mov x1, #11
    b .Ljoin
.Ltaken:
    mov x1, #22
.Ljoin:
    ldr x2, [x20], #0
    add x3, x1, x2
    str x3, [x20], #0
    ret
.Lfixture_end:
.size rvzr_fixture, .Lfixture_end - rvzr_fixture

.section .rodata.rvzr_fixture_size,"a",%progbits
.balign 8
.global rvzr_fixture_size
.type rvzr_fixture_size, %object
rvzr_fixture_size:
    .quad .Lfixture_end - rvzr_fixture
.size rvzr_fixture_size, 8

.text
.balign 4
.global rvzr_arch_invoke
.type rvzr_arch_invoke, %function
// (code, main, selector, result). Result layout checked in the C source.
// Only X19/X20 and FP/LR among preserved registers are touched; SIMD and X18
// are untouched. The fixed fixture never changes SP, X19, X20, or X30.
rvzr_arch_invoke:
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    mov x19, x3
    mov x20, x1
    mov x16, x0
    mov x0, x2
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    mov x6, xzr
    mov x7, xzr
    msr nzcv, xzr
    blr x16
    stp x0, x1, [x19]
    stp x2, x3, [x19, #16]
    stp x4, x5, [x19, #32]
    stp x6, x7, [x19, #48]
    mrs x9, nzcv
    str x9, [x19, #64]
    mov x9, sp
    and x9, x9, #15
    str x9, [x19, #72]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
.size rvzr_arch_invoke, . - rvzr_arch_invoke
.section .note.GNU-stack,"",%progbits
