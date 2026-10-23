// B3.4d: only the RANDOM slots vary; selector/pointers/memory accesses stay fixed.
.section .data.main
.function_0:
.macro.random_instructions.8.0:
    add x4, x20, #128
    cmp x0, #0
    b.eq .taken
.fallthrough:
.macro.random_instructions.4.0:
    mov x1, #11
    ldr x2, [x20], #0
    str x1, [x20], #0
    cmp x1, #12
    b .join
.taken:
.macro.random_instructions.4.0:
    mov x1, #22
    ldr x2, [x4], #0
    str x1, [x4], #0
    cmp x1, #22
.join:
    add x3, x1, x2
.test_case_exit:
