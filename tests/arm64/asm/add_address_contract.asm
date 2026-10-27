.section .data.main
.function_0:
    cmp x0, #0
    add x4, x1, x2
    and x4, x4, #128
    add x4, x20, x4
    b.eq .computed
.fallthrough:
    mov x3, #11
    ldr x5, [x20], #0
    str x3, [x20], #0
    cmp x3, #12
    b .join
.computed:
    mov x3, #22
    ldr x5, [x4], #0
    str x3, [x4], #0
    cmp x3, #22
.join:
    add x3, x3, x5
.test_case_exit:
