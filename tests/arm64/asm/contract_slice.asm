// Software-only seq+ct fixture. X20 is the model's main-region base.
.section .data.main
.function_0:
    cmp x0, #0
    b.eq .taken
.fallthrough:
    mov x1, #11
    b .join
.taken:
    mov x1, #22
.join:
    ldr x2, [x20], #0
    add x3, x1, x2
    str x3, [x20], #0
.test_case_exit:
