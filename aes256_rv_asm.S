//  aes256_rv_asm.S
//  2025-01-12  Markku-Juhani O. Saarinen <mjos@iki.fi>

//  === AES-256 using RISC-V Zvnked extensions.
//  Originally generated with gcc from intrinsics, but looks pretty tight.

#ifndef USE_ZVKNED_INTRIN

    .option nopic
    .attribute unaligned_access, 0
    .attribute stack_align, 16
    .text
    .align  1

//  === Expand 256-bit key "sk" into 15*16 - byte subkeys in "rk".

//      void aes256_exp_key(uint32_t rk[15 * 4], const uint8_t sk[32]);

    .globl  aes256_exp_key
    .type   aes256_exp_key, @function

aes256_exp_key:
    .cfi_startproc
    vsetivli    zero, 4, e32, m1, ta, ma
    vle32.v     v2, 0(a1)
    addi        a1, a1, 16
    addi        a5, a0, 16
    addi        t6, a0, 32
    addi        t5, a0, 48
    addi        t4, a0, 64
    vse32.v     v2, 0(a0)
    addi        t3, a0, 80
    addi        t1, a0, 96
    addi        a7, a0, 112
    addi        a6, a0, 128
    addi        a2, a0, 160
    vle32.v     v1, 0(a1)
    addi        a1, a0, 144
    addi        a3, a0, 176
    addi        a4, a0, 192
    vse32.v     v1, 0(a5)
    vaeskf2.vi  v2, v1, 2
    addi        a5, a0, 208
    addi        a0, a0, 224
    vaeskf2.vi  v1, v2, 3
    vse32.v     v2, 0(t6)
    vaeskf2.vi  v2, v1, 4
    vse32.v     v1, 0(t5)
    vaeskf2.vi  v1, v2, 5
    vmv1r.v     v3, v2
    vaeskf2.vi  v3, v1, 6
    vse32.v     v2, 0(t4)
    vmv1r.v     v2, v1
    vmv1r.v     v5, v3
    vaeskf2.vi  v2, v3, 7
    vse32.v     v1, 0(t3)
    vaeskf2.vi  v5, v2, 8
    vmv1r.v     v4, v2
    vse32.v     v3, 0(t1)
    vaeskf2.vi  v4, v5, 9
    vmv1r.v     v3, v5
    vaeskf2.vi  v3, v4, 10
    vse32.v     v2, 0(a7)
    vmv1r.v     v2, v4
    vmv1r.v     v1, v3
    vaeskf2.vi  v2, v3, 11
    vse32.v     v5, 0(a6)
    vaeskf2.vi  v1, v2, 12
    vmv1r.v v5, v2
    vse32.v     v4, 0(a1)
    vaeskf2.vi  v5, v1, 13
    vmv1r.v     v4, v1
    vaeskf2.vi  v4, v5, 14
    vse32.v     v3, 0(a2)
    vse32.v     v2, 0(a3)
    vse32.v     v1, 0(a4)
    vse32.v     v5, 0(a5)
    vse32.v     v4, 0(a0)
    ret
    .cfi_endproc
.LFE0:
    .size   aes256_exp_key, .-aes256_exp_key
    .align  1


//  === Encrypt (ECB) "sz" bytes (must be divisible by 16) from "pt" to "ct".

//      void aes256_enc(void *ct, const void *pt,
//                      size_t sz, const uint32_t rk[15 * 4]);

    .globl  aes256_enc
    .type   aes256_enc, @function

aes256_enc:
    .cfi_startproc
    vsetivli    zero, 4, e32, m1, ta, ma
    addi        a6, a3, 16
    addi        a4, a3, 32
    addi        a5, a3, 48
    vle32.v     v16, 0(a6)
    vle32.v     v15, 0(a4)
    vle32.v     v14, 0(a5)
    addi        t2, a3, 64
    addi        t0, a3, 80
    addi        t6, a3, 96
    addi        t5, a3, 112
    addi        t4, a3, 128
    addi        t3, a3, 144
    addi        t1, a3, 160
    addi        a7, a3, 176
    addi        a6, a3, 192
    addi        a4, a3, 208
    addi        a5, a3, 224
    srli        a2, a2, 2
    vle32.v     v13, 0(t2)
    vle32.v     v12, 0(t0)
    vle32.v     v11, 0(t6)
    vle32.v     v10, 0(t5)
    vle32.v     v9, 0(t4)
    vle32.v     v8, 0(t3)
    vle32.v     v7, 0(t1)
    vle32.v     v6, 0(a7)
    vle32.v     v5, 0(a6)
    vle32.v     v4, 0(a4)
    vle32.v     v3, 0(a5)
    vle32.v     v2, 0(a3)
    vsetvli     a5, zero, e32, m1, ta, ma
    beq         a2, zero, .L11
.L6:
    bleu        a5, a2, .L5
    mv          a5, a2
    vsetvli     zero, a5, e32, m1, ta, ma
.L5:
    vle32.v     v1, 0(a1)
    slli        a4, a5, 2
    sub a2,     a2, a5
    add a1,     a1, a4
    vaesz.vs    v1, v2
    vaesem.vs   v1, v16
    vaesem.vs   v1, v15
    vaesem.vs   v1, v14
    vaesem.vs   v1, v13
    vaesem.vs   v1, v12
    vaesem.vs   v1, v11
    vaesem.vs   v1, v10
    vaesem.vs   v1, v9
    vaesem.vs   v1, v8
    vaesem.vs   v1, v7
    vaesem.vs   v1, v6
    vaesem.vs   v1, v5
    vaesem.vs   v1, v4
    vaesef.vs   v1, v3
    vse32.v     v1, 0(a0)
    add         a0, a0, a4
    bne         a2, zero, .L6
.L11:
    ret
    .cfi_endproc
.LFE1:
    .size   aes256_enc, .-aes256_enc
    .align  1


//  === Decrypt (ECB) "sz" bytes (must be divisible by 16) from "ct" to "pt".

//      void aes256_dec(void *pt, const void *ct,
//                      size_t sz, const uint32_t rk[15 * 4]);

    .globl      aes256_dec
    .type       aes256_dec, @function

aes256_dec:
    .cfi_startproc
    vsetivli    zero, 4, e32, m1, ta, ma
    addi        a6, a3, 16
    addi        a4, a3, 32
    addi        a5, a3, 48
    vle32.v     v16, 0(a6)
    vle32.v     v15, 0(a4)
    vle32.v     v14, 0(a5)
    addi        t2, a3, 64
    addi        t0, a3, 80
    addi        t6, a3, 96
    addi        t5, a3, 112
    addi        t4, a3, 128
    addi        t3, a3, 144
    addi        t1, a3, 160
    addi        a7, a3, 176
    addi        a6, a3, 192
    addi        a4, a3, 208
    addi        a5, a3, 224
    srli        a2, a2, 2
    vle32.v     v13, 0(t2)
    vle32.v     v12, 0(t0)
    vle32.v     v11, 0(t6)
    vle32.v     v10, 0(t5)
    vle32.v     v9, 0(t4)
    vle32.v     v8, 0(t3)
    vle32.v     v7, 0(t1)
    vle32.v     v6, 0(a7)
    vle32.v     v5, 0(a6)
    vle32.v     v4, 0(a4)
    vle32.v     v3, 0(a5)
    vle32.v     v2, 0(a3)
    vsetvli     a5, zero, e32, m1, ta, ma
    beq         a2, zero, .L21
.L16:
    bleu        a5, a2, .L15
    mv          a5, a2
    vsetvli     zero, a5, e32, m1, ta, ma
.L15:
    vle32.v     v1, 0(a1)
    slli        a4, a5, 2
    sub a2,     a2, a5
    add a1,     a1, a4
    vaesz.vs    v1, v3
    vaesdm.vs   v1, v4
    vaesdm.vs   v1, v5
    vaesdm.vs   v1, v6
    vaesdm.vs   v1, v7
    vaesdm.vs   v1, v8
    vaesdm.vs   v1, v9
    vaesdm.vs   v1, v10
    vaesdm.vs   v1, v11
    vaesdm.vs   v1, v12
    vaesdm.vs   v1, v13
    vaesdm.vs   v1, v14
    vaesdm.vs   v1, v15
    vaesdm.vs   v1, v16
    vaesdf.vs   v1, v2
    vse32.v v1, 0(a0)
    add         a0, a0, a4
    bne         a2, zero, .L16
.L21:
    ret
    .cfi_endproc
.LFE2:
    .size   aes256_dec, .-aes256_dec
    .section    .note.GNU-stack, "", @progbits

#endif
