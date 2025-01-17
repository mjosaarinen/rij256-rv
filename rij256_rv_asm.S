//  rij256_rv_asm.S
//  2025-01-13  Markku-Juhani O. Saarinen <mjos@iki.fi>

//  === Rijndael-256 using RISC-V Zvkned extensions.
//  Originally derived from the (clang) intrinsics code, cleaned up a bit.

#ifndef USE_ZVKNED_INTRIN

    .option nopic
    .attribute unaligned_access, 0
    .attribute stack_align, 16
    .text
    .align  1

//  === Expand 256-bit key "sk" into 15*32 - byte subkeys in "rk".

//      void rij256_exp_key(uint32_t rk[15 * 8], const uint8_t sk[32]);

    .globl      rij256_exp_key
    .p2align    1
    .type       rij256_exp_key,@function

rij256_exp_key:
    .cfi_startproc
    vsetivli    zero, 4, e32, m1, ta, ma
    vle32.v     v8, (a1)
    vse32.v v8, (a0)
    addi        a1, a1, 16
    vle32.v     v9, (a1)
    addi        a1, a0, 16
    vse32.v v9, (a1)
    vaeskf2.vi  v8, v9, 2
    addi        a1, a0, 32
    vse32.v v8, (a1)
    vaeskf2.vi  v9, v8, 3
    addi        a1, a0, 48
    vse32.v v9, (a1)
    vaeskf2.vi  v8, v9, 4
    addi        a1, a0, 64
    vse32.v v8, (a1)
    vaeskf2.vi  v9, v8, 5
    addi        a1, a0, 80
    vse32.v v9, (a1)
    vaeskf2.vi  v8, v9, 6
    addi        a1, a0, 96
    vse32.v v8, (a1)
    vaeskf2.vi  v9, v8, 7
    addi        a1, a0, 112
    vse32.v v9, (a1)
    vaeskf2.vi  v8, v9, 8
    addi        a1, a0, 128
    vse32.v v8, (a1)
    vaeskf2.vi  v9, v8, 9
    addi        a1, a0, 144
    vse32.v v9, (a1)
    vaeskf2.vi  v8, v9, 10
    addi        a1, a0, 160
    vse32.v v8, (a1)
    vaeskf2.vi  v9, v8, 11
    addi        a1, a0, 176
    vse32.v v9, (a1)
    vaeskf2.vi  v8, v9, 12
    addi        a1, a0, 192
    vse32.v v8, (a1)
    vaeskf2.vi  v9, v8, 13
    addi        a1, a0, 208
    vse32.v v9, (a1)
    vaeskf2.vi  v8, v9, 14
    addi        a1, a0, 224
    vse32.v v8, (a1)
    vaeskf2.vi  v9, v8, 3
    addi        a1, a0, 240
    vse32.v v9, (a1)
    li          a1, 129
    vsetivli    zero, 1, e32, m1, tu, ma
    vxor.vx v8, v8, a1
    vsetivli    zero, 4, e32, m1, ta, ma
    vaeskf2.vi  v8, v9, 2
    addi        a1, a0, 256
    vse32.v v8, (a1)
    vaeskf2.vi  v9, v8, 3
    addi        a1, a0, 272
    vse32.v v9, (a1)
    li          a1, 26
    vsetivli    zero, 1, e32, m1, tu, ma
    vxor.vx v8, v8, a1
    vsetivli    zero, 4, e32, m1, ta, ma
    vaeskf2.vi  v8, v9, 2
    addi        a1, a0, 288
    vse32.v v8, (a1)
    vaeskf2.vi  v9, v8, 3
    addi        a1, a0, 304
    vse32.v v9, (a1)
    li          a1, 55
    vsetivli    zero, 1, e32, m1, tu, ma
    vxor.vx v8, v8, a1
    vsetivli    zero, 4, e32, m1, ta, ma
    vaeskf2.vi  v8, v9, 2
    addi        a1, a0, 320
    vse32.v v8, (a1)
    vaeskf2.vi  v9, v8, 3
    addi        a1, a0, 336
    vse32.v v9, (a1)
    li          a1, 109
    vsetivli    zero, 1, e32, m1, tu, ma
    vxor.vx v8, v8, a1
    vsetivli    zero, 4, e32, m1, ta, ma
    vaeskf2.vi  v8, v9, 2
    addi        a1, a0, 352
    vse32.v v8, (a1)
    vaeskf2.vi  v9, v8, 3
    addi        a1, a0, 368
    vse32.v v9, (a1)
    li          a1, 217
    vsetivli    zero, 1, e32, m1, tu, ma
    vxor.vx v8, v8, a1
    vsetivli    zero, 4, e32, m1, ta, ma
    vaeskf2.vi  v8, v9, 2
    addi        a1, a0, 384
    vse32.v v8, (a1)
    vaeskf2.vi  v9, v8, 3
    addi        a1, a0, 400
    vse32.v v9, (a1)
    li          a1, 170
    vsetivli    zero, 1, e32, m1, tu, ma
    vxor.vx v8, v8, a1
    vsetivli    zero, 4, e32, m1, ta, ma
    vaeskf2.vi  v8, v9, 2
    addi        a1, a0, 416
    vse32.v v8, (a1)
    vaeskf2.vi  v9, v8, 3
    addi        a1, a0, 432
    vse32.v v9, (a1)
    li          a1, 76
    vsetivli    zero, 1, e32, m1, tu, ma
    vxor.vx v8, v8, a1
    vsetivli    zero, 4, e32, m1, ta, ma
    vaeskf2.vi  v8, v9, 2
    addi        a1, a0, 448
    vse32.v v8, (a1)
    vaeskf2.vi  v9, v8, 3
    addi        a0, a0, 464
    vse32.v v9, (a0)
    ret
.Lfunc_end0:
    .size   rij256_exp_key, .Lfunc_end0-rij256_exp_key
    .cfi_endproc

//  === Encrypt (ECB) "sz" bytes (must be divisible by 32) from "pt" to "ct".

//      void rij256_enc(void *ct, const void *pt,
//                      size_t sz, const uint32_t rk[15 * 8]);

    .globl  rij256_enc
    .p2align    1
    .type   rij256_enc,@function
rij256_enc:
    .cfi_startproc
    srli    a2, a2, 2
    beqz    a2, .LBB1_3

.Lpcrel_hi0:
    auipc   a4, %pcrel_hi(.L__const.rij256_enc.rij256_shufe)
    addi        a5, a4, %pcrel_lo(.Lpcrel_hi0)
    li          a4, 32
    vsetvli     zero, a4, e8, m1, ta, ma
    vle8.v  v8, (a5)
    vsetivli    zero, 8, e32, m1, ta, ma
    vle32.v     v9, (a3)
    addi        a5, a3, 32
    vle32.v     v10, (a5)
    addi        a5, a3, 64
    vle32.v     v11, (a5)
    addi        a5, a3, 96
    vle32.v     v12, (a5)
    addi        a5, a3, 128
    vle32.v     v13, (a5)
    addi        a5, a3, 160
    vle32.v     v14, (a5)
    addi        a5, a3, 192
    vle32.v     v15, (a5)
    addi        a5, a3, 224
    vle32.v     v16, (a5)
    addi        a5, a3, 256
    vle32.v     v17, (a5)
    addi        a5, a3, 288
    vle32.v     v18, (a5)
    addi        a5, a3, 320
    vle32.v     v19, (a5)
    addi        a5, a3, 352
    vle32.v     v20, (a5)
    addi        a5, a3, 384
    vle32.v     v21, (a5)
    addi        a5, a3, 416
    vle32.v     v22, (a5)
    addi        a3, a3, 448
    vle32.v     v23, (a3)
.LBB1_2:
    vle32.v     v24, (a1)
    addi        a2, a2, -8
    addi        a1, a1, 32
    vxor.vv     v24, v24, v9
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v25, v24, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesem.vv   v25, v10
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v24, v25, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesem.vv   v24, v11
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v25, v24, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesem.vv   v25, v12
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v24, v25, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesem.vv   v24, v13
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v25, v24, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesem.vv   v25, v14
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v24, v25, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesem.vv   v24, v15
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v25, v24, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesem.vv   v25, v16
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v24, v25, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesem.vv   v24, v17
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v25, v24, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesem.vv   v25, v18
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v24, v25, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesem.vv   v24, v19
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v25, v24, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesem.vv   v25, v20
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v24, v25, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesem.vv   v24, v21
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v25, v24, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesem.vv   v25, v22
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v24, v25, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesef.vv   v24, v23
    vse32.v     v24, (a0)
    addi        a0, a0, 32
    bnez        a2, .LBB1_2
.LBB1_3:
    ret
.Lfunc_end1:
    .size   rij256_enc, .Lfunc_end1-rij256_enc
    .cfi_endproc

//  === Decrypt (ECB) "sz" bytes (must be divisible by 32) from "ct" to "pt".

//      void rij256_dec(void *pt, const void *ct,
//                      size_t sz, const uint32_t rk[15 * 8]);

    .globl      rij256_dec
    .p2align    1
    .type       rij256_dec,@function

rij256_dec:
    .cfi_startproc
    srli        a2, a2, 2
    beqz        a2, .LBB2_3
.Lpcrel_hi1:
    auipc       a4, %pcrel_hi(.L__const.rij256_dec.rij256_shufd)
    addi        a5, a4, %pcrel_lo(.Lpcrel_hi1)
    li          a4, 32
    vsetvli     zero, a4, e8, m1, ta, ma
    vle8.v  v8, (a5)
    vsetivli    zero, 8, e32, m1, ta, ma
    vle32.v     v9, (a3)
    addi        a5, a3, 32
    vle32.v     v10, (a5)
    addi        a5, a3, 64
    vle32.v     v11, (a5)
    addi        a5, a3, 96
    vle32.v     v12, (a5)
    addi        a5, a3, 128
    vle32.v     v13, (a5)
    addi        a5, a3, 160
    vle32.v     v14, (a5)
    addi        a5, a3, 192
    vle32.v     v15, (a5)
    addi        a5, a3, 224
    vle32.v     v16, (a5)
    addi        a5, a3, 256
    vle32.v     v17, (a5)
    addi        a5, a3, 288
    vle32.v     v18, (a5)
    addi        a5, a3, 320
    vle32.v     v19, (a5)
    addi        a5, a3, 352
    vle32.v     v20, (a5)
    addi        a5, a3, 384
    vle32.v     v21, (a5)
    addi        a5, a3, 416
    vle32.v     v22, (a5)
    addi        a3, a3, 448
    vle32.v     v23, (a3)
.LBB2_2:
    vle32.v     v24, (a1)
    addi        a2, a2, -8
    addi        a1, a1, 32
    vxor.vv v24, v24, v23
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v25, v24, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesdm.vv   v25, v22
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v24, v25, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesdm.vv   v24, v21
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v25, v24, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesdm.vv   v25, v20
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v24, v25, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesdm.vv   v24, v19
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v25, v24, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesdm.vv   v25, v18
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v24, v25, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesdm.vv   v24, v17
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v25, v24, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesdm.vv   v25, v16
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v24, v25, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesdm.vv   v24, v15
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v25, v24, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesdm.vv   v25, v14
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v24, v25, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesdm.vv   v24, v13
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v25, v24, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesdm.vv   v25, v12
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v24, v25, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesdm.vv   v24, v11
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v25, v24, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesdm.vv   v25, v10
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v24, v25, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesdf.vv   v24, v9
    vse32.v     v24, (a0)
    addi        a0, a0, 32
    bnez        a2, .LBB2_2
.LBB2_3:
    ret
.Lfunc_end2:
    .size   rij256_dec, .Lfunc_end2-rij256_dec
    .cfi_endproc

    .type   .L__const.rij256_enc.rij256_shufe,@object

    .section    .rodata.cst32,"aM",@progbits,32
.L__const.rij256_enc.rij256_shufe:
    .byte       0,  17, 22, 23, 4,  5,  26, 27, 8,  9,  14, 31, 12, 13, 18, 19
    .byte       16, 1,  6,  7,  20, 21, 10, 11, 24, 25, 30, 15, 28, 29, 2,  3
    .size   .L__const.rij256_enc.rij256_shufe, 32

    .type   .L__const.rij256_dec.rij256_shufd,@object
.L__const.rij256_dec.rij256_shufd:
    .byte       0,  1,  30, 31, 4,  5,  2,  19, 8,  9,  22, 23, 12, 29, 26, 27
    .byte       16, 17, 14, 15, 20, 21, 18, 3,  24, 25, 6,  7,  28, 13, 10, 11
    .size   .L__const.rij256_dec.rij256_shufd, 32

#endif
