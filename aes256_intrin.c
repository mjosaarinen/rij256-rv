//  aes256_intrin.c
//  2025-01-12  Markku-Juhani O. Saarinen <mjos@iki.fi>

//  === Simple implementation of AES-256 with RISC-V Vector Crypto Intrinsics

#include "aes256_rv.h"

#ifdef USE_ZVKNED_INTRIN
#include <riscv_vector.h>

//  Expand 256-bit key "sk" into 15*16 - byte subkeys in "rk".

void aes256_exp_key(uint32_t rk[15 * 4], const uint8_t sk[32])
{
    const size_t vl = 4;        //  vaeskf2 is really 128-bit
    vuint32m1_t k0, k1;

    k0 = __riscv_vle32_v_u32m1((uint32_t *) sk, 4);
    __riscv_vse32_v_u32m1(&rk[ 0], k0, vl);
    k1 = __riscv_vle32_v_u32m1((uint32_t *) (sk + 16), 4);
    __riscv_vse32_v_u32m1(&rk[ 4], k1, vl);

    k0 = __riscv_vaeskf2_vi_u32m1(k0, k1, 2, vl);
    __riscv_vse32_v_u32m1(&rk[ 8], k0, 4);
    k1 = __riscv_vaeskf2_vi_u32m1(k1, k0, 3, vl);
    __riscv_vse32_v_u32m1(&rk[12], k1, 4);

    k0 = __riscv_vaeskf2_vi_u32m1(k0, k1, 4, vl);
    __riscv_vse32_v_u32m1(&rk[16], k0, 4);
    k1 = __riscv_vaeskf2_vi_u32m1(k1, k0, 5, vl);
    __riscv_vse32_v_u32m1(&rk[20], k1, 4);

    k0 = __riscv_vaeskf2_vi_u32m1(k0, k1, 6, vl);
    __riscv_vse32_v_u32m1(&rk[24], k0, 4);
    k1 = __riscv_vaeskf2_vi_u32m1(k1, k0, 7, vl);
    __riscv_vse32_v_u32m1(&rk[28], k1, 4);

    k0 = __riscv_vaeskf2_vi_u32m1(k0, k1, 8, vl);
    __riscv_vse32_v_u32m1(&rk[32], k0, 4);
    k1 = __riscv_vaeskf2_vi_u32m1(k1, k0, 9, vl);
    __riscv_vse32_v_u32m1(&rk[36], k1, 4);

    k0 = __riscv_vaeskf2_vi_u32m1(k0, k1, 10, vl);
    __riscv_vse32_v_u32m1(&rk[40], k0, 4);
    k1 = __riscv_vaeskf2_vi_u32m1(k1, k0, 11, vl);
    __riscv_vse32_v_u32m1(&rk[44], k1, 4);

    k0 = __riscv_vaeskf2_vi_u32m1(k0, k1, 12, vl);
    __riscv_vse32_v_u32m1(&rk[48], k0, 4);
    k1 = __riscv_vaeskf2_vi_u32m1(k1, k0, 13, vl);
    __riscv_vse32_v_u32m1(&rk[52], k1, 4);

    k0 = __riscv_vaeskf2_vi_u32m1(k0, k1, 14, vl);
    __riscv_vse32_v_u32m1(&rk[56], k0, 4);
}

//  Encrypt (ECB) "sz" bytes (must be divisible by 16) from "pt" to "ct".

void aes256_enc(void *ct, const void *pt,
                size_t sz, const uint32_t rk[15 * 4])
{
    size_t vl = __riscv_vsetvlmax_e32m1();                  //  system vl
    size_t n = sz / 4;
    uint32_t *ct32 = ct;
    const uint32_t *pt32 = pt;

    vuint32m1_t blk, k0, k1, k2, k3, k4, k5, k6, k7,
                k8, k9, k10, k11, k12, k13, k14;

    //  read in round keys
    k0  = __riscv_vle32_v_u32m1(&rk[ 0], 4);                //  load round keys
    k1  = __riscv_vle32_v_u32m1(&rk[ 4], 4);
    k2  = __riscv_vle32_v_u32m1(&rk[ 8], 4);
    k3  = __riscv_vle32_v_u32m1(&rk[12], 4);
    k4  = __riscv_vle32_v_u32m1(&rk[16], 4);
    k5  = __riscv_vle32_v_u32m1(&rk[20], 4);
    k6  = __riscv_vle32_v_u32m1(&rk[24], 4);
    k7  = __riscv_vle32_v_u32m1(&rk[28], 4);
    k8  = __riscv_vle32_v_u32m1(&rk[32], 4);
    k9  = __riscv_vle32_v_u32m1(&rk[36], 4);
    k10 = __riscv_vle32_v_u32m1(&rk[40], 4);
    k11 = __riscv_vle32_v_u32m1(&rk[44], 4);
    k12 = __riscv_vle32_v_u32m1(&rk[48], 4);
    k13 = __riscv_vle32_v_u32m1(&rk[52], 4);
    k14 = __riscv_vle32_v_u32m1(&rk[56], 4);

    while (n > 0) {

        if (n < vl) {
            vl = n;
        }
        n -= vl;

        blk = __riscv_vle32_v_u32m1(pt32, vl);              //  load pt
        pt32 += vl;

        blk = __riscv_vaesz_vs_u32m1_u32m1( blk, k0,  vl);  //  zero round
        blk = __riscv_vaesem_vs_u32m1_u32m1(blk, k1,  vl);  //  middle rounds
        blk = __riscv_vaesem_vs_u32m1_u32m1(blk, k2,  vl);
        blk = __riscv_vaesem_vs_u32m1_u32m1(blk, k3,  vl);
        blk = __riscv_vaesem_vs_u32m1_u32m1(blk, k4,  vl);
        blk = __riscv_vaesem_vs_u32m1_u32m1(blk, k5,  vl);
        blk = __riscv_vaesem_vs_u32m1_u32m1(blk, k6,  vl);
        blk = __riscv_vaesem_vs_u32m1_u32m1(blk, k7,  vl);
        blk = __riscv_vaesem_vs_u32m1_u32m1(blk, k8,  vl);
        blk = __riscv_vaesem_vs_u32m1_u32m1(blk, k9,  vl);
        blk = __riscv_vaesem_vs_u32m1_u32m1(blk, k10, vl);
        blk = __riscv_vaesem_vs_u32m1_u32m1(blk, k11, vl);
        blk = __riscv_vaesem_vs_u32m1_u32m1(blk, k12, vl);
        blk = __riscv_vaesem_vs_u32m1_u32m1(blk, k13, vl);
        blk = __riscv_vaesef_vs_u32m1_u32m1(blk, k14, vl);  //  final round

        __riscv_vse32_v_u32m1(ct32, blk, vl);               //  store ct
        ct32 += vl;
    }
}

//  Decrypt (ECB) "sz" bytes (must be divisible by 16) from "ct" to "pt".

void aes256_dec(void *pt, const void *ct,
                size_t sz, const uint32_t rk[15 * 4])
{
    size_t vl = __riscv_vsetvlmax_e32m1();                  //  system vl
    size_t n = sz / 4;
    uint32_t *pt32 = pt;
    const uint32_t *ct32 = ct;

    vuint32m1_t blk, k0, k1, k2, k3, k4, k5, k6, k7,
                k8, k9, k10, k11, k12, k13, k14;

    //  read in round keys
    k0  = __riscv_vle32_v_u32m1(&rk[ 0], 4);                //  load round keys
    k1  = __riscv_vle32_v_u32m1(&rk[ 4], 4);
    k2  = __riscv_vle32_v_u32m1(&rk[ 8], 4);
    k3  = __riscv_vle32_v_u32m1(&rk[12], 4);
    k4  = __riscv_vle32_v_u32m1(&rk[16], 4);
    k5  = __riscv_vle32_v_u32m1(&rk[20], 4);
    k6  = __riscv_vle32_v_u32m1(&rk[24], 4);
    k7  = __riscv_vle32_v_u32m1(&rk[28], 4);
    k8  = __riscv_vle32_v_u32m1(&rk[32], 4);
    k9  = __riscv_vle32_v_u32m1(&rk[36], 4);
    k10 = __riscv_vle32_v_u32m1(&rk[40], 4);
    k11 = __riscv_vle32_v_u32m1(&rk[44], 4);
    k12 = __riscv_vle32_v_u32m1(&rk[48], 4);
    k13 = __riscv_vle32_v_u32m1(&rk[52], 4);
    k14 = __riscv_vle32_v_u32m1(&rk[56], 4);

    while (n > 0) {

        if (n < vl) {
            vl = n;
        }
        n -= vl;

        blk = __riscv_vle32_v_u32m1(ct32, vl);              //  load ct
        ct32 += vl;

        blk = __riscv_vaesz_vs_u32m1_u32m1( blk, k14, vl);  //  zero round
        blk = __riscv_vaesdm_vs_u32m1_u32m1(blk, k13, vl);  //  middle rounds
        blk = __riscv_vaesdm_vs_u32m1_u32m1(blk, k12, vl);
        blk = __riscv_vaesdm_vs_u32m1_u32m1(blk, k11, vl);
        blk = __riscv_vaesdm_vs_u32m1_u32m1(blk, k10, vl);
        blk = __riscv_vaesdm_vs_u32m1_u32m1(blk, k9,  vl);
        blk = __riscv_vaesdm_vs_u32m1_u32m1(blk, k8,  vl);
        blk = __riscv_vaesdm_vs_u32m1_u32m1(blk, k7,  vl);
        blk = __riscv_vaesdm_vs_u32m1_u32m1(blk, k6,  vl);
        blk = __riscv_vaesdm_vs_u32m1_u32m1(blk, k5,  vl);
        blk = __riscv_vaesdm_vs_u32m1_u32m1(blk, k4,  vl);
        blk = __riscv_vaesdm_vs_u32m1_u32m1(blk, k3,  vl);
        blk = __riscv_vaesdm_vs_u32m1_u32m1(blk, k2,  vl);
        blk = __riscv_vaesdm_vs_u32m1_u32m1(blk, k1,  vl);
        blk = __riscv_vaesdf_vs_u32m1_u32m1(blk, k0,  vl);  //  final

        __riscv_vse32_v_u32m1(pt32, blk, vl);               //  store pt
        pt32 += vl;
    }
}

#endif
