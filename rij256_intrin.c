//  rij256_intrin.c
//  2025-01-12  Markku-Juhani O. Saarinen <mjos@iki.fi>

//  === Rijndael-(256,256) implementation with RISC-V Vector C intrinsics

#include "rij256_rv.h"

#ifdef USE_ZVKNED_INTRIN
#include <riscv_vector.h>

//  Expand 256-bit key "sk" into 15*32 - byte subkeys in "rk".

void rij256_exp_key(uint32_t rk[15 * 8], const uint8_t sk[32])
{
    //  round constants (we actually just use 8..14)
    const uint32_t rij_rc[30] = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B,
        0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63,
        0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5  };

    int r;
    const size_t vl = 4;        //  vaeskf2 is really 128-bit
    vuint32m1_t k0, k1;

    //  the first half is equivalent to AES-256 key schedule
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

    //  === Rijndael-(256,256) half
    k1 = __riscv_vaeskf2_vi_u32m1(k1, k0, 3, vl);   //  round can be any odd
    __riscv_vse32_v_u32m1(&rk[60], k1, 4);

    //  we have run out of round constant immediates, need a little work-around
    for (r = 8; r < 15; r++) {

        //  cancel first round constant, insert the appropriate one
        k0 = __riscv_vxor_vx_u32m1_tu(k0, k0, 0x01 ^ rij_rc[r], 1);

        k0 = __riscv_vaeskf2_vi_u32m1(k0, k1, 2, vl);
        __riscv_vse32_v_u32m1(&rk[r * 8], k0, 4);

        k1 = __riscv_vaeskf2_vi_u32m1(k1, k0, 3, vl);
        __riscv_vse32_v_u32m1(&rk[r * 8 + 4], k1, 4);
    }
}


//  byte shuffle with vrgather.vv

static inline vuint32m1_t rij256_shuf8( vuint32m1_t blk,
                                        vuint8m1_t shuf,
                                        size_t vl)
{
    blk = __riscv_vreinterpret_v_u8m1_u32m1(
                __riscv_vrgather_vv_u8m1(
                    __riscv_vreinterpret_v_u32m1_u8m1(blk),
                        shuf, 4 * vl));
    return  blk;
}

//  Encrypt (ECB) "sz" bytes (must be divisible by 32) from "pt" to "ct".

void rij256_enc(void *ct, const void *pt,
                size_t sz, const uint32_t rk[15 * 8])
{
    const uint8_t rij256_shufe[32] = {
        0,  17, 22, 23, 4,  5,  26, 27, 8,  9,  14, 31, 12, 13, 18, 19,
        16, 1,  6,  7,  20, 21, 10, 11, 24, 25, 30, 15, 28, 29, 2,  3  };

    //  size_t vl = __riscv_vsetvlmax_e32m1();
    const size_t vl = 8;    //  currently just vlen=256
    size_t n = sz / 4;
    const uint32_t *pt32 = pt;  //  input blocks
    uint32_t *ct32 = ct;        //  output blocks

    const vuint8m1_t  se8   =__riscv_vle8_v_u8m1(rij256_shufe, 32);

    vuint32m1_t blk, k0, k1, k2, k3, k4, k5, k6, k7,
                k8, k9, k10, k11, k12, k13, k14;

    k0  = __riscv_vle32_v_u32m1(&rk[  0], 8);           //  load round keys
    k1  = __riscv_vle32_v_u32m1(&rk[  8], 8);
    k2  = __riscv_vle32_v_u32m1(&rk[ 16], 8);
    k3  = __riscv_vle32_v_u32m1(&rk[ 24], 8);
    k4  = __riscv_vle32_v_u32m1(&rk[ 32], 8);
    k5  = __riscv_vle32_v_u32m1(&rk[ 40], 8);
    k6  = __riscv_vle32_v_u32m1(&rk[ 48], 8);
    k7  = __riscv_vle32_v_u32m1(&rk[ 56], 8);
    k8  = __riscv_vle32_v_u32m1(&rk[ 64], 8);
    k9  = __riscv_vle32_v_u32m1(&rk[ 72], 8);
    k10 = __riscv_vle32_v_u32m1(&rk[ 80], 8);
    k11 = __riscv_vle32_v_u32m1(&rk[ 88], 8);
    k12 = __riscv_vle32_v_u32m1(&rk[ 96], 8);
    k13 = __riscv_vle32_v_u32m1(&rk[104], 8);
    k14 = __riscv_vle32_v_u32m1(&rk[112], 8);

    while (n > 0) {
        n -= vl;

        blk = __riscv_vle32_v_u32m1(pt32, vl);          //  load plaintext
        pt32 += vl;

        blk = __riscv_vxor_vv_u32m1(blk, k0, vl);       //  zero round
        blk = rij256_shuf8(blk, se8, vl);
        blk = __riscv_vaesem_vv_u32m1(blk, k1, vl);     //  middle rounds
        blk = rij256_shuf8(blk, se8, vl);
        blk = __riscv_vaesem_vv_u32m1(blk, k2, vl);
        blk = rij256_shuf8(blk, se8, vl);
        blk = __riscv_vaesem_vv_u32m1(blk, k3, vl);
        blk = rij256_shuf8(blk, se8, vl);
        blk = __riscv_vaesem_vv_u32m1(blk, k4, vl);
        blk = rij256_shuf8(blk, se8, vl);
        blk = __riscv_vaesem_vv_u32m1(blk, k5, vl);
        blk = rij256_shuf8(blk, se8, vl);
        blk = __riscv_vaesem_vv_u32m1(blk, k6, vl);
        blk = rij256_shuf8(blk, se8, vl);
        blk = __riscv_vaesem_vv_u32m1(blk, k7, vl);
        blk = rij256_shuf8(blk, se8, vl);
        blk = __riscv_vaesem_vv_u32m1(blk, k8, vl);
        blk = rij256_shuf8(blk, se8, vl);
        blk = __riscv_vaesem_vv_u32m1(blk, k9, vl);
        blk = rij256_shuf8(blk, se8, vl);
        blk = __riscv_vaesem_vv_u32m1(blk, k10, vl);
        blk = rij256_shuf8(blk, se8, vl);
        blk = __riscv_vaesem_vv_u32m1(blk, k11, vl);
        blk = rij256_shuf8(blk, se8, vl);
        blk = __riscv_vaesem_vv_u32m1(blk, k12, vl);
        blk = rij256_shuf8(blk, se8, vl);
        blk = __riscv_vaesem_vv_u32m1(blk, k13, vl);
        blk = rij256_shuf8(blk, se8, vl);
        blk = __riscv_vaesef_vv_u32m1(blk, k14, vl);    //  final round

        __riscv_vse32_v_u32m1(ct32, blk, vl);           //  store ciphertext
        ct32 += vl;
    }
}

//  Decrypt (ECB) "sz" bytes (must be divisible by 32) from "ct" to "pt".

void rij256_dec(void *pt, const void *ct,
                size_t sz, const uint32_t rk[15 * 8])
{
    const uint8_t rij256_shufd[32] = {
        0,  1,  30, 31, 4,  5,  2,  19, 8,  9,  22, 23, 12, 29, 26, 27,
        16, 17, 14, 15, 20, 21, 18, 3,  24, 25, 6,  7,  28, 13, 10, 11 };

    //  size_t vl = __riscv_vsetvlmax_e32m1();
    const size_t vl = 8;        //  currently just vlen=256
    size_t n = sz / 4;
    const uint32_t *ct32 = ct;  //  input blocks
    uint32_t *pt32 = pt;        //  output blocks

    const vuint8m1_t  sd8   =__riscv_vle8_v_u8m1(rij256_shufd, 32);

    vuint32m1_t blk, k0, k1, k2, k3, k4, k5, k6, k7,
                k8, k9, k10, k11, k12, k13, k14;

    k0  = __riscv_vle32_v_u32m1(&rk[  0], 8);           //  load round keys
    k1  = __riscv_vle32_v_u32m1(&rk[  8], 8);
    k2  = __riscv_vle32_v_u32m1(&rk[ 16], 8);
    k3  = __riscv_vle32_v_u32m1(&rk[ 24], 8);
    k4  = __riscv_vle32_v_u32m1(&rk[ 32], 8);
    k5  = __riscv_vle32_v_u32m1(&rk[ 40], 8);
    k6  = __riscv_vle32_v_u32m1(&rk[ 48], 8);
    k7  = __riscv_vle32_v_u32m1(&rk[ 56], 8);
    k8  = __riscv_vle32_v_u32m1(&rk[ 64], 8);
    k9  = __riscv_vle32_v_u32m1(&rk[ 72], 8);
    k10 = __riscv_vle32_v_u32m1(&rk[ 80], 8);
    k11 = __riscv_vle32_v_u32m1(&rk[ 88], 8);
    k12 = __riscv_vle32_v_u32m1(&rk[ 96], 8);
    k13 = __riscv_vle32_v_u32m1(&rk[104], 8);
    k14 = __riscv_vle32_v_u32m1(&rk[112], 8);

    while (n > 0) {
        n -= vl;

        blk = __riscv_vle32_v_u32m1(ct32, vl);          //  load ciphertext
        ct32 += vl;

        blk = __riscv_vxor_vv_u32m1(blk, k14, vl);      //  initial round
        blk = rij256_shuf8(blk, sd8, vl);
        blk = __riscv_vaesdm_vv_u32m1(blk, k13, vl);    //  middle rounds
        blk = rij256_shuf8(blk, sd8, vl);
        blk = __riscv_vaesdm_vv_u32m1(blk, k12, vl);
        blk = rij256_shuf8(blk, sd8, vl);
        blk = __riscv_vaesdm_vv_u32m1(blk, k11, vl);
        blk = rij256_shuf8(blk, sd8, vl);
        blk = __riscv_vaesdm_vv_u32m1(blk, k10, vl);
        blk = rij256_shuf8(blk, sd8, vl);
        blk = __riscv_vaesdm_vv_u32m1(blk, k9, vl);
        blk = rij256_shuf8(blk, sd8, vl);
        blk = __riscv_vaesdm_vv_u32m1(blk, k8, vl);
        blk = rij256_shuf8(blk, sd8, vl);
        blk = __riscv_vaesdm_vv_u32m1(blk, k7, vl);
        blk = rij256_shuf8(blk, sd8, vl);
        blk = __riscv_vaesdm_vv_u32m1(blk, k6, vl);
        blk = rij256_shuf8(blk, sd8, vl);
        blk = __riscv_vaesdm_vv_u32m1(blk, k5, vl);
        blk = rij256_shuf8(blk, sd8, vl);
        blk = __riscv_vaesdm_vv_u32m1(blk, k4, vl);
        blk = rij256_shuf8(blk, sd8, vl);
        blk = __riscv_vaesdm_vv_u32m1(blk, k3, vl);
        blk = rij256_shuf8(blk, sd8, vl);
        blk = __riscv_vaesdm_vv_u32m1(blk, k2, vl);
        blk = rij256_shuf8(blk, sd8, vl);
        blk = __riscv_vaesdm_vv_u32m1(blk, k1, vl);
        blk = rij256_shuf8(blk, sd8, vl);
        blk = __riscv_vaesdf_vv_u32m1(blk, k0, vl);     //  final round

        __riscv_vse32_v_u32m1(pt32, blk, vl);           //  store plaintext
        pt32 += vl;
    }
}

#endif
