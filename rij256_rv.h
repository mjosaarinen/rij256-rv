//  rij256_rv.h
//  2025-01-12  Markku-Juhani O. Saarinen <mjos@iki.fi>

//  === Header for RISC-V Rijndael-(256,256) implementations

#ifndef _RIJ256_RV_H_
#define _RIJ256_RV_H_

#include <stdint.h>
#include <stddef.h>

//  Expand 256-bit key "sk" into 15*32 - byte subkeys in "rk".
void rij256_exp_key(uint32_t rk[15 * 8], const uint8_t sk[32]);

//  Encrypt (ECB) "sz" bytes (must be divisible by 32) from "pt" to "ct".
void rij256_enc(void *ct, const void *pt,
                size_t sz, const uint32_t rk[15 * 8]);

//  Decrypt (ECB) "sz" bytes (must be divisible by 32) from "ct" to "pt".
void rij256_dec(void *pt, const void *ct,
                size_t sz, const uint32_t rk[15 * 8]);

//  rij256_test.c -- Fast self-test; return 0 if all tests pass.
int rij256_test();

#endif
