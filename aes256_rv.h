//  aes256_rv.h
//  2025-01-12  Markku-Juhani O. Saarinen <mjos@iki.fi>

//  === Header for RISC-V AES-256 implementations

#ifndef _AES256_RV_H_
#define _AES256_RV_H_

#include <stdint.h>
#include <stddef.h>

//  Expand 256-bit key "sk" into 15*16 - byte subkeys in "rk".
void aes256_exp_key(uint32_t rk[15 * 4], const uint8_t sk[32]);

//  Encrypt (ECB) "sz" bytes (must be divisible by 16) from "pt" to "ct".
void aes256_enc(void *ct, const void *pt,
                size_t sz, const uint32_t rk[15 * 4]);

//  Decrypt (ECB) "sz" bytes (must be divisible by 16) from "ct" to "pt".
void aes256_dec(void *pt, const void *ct,
                size_t sz, const uint32_t rk[15 * 4]);

//  aes256_test.c -- Fast self-test; return 0 if all tests pass.
int aes256_test();

#endif

