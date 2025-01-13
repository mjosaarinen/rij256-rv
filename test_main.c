//  test_main.c
//  2025-01-12  Markku-Juhani O. Saarinen <mjos@iki.fi>

//  === Stub main

#include <stdio.h>
#include <stdlib.h>
#include "aes256_rv.h"
#include "rij256_rv.h"
#include "plat_local.h"

//  print data in hex

static void xhex(const void *dat, size_t dat_sz)
{
    size_t i;
    for (i = 0; i < dat_sz; i++) {
        printf("%02X", ((const uint8_t *) dat)[i]);
    }
    printf("\n");
}

//  print information about the platform

int plat_info()
{
    int fail = 0;

    const uint32_t c32 = 0x01020304;
    const uint64_t c64 = 0x0102030405060708;

    printf("%24s = %s\n", "PLAT_ARCH_STR", PLAT_ARCH_STR);
    printf("%24s = %d\n", "PLAT_XLEN", (int) PLAT_XLEN);
    printf("%24s = ", "0x01020304");
    xhex(&c32, sizeof(c32));
    printf("%24s = ", "0x0102030405060708");
    xhex(&c64, sizeof(c64));
    printf("%24s = %d\n", "sizeof(char)",           (int) sizeof(char));
    printf("%24s = %d\n", "sizeof(short)",          (int) sizeof(short));
    printf("%24s = %d\n", "sizeof(int)",            (int) sizeof(int));
    printf("%24s = %d\n", "sizeof(void *)",         (int) sizeof(void *));
    printf("%24s = %d\n", "sizeof(long)",           (int) sizeof(long));
    printf("%24s = %d\n", "sizeof(long long)",      (int) sizeof(long long));
    printf("%24s = %d\n", "sizeof(size_t)",         (int) sizeof(size_t));
    printf("%24s = %d\n", "((char) 0xFF)",          (int) ((char) 0xFF));
    printf("%24s = %d\n", "((unsigned char) 0xFF)", (int) ((unsigned char) 0xFF));

    printf("%24s = %ld\n", "vlen",      8 * rv_get_vlenb());
    printf("%24s = %lu\n", "cycle",     plat_get_cycle());
    printf("%24s = %lu\n", "instret",   plat_get_instret());

    return fail;
}

int rij_bench()
{
    uint32_t ra, rb;
    uint64_t zc, zi, cc, ci;
    size_t i, sz, rep = 100;
    volatile size_t *vp;

    uint32_t rk[15 * 8];
    uint8_t sk[32];
    uint8_t xt[1024];

    ra = 0x01234567;
    rb = 0xDEADBEEF;

    //  fill in with some data
    for (i = 0; i < sizeof(sk); i++) {
        sk[i] = ra >> 24;
        ra += rb;
        rb += ra;
    }
    for (i = 0; i < sizeof(xt); i++) {
        xt[i] = ra >> 24;
        ra += rb;
        rb += ra;
    }

    //  "volatile" here is a hack to prevent some optimizations
    vp = (volatile size_t *) sk;

    //  calibrate with a null function
    cc = plat_get_cycle();
    ci = plat_get_instret();
    for (i = 0; i < rep; i++) {
        *vp = i;
    }
    cc = plat_get_cycle() - cc;
    ci = plat_get_instret() - ci;
    printf("calibrate rep= %lu  ins= %lu  cyc= %lu\n\n", rep, cc, ci);
    zc = cc;
    zi = ci;

    //  === AES-256
    printf("=== AES-256 ===\n");

    //  bench key expansion
    cc = plat_get_cycle();
    ci = plat_get_instret();
    for (i = 0; i < rep; i++) {
        *vp = i;
        aes256_exp_key(rk, sk);
    }
    cc = plat_get_cycle() - cc;
    ci = plat_get_instret() - ci;
    printf("aes256_exp_key():  ins=%6lu  cyc=%6lu\n",
            (ci - zi) / rep , (cc - zc) / rep);

    //  encryption of 1KB
    vp = (volatile size_t *) xt;
    sz = 1024;

    cc = plat_get_cycle();
    ci = plat_get_instret();
    for (i = 0; i < rep; i++) {
        *vp = i;
        aes256_enc(xt, xt, sz, rk);
    }
    cc = plat_get_cycle() - cc;
    ci = plat_get_instret() - ci;
    printf("aes256_enc(%zu):  ins=%6lu  cyc=%6lu\n",
            sz, (ci - zi) / rep , (cc - zc) / rep);

    //  decryption
    cc = plat_get_cycle();
    ci = plat_get_instret();
    for (i = 0; i < rep; i++) {
        *vp = i;
        aes256_dec(xt, xt, sz, rk);
    }
    cc = plat_get_cycle() - cc;
    ci = plat_get_instret() - ci;
    printf("aes256_dec(%zu):  ins=%6lu  cyc=%6lu\n",
            sz, (ci - zi) / rep , (cc - zc) / rep);


    //  === Rijndael-256
    printf("\n=== Rijndael-(256,256) ===\n");

    //  bench key expansion
    cc = plat_get_cycle();
    ci = plat_get_instret();
    for (i = 0; i < rep; i++) {
        *vp = i;
        rij256_exp_key(rk, sk);
    }
    cc = plat_get_cycle() - cc;
    ci = plat_get_instret() - ci;
    printf("rij256_exp_key():  ins=%6lu  cyc=%6lu\n",
            (ci - zi) / rep , (cc - zc) / rep);

    //  encryption of 1KB
    vp = (volatile size_t *) xt;
    sz = 1024;

    cc = plat_get_cycle();
    ci = plat_get_instret();
    for (i = 0; i < rep; i++) {
        *vp = i;
        rij256_enc(xt, xt, sz, rk);
    }
    cc = plat_get_cycle() - cc;
    ci = plat_get_instret() - ci;
    printf("rij256_enc(%zu):  ins=%6lu  cyc=%6lu\n",
            sz, (ci - zi) / rep , (cc - zc) / rep);

    //  decryption
    cc = plat_get_cycle();
    ci = plat_get_instret();
    for (i = 0; i < rep; i++) {
        *vp = i;
        rij256_dec(xt, xt, sz, rk);
    }
    cc = plat_get_cycle() - cc;
    ci = plat_get_instret() - ci;
    printf("rij256_dec(%zu):  ins=%6lu  cyc=%6lu\n",
            sz, (ci - zi) / rep , (cc - zc) / rep);

    return 0;
}

int main()
{
    int test, fail = 0;

    //  fail += plat_info();

    printf("\n=== Self-Test ===\n");

    test = aes256_test();
    printf("aes256_test()= %d\n", test);
    fail += test;

    test = rij256_test();
    printf("rij256_test()= %d\n", test);
    fail += test;

    fail += rij_bench();
    printf("\nFailed tests= %d\n", fail);

    return 0;;
}
