#   rij256-rv

2025-01-13  Markku-Juhani Saarinen -- markku-juhani.saarinen@tuni.fi


##  Background

On December 23, 2024, the U.S. [NIST Proposed to standardize a wider variant of AES](https://csrc.nist.gov/news/2024/nist-proposes-to-standardize-wider-variant-of-aes),
more specifically Rijndael with 256-bit block size and a single key size of
256bits. We will be calling this variant Rijndael-256 or "rij256" in short.

NIST asked for comments about performance and efficiency,
_"particularly in environments with hardware support for AES."_
This repository contains work to answer that question on behalf
of RISC-V International.


##  Rijndael-256

The [original Rijandael proposal for AES](https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf)
from the late 1990s allowed the block length and the key length to be
independently specified to 128, 192, or 256 bits.

However, the [FIPS 197, the Advanced Encryption Standard](https://doi.org/10.6028/NIST.FIPS.197-upd1) limited the block size to 128-bits in 2001, and the larger-block variants have been largely ignored by the research and engineering community for over 20 years.

A reference implementation of Rijndael supporting all key and block sizes,
and some test vectors are available in the appendices of the book
["The Design of Rijndael "](https://doi.org/10.1007/978-3-662-60769-5) from
its designers, Joan Daemen and Vincent Rijmen. I have extracted the
reference implementation as [ref/rijndael.c](ref/rijndael.c) and the test
vectors (produced by that implementation, and also contained in the book)
as [ref/testvec.txt](ref/testvec.txt). The code isn't modern C and
not for production use, but it still compiles, and the 128-bit block size
computations by that code agree with AES (note, however, that matrices are
organized column-first rather than row-first.). Perhaps the self-test code
in [rij256_test.c](rij256_test.c) will be independently helpful to others.

**In short:**

*   The key schedule of Rijndael-(256,256) is the same as AES-256, except
that one needs to double the amount. The first half of the
(14+1)*32 = 480-byte Rijndael-(256,256) key schedule for a given key is the
same as AES-256 subkeys generated for the same 256-bit key.
To generate the second half, one needs to increase the loop length
(and make more round constants available.)

*   Rijndael-(256,256) has 14 rounds (same as AES-256). The state is
organized as 8 "columns" of 4 bytes. The ShiftRows() constants are {0,1,3,4}.
Other component steps -- SubBytes(), MixColumns(), AddRoundKey() --
are just as in other variants of Rijndael. There are 32 parallel S-boxes,
8 MixColumns() calls and the subkeys are 32 bytes as well.

```
Rijndael-(256,256) state is loaded with 32 bytes 0, 1, 2, .. 31:

    (  0  4  8 12 16 20 24 28 )
    (  1  5  9 13 17 21 25 29 )
    (  2  6 10 14 18 22 26 30 )
    (  3  7 11 15 19 23 27 31 )

After Rijndael-(256,256) ShiftRows step (left) by {0,1,3,4}:

    (  0  4  8 12 16 20 24 28 )
    (  5  9 13 17 21 25 29  1 )
    ( 14 18 22 26 30  2  6 10 )
    ( 19 23 27 31  3  7 11 15 )
```

##  Implementation with with RISC-V "Zvkned" Extension

Like most other modern ISAs, RISC-V has SIMD/Vector support for AES
computations; these are part of the standard NIST Suite AES Vector (Zvkned)
extensions. You can find details in the
[RISC-V Unprivileged ISA manual](https://github.com/riscv/riscv-isa-manual).

A Rijndael-256 implementation with
[RISC-V Vector intrinsics](https://dzaima.github.io/intrinsics-viewer/)
is contained in file [rij256_intrin.c](rij256_intrin.c).
The assembler counterpart is in [rij256_rv_asm.S](rij256_rv_asm.S).
The Rijndael code assumes VLEN >= 256. The repository also contains AES-256
code for comparison reasons, structured the same way.


### Running the implementation

To test these implementations, you will need either RISC-V hardware with
AES support (not many options for that at the moment), or the
[spike ISA Simulator](https://github.com/riscv-software-src/riscv-isa-sim),
and, of course, a compiler toolchain that supports this target. I have tested
the code with GCC 14.2.0 and CLANG 20 (dev), but a few earlier versions should
be ok as well.

Take a look at the [Makefile](Makefile) if you need to configure something.
By default, it is set up to create a binary `xtest` for a VLEN=256 target
and execute it with Spike.

A successful run looks like this:
```
$ make
(..)
riscv64-unknown-linux-gnu-gcc -Wall  -march=rv64gcv_zvkned_zvl256b -c rij256_rv_asm.S -o rij256_rv_asm.o
riscv64-unknown-linux-gnu-gcc -static -march=rv64gcv_zvkned_zvl256b -o xtest aes256_intrin.o aes256_test.o rij256_intrin.o rij256_test.o test_main.o aes256_rv_asm.o rij256_rv_asm.o
spike --isa=rv64gcv_zvkned_zvl256b_zicntr_zihpm  pk xtest

=== Self-Test ===
aes256_test()= 0
rij256_test()= 0
calibrate rep= 100  ins= 304  cyc= 304

=== AES-256 ===
aes256_exp_key():  ins=    58  cyc=    58
aes256_enc(1024):  ins=   775  cyc=   775
aes256_dec(1024):  ins=   775  cyc=   775

=== Rijndael-(256,256) ===
rij256_exp_key():  ins=   123  cyc=   123
rij256_enc(1024):  ins=  2059  cyc=  2059
rij256_dec(1024):  ins=  2059  cyc=  2059

Failed tests= 0
```
The encryption and decryption cycle counts are given for 1024 bytes of
plaintext / ciphertext.

Due to the simulator platform, the instruction count (ins) and cycle count
(cyc) are equivalent in this example. This is very rarely the case on actual
RISC-V silicon; on "superscalar" loads, the instruction count can be larger
than the cycle count, but with a vector load such as Rijndael-256, the cycle
count is substantially larger. Especially the latency of `vrgather` may
vary widely depending on the hardware architecture.


### Discussion: Key Expansion

As noted, the first 7 of Rijndael-256's round keys have the same bytes
as the first 14 round keys of AES-256 with the same 256-bit secret keys.

Slight hitch is that `aeskf2.vi` AES-256 key schedule instruction also
includes the round constant addition and performs a table lookup
from an index provided as an immediate value.

We add XOR into the key schedule process to undo
the "built-in" round constant and insert a new one from the table
( see function `rij256_exp_key()` in [rij256_intrin.c](rij256_intrin.c) ).

Key schedule is not a time-sensitive operation, and even with this
additional step, the operation is still very fast. Note that
(unlike some other ISAs), there is no need to modify the expanded
key schedule for decryption.


### Byte Shuffle

As observed on Intel ISA by N. Drucker and S. Gueron in their paper
["Software Optimization of Rijndael256 for Modern x86-64 Platforms"](https://doi.org/10.1007/978-3-030-97652-1_18),
one can implement Rijndael-256 with AES round
instructions by adding an appropriate 256-bit "byte shuffle" into each round.
The 32-bit S-Boxes and other components of Rijndael-256 are implemented by
having two 128-bit AES instructions in parallel; the permutation (in one step)
essentially undoes ShiftRows of AES-256 and then does the ShiftRows operation
of Rijndael-256.

However, the details are quite different as the operation of the instructions
is not the same.

On RVV, one can use `vrgather.vv` to perform a byte shuffle with a byte
index. The magical byte shuffle for encryption is:
```
    {   0,  17, 22, 23, 4,  5,  26, 27, 8,  9,  14, 31, 12, 13, 18, 19,
        16, 1,  6,  7,  20, 21, 10, 11, 24, 25, 30, 15, 28, 29, 2,  3  };
```
For decryption, we have:
```
    {   0,  1,  30, 31, 4,  5,  2,  19, 8,  9,  22, 23, 12, 29, 26, 27,
        16, 17, 14, 15, 20, 21, 18, 3,  24, 25, 6,  7,  28, 13, 10, 11  };

```

The element width of the byte shuffle (8) differs from the element
width (32) of AES. There may be some trick around this, but currently,
the code includes `vsetvli` instructions around the `vrgather` to change
the element width.

```
    vsetvli     zero, a4, e8, m1, ta, ma
    vrgather.vv v25, v24, v8
    vsetivli    zero, 8, e32, m1, ta, ma
    vaesem.vv   v25, v10
```


