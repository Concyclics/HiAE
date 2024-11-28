#ifndef __HiAE__ALGO__
#define __HiAE__ALGO__

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Configuration constants */
#define UNROLL_BLOCK_SIZE 256 // Number of states multiplied by block size
#define BLOCK_SIZE 16         // 128 bits = 16 bytes
#define UNROLL_ROUND 16       // Number of states
#define STATE 16              // Number of states

/* Permutation parameters */
#define P_0 0 
#define P_1 1
#define P_4 13
#define P_7 9
#define i_1 3
#define i_2 13

/* For x86-64 with AES-NI */
#if defined(__AES__) && defined(__x86_64__)
#include <immintrin.h>
#include <wmmintrin.h>

typedef __m128i DATA128b;

// Macros for AES operations
#define load(x) _mm_loadu_si128((const __m128i *)(x))
#define store(x, y) _mm_storeu_si128((__m128i *)(x), y)
#define xor(x, y) _mm_xor_si128(x, y)
#define zero128() _mm_setzero_si128()
#define aesemc(x, y) _mm_aesenc_si128(xor(x, y), zero128())
#define aesdimc(x, y) _mm_aesdeclast_si128(xor(x, y), zero128())
#define aes(x) _mm_aesenc_si128(x, zero128())
#define aesenc(x, y) _mm_aesenc_si128(x, y)
#define X_A_X(a, b, c) aesenc(xor(a, b), c)

/*
 * For ARMv8/v9 with NEON + crypto.
 * Compile with GCC:
 * gcc -Ofast -march=native HiAE.c HiAE_test.c -o HiAE
 */
#elif defined(__ARM_FEATURE_CRYPTO) && defined(__ARM_NEON)
#include <arm_neon.h>

typedef uint8x16_t DATA128b;

// Macros for AES operations
#define load(x) vld1q_u8(x)
#define store(dst, x) vst1q_u8(dst, x)
#define xor(a, b) veorq_u8(a, b)
#define zero128() vmovq_n_u8(0)
#define aesemc(x, y) vaesmcq_u8(vaeseq_u8(x, y))
#define aesdimc(x, y) vaesdq_u8(x, y)
#define aes(x) aesemc(x, zero128())
#define aesenc(x, y) xor(aesemc(x, zero128()), y)
#define X_A_X(a, b, c) xor(aesemc(a, b), c)

#else

#error "This architecture is not supported yet!"

#endif

/**
 * Initialize the state for HiAE.
 *
 * INPUT:
 * @param key 256 bits (32 bytes)
 * @param iv 128 bits (16 bytes)
 * OUTPUT:
 * @param state 2048 bits (16 * 128 bits)
 */
void HiAE_stream_init(DATA128b* state, 
    const uint8_t* key,
    const uint8_t* iv
);

/**
 * Process associated data for HiAE.
 *
 * INPUT:
 * @param state 2048 bits (16 * 128 bits)
 * @param ad Associated data byte array
 * @param len Length of the associated data in bytes
 */
void HiAE_stream_proc_ad(DATA128b* state, 
    const uint8_t* ad, 
    size_t len
);

/**
 * Finalize and compute the tag for HiAE.
 *
 * INPUT:
 * @param state 2048 bits (16 * 128 bits)
 * @param ad_len Length of associated data in bytes
 * @param plain_len Length of the plaintext in bytes
 * OUTPUT:
 * @param tag Authentication tag (128 bits, 16 bytes)
 */
void HiAE_stream_finalize(DATA128b* state,
    uint64_t ad_len, 
    uint64_t plain_len,
    uint8_t* tag
);

/**
 * Perform encryption for HiAE.
 *
 * INPUT:
 * @param state 2048 bits (16 * 128 bits)
 * @param src Plaintext byte array
 * @param size Length of the plaintext in bytes
 * OUTPUT:
 * @param dst Ciphertext byte array
 */
void HiAE_stream_encrypt(DATA128b* state,
    uint8_t* dst, 
    const uint8_t* src,
    size_t size
);

/**
 * Perform decryption for HiAE.
 *
 * INPUT:
 * @param state 2048 bits (16 * 128 bits)
 * @param src Ciphertext byte array
 * @param size Length of the ciphertext in bytes
 * OUTPUT:
 * @param dst Plaintext byte array
 */
void HiAE_stream_decrypt(DATA128b* state,
    uint8_t* dst, 
    const uint8_t* src,
    size_t size
);

/**
 * Unified function for HiAE stream processing.
 *
 * INPUT:
 * @param key Encryption key (256 bits, 32 bytes)
 * @param iv Initialization vector (128 bits, 16 bytes)
 * @param plain Plaintext input
 * @param cipher Output buffer for ciphertext
 * @param ad Associated data for authentication
 * @param tag Output buffer for the authentication tag
 */
void HiAE(uint8_t* key, 
    uint8_t* iv, 
    uint8_t* plain, 
    uint8_t* cipher, 
    uint8_t* ad, 
    uint8_t* tag);

#endif
