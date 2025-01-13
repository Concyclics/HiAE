
#ifndef __HiAE__ALGO__
#define __HiAE__ALGO__

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Modify this part before run
 */

#define UNROLL_BLOCK_SIZE 256 // NUM of STATES * BLOCK_SIZE
#define BLOCK_SIZE 16 // 128bits = 16 Bytes
#define UNROLL_ROUND 16 // = NUM of STATES
#define STATE 16 // NUM of STATES

#if defined(__AES__) && defined(__x86_64__)
#include <immintrin.h>
#include <wmmintrin.h>
typedef __m128i DATA128b;
/*
 * For Kunpeng 920
 * Compile with GCC command
 * gcc -Ofast -march=armv8.2-a+crypto HiAE.c HiAE_test.c -o HiAE
 */
#elif defined(__ARM_FEATURE_CRYPTO) && defined(__ARM_NEON)
#include <arm_neon.h>
typedef uint8x16_t DATA128b;
#else
#error This_Arch_do_not_Supported_yet_!!!
#endif

/**
 * state initial for HiAE
 *
 * INPUT:
 * @param key 256bit: 32 byte
 * @param iv 128bit: 16 byte
 * OUTPUT:
 * @param state 256 byte
 */
void HiAE_stream_init(DATA128b* state, 
    const uint8_t* key,
    const uint8_t* iv
);
/**
 * process ad for HiAE
 *
 * INPUT:
 * @param state 256 byte
 * @param len length of ad (byte)
 * OUTPUT:
 * @param ad a byte array for ad
 */
void HiAE_stream_proc_ad(DATA128b* state, 
    const uint8_t* ad, 
    size_t len
);
/**
 * finalize to get tag for HiAE
 *
 * INPUT:
 * @param state 256 byte
 * @param ad_len length of ad (byte)
 * @param plain_len length of message(byte)
 * OUTPUT:
 * @param tag 128bit: 16 byte
 */
void HiAE_stream_finalize(DATA128b* state,
    uint64_t ad_len, 
    uint64_t plain_len,
    uint8_t* tag
);
/**
 * encryption for HiAE
 *
 * INPUT:
 * @param state 256 byte
 * @param size length of message(byte)
 * @param src a byte array for message
 * OUTPUT:
 * @param dst a byte array for cipher
 */
void HiAE_stream_encrypt(DATA128b* state,
    uint8_t* dst, 
    const uint8_t* src,
    size_t size
);
/**
 * decryption for HiAE
 *
 * INPUT:
 * @param state 256 byte
 * @param size length of message(byte)
 * @param src a byte array for cipher text
 * OUTPUT:
 * @param dst a byte array for message
 */
void HiAE_stream_decrypt(DATA128b* state,
    uint8_t* dst, 
    const uint8_t* src,
    size_t size
);

/**
 * encryption for HiAE AEAD mode
 *
 * INPUT:
 * @param key 256bit: 32 byte
 * @param iv 128bit: 16 byte
 * @param plain message array
 * @param ad associate data
 * @param msg_len length in byte of message
 * @param ad_len length of associate data
 * OUTPUT:
 * @param cipher a byte array for cipher text
* @param tag 128-bit tag for verification
 */
void HiAE_AEAD_encrypt(uint8_t* key, 
    uint8_t* iv, 
    uint8_t* plain, 
    uint8_t* cipher, 
    size_t msg_len,
    uint8_t* ad, 
    size_t ad_len,
    uint8_t* tag);

/**
 * decryption for HiAE AEAD mode
 *
 * INPUT:
 * @param key 256bit: 32 byte
 * @param iv 128bit: 16 byte
 * @param cipher message array
 * @param ad associate data
 * @param msg_len length in byte of message
 * @param ad_len length of associate data
 * OUTPUT:
 * @param plain a byte array for cipher text
* @param tag 128-bit tag for verification
 */
void HiAE_AEAD_decrypt(uint8_t* key, 
    uint8_t* iv, 
    uint8_t* plain, 
    uint8_t* cipher, 
    size_t msg_len,
    uint8_t* ad, 
    size_t ad_len,
    uint8_t* tag);

#endif
