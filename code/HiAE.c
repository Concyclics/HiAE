#include "HiAE.h"

static const uint8_t CONST0[16] = {
    0x42, 0x8a, 0x2f, 0x98, 0xd7, 0x28, 0xae, 0x22, 0x71, 0x37, 0x44, 0x91, 0x23, 0xef, 0x65, 0xcd
};
static const uint8_t CONST1[16] = {
     0xb5, 0xc0, 0xfb, 0xcf, 0xec, 0x4d, 0x3b, 0x2f, 0xe9, 0xb5, 0xdb, 0xa5, 0x81, 0x89, 0xdb, 0xbc
};

static const uint8_t zo[16] = {
    0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00
};

/*
 * Avoid cost of extra XOR operation cross platform
 */
#if defined(__AES__) && defined(__x86_64__)

#define UPDATE_STATE_offset(M, offset)\
    tmp[offset] = xor(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);\
    tmp[offset] = aesenc(tmp[offset], M);\
    state[(0 + offset) % STATE] = aesenc(state[(P_4 + offset) % STATE], tmp[offset]);\
    state[(i_1 + offset) % STATE] = xor(state[(i_1 + offset) % STATE], M);\
    state[(i_2 + offset) % STATE] = xor(state[(i_2 + offset) % STATE], M);

#define ENC_offset(M, C, offset)\
    C = xor(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);\
    C = aesenc(C, M);\
    state[(0 + offset) % STATE] = aesenc(state[(P_4 + offset) % STATE], C);\
    C = xor(C, state[(P_7 + offset) % STATE]);\
    state[(i_1 + offset) % STATE] = xor(state[(i_1 + offset) % STATE], M);\
    state[(i_2 + offset) % STATE] = xor(state[(i_2 + offset) % STATE], M);

#define DEC_offset(M, C, offset)\
    tmp[offset] = xor(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);\
    M = xor(state[(P_7 + offset) % STATE], C);\
    state[(0 + offset) % STATE] = aesenc(state[(P_4 + offset) % STATE], M);\
    M = aesenc(tmp[offset], M);\
    state[(i_1 + offset) % STATE] = xor(state[(i_1 + offset) % STATE], M);\
    state[(i_2 + offset) % STATE] = xor(state[(i_2 + offset) % STATE], M);


#elif defined(__ARM_FEATURE_CRYPTO) && defined(__ARM_NEON)

#define UPDATE_STATE_offset(M, offset)\
    tmp[offset] = aesemc(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);\
    tmp[offset] = xor(tmp[offset], M); \
    state[(0 + offset) % STATE] = xor(tmp[offset], aes(state[(P_4 + offset) % STATE]));\
    state[(i_1 + offset) % STATE] = xor(state[(i_1 + offset) % STATE], M);\
    state[(i_2 + offset) % STATE] = xor(state[(i_2 + offset) % STATE], M);

#define ENC_offset(M, C, offset)\
    tmp[offset] = aesemc(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);\
    C = xor(tmp[offset], M); \
    state[(0 + offset) % STATE] = xor(C, aes(state[(P_4 + offset) % STATE]));\
    C = xor(C, state[(P_7 + offset) % STATE]); \
    state[(i_1 + offset) % STATE] = xor(state[(i_1 + offset) % STATE], M);\
    state[(i_2 + offset) % STATE] = xor(state[(i_2 + offset) % STATE], M);

#define DEC_offset(M, C, offset)\
    tmp[offset] = aesemc(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);\
    M = xor(state[(P_7 + offset) % STATE], C);\
    state[(0 + offset) % STATE] = xor(M, aes(state[(P_4 + offset) % STATE]));\
    M = xor(M, tmp[offset]);\
    state[(i_1 + offset) % STATE] = xor(state[(i_1 + offset) % STATE], M);\
    state[(i_2 + offset) % STATE] = xor(state[(i_2 + offset) % STATE], M);

#else

#error This_Arch_do_not_Supported_yet_!!!

#endif

/*
 * load 4 128bit block from src
 */
#define LOAD_1BLOCK_offset(M, offset) \
    (M) = load(src + i + 0 + BLOCK_SIZE * offset); \
/*
 * store 4 128bit block to dst
 */
#define STORE_1BLOCK_offset(C, offset) \
    store(dst + i + 0 + BLOCK_SIZE * offset, (C)); \

#define encode_little_endian(bytes, v) \
    bytes[ 0] = (( uint64_t )( v ) << ( 3)); \
    bytes[ 1] = (( uint64_t )( v ) >> (1*8 -3)); \
    bytes[ 2] = (( uint64_t )( v ) >> (2*8 -3)); \
    bytes[ 3] = (( uint64_t )( v ) >> (3*8 -3)); \
    bytes[ 4] = (( uint64_t )( v ) >> (4*8 -3)); \
    bytes[ 5] = (( uint64_t )( v ) >> (5*8 -3)); \
    bytes[ 6] = (( uint64_t )( v ) >> (6*8 -3)); \
    bytes[ 7] = (( uint64_t )( v ) >> (7*8 -3)); \
    bytes[ 8] = (( uint64_t )( v ) >> (8*8 -3)); \
    bytes[ 9] = 0; \
    bytes[10] = 0; \
    bytes[11] = 0; \
    bytes[12] = 0; \
    bytes[13] = 0; \
    bytes[14] = 0; \
    bytes[15] = 0;

#define STATE_SHIFT \
tmp[0] = state[0];\
state[0] = state[1]; \
state[1] = state[2]; \
state[2] = state[3]; \
state[3] = state[4]; \
state[4] = state[5]; \
state[5] = state[6]; \
state[6] = state[7]; \
state[7] = state[8]; \
state[8] = state[9]; \
state[9] = state[10]; \
state[10] = state[11]; \
state[11] = state[12]; \
state[12] = state[13]; \
state[13] = state[14]; \
state[14] = state[15]; \
state[15] = tmp[0]

#define AD_UPDATE_1_STEP(i) \
    LOAD_1BLOCK_offset(M[i], i);\
    UPDATE_STATE_offset(M[i], i);

#define ENCRYPT_1_STEP(i) \
    LOAD_1BLOCK_offset(M[i], i);\
    ENC_offset(M[i], C[i], i);\
    STORE_1BLOCK_offset(C[i], i);

#define DECRYPT_1_STEP(i) \
    LOAD_1BLOCK_offset(C[i], i); \
    DEC_offset(M[i], C[i], i); \
    STORE_1BLOCK_offset(M[i], i);

void HiAE_stream_init(DATA128b* state, const uint8_t *key, const uint8_t *iv) {
    DATA128b c0 = load(CONST0);
    DATA128b c1 = load(CONST1);
    DATA128b k0 = load(key);
    DATA128b k1 = load(key+16);
    DATA128b N = load(iv);

    DATA128b ze = load(zo);
    state[0] = c0;
    state[1] = k1;
    state[2] = N;
    state[3] = c0;
    state[4] = ze;
    state[5] = xor(N, k0);
    state[6] = ze;
    state[7] = c1;
    state[8] = xor(N, k1);
    state[9] = ze;
    state[10] = k1;
    state[11] = c0;
    state[12] = c1;
    state[13] = k1;
    state[14] = ze;
    state[15] = xor(c0, c1);

    DATA128b temp, tmp[STATE];
    for (size_t i = 0; i < 2 * STATE; ++i) {
        UPDATE_STATE_offset(c0, i%STATE);
    }
    state[0] = xor(state[0], k0);
    state[7] = xor(state[7], k1);
}

void HiAE_stream_proc_ad(DATA128b* state, const uint8_t *ad, size_t len) {
    size_t i = 0;
    size_t rest = len % UNROLL_BLOCK_SIZE;
    size_t prefix = len - rest;
    const uint8_t *src = ad;
    DATA128b temp, tmp[STATE], M[16];
    for(; i < prefix; i += UNROLL_BLOCK_SIZE) {
        AD_UPDATE_1_STEP(0);
        AD_UPDATE_1_STEP(1);
        AD_UPDATE_1_STEP(2);
        AD_UPDATE_1_STEP(3);
        AD_UPDATE_1_STEP(4);
        AD_UPDATE_1_STEP(5);
        AD_UPDATE_1_STEP(6);
        AD_UPDATE_1_STEP(7);
        AD_UPDATE_1_STEP(8);
        AD_UPDATE_1_STEP(9);
        AD_UPDATE_1_STEP(10);
        AD_UPDATE_1_STEP(11);
        AD_UPDATE_1_STEP(12);
        AD_UPDATE_1_STEP(13);
        AD_UPDATE_1_STEP(14);
        AD_UPDATE_1_STEP(15);
    }
    for(; i < len; i += BLOCK_SIZE) {
        M[0] = load(ad + i);
        UPDATE_STATE_offset(M[0], 0);
        STATE_SHIFT;
    }
}
    
void HiAE_stream_finalize(DATA128b* state, uint64_t ad_len, uint64_t plain_len, uint8_t *tag) {
    uint64_t lens[2];
    lens[0] = ad_len;
    lens[1] = plain_len;
    DATA128b temp, tmp[STATE];
    temp = load(lens);
    for (size_t i = 0; i < STATE; ++i) {
        UPDATE_STATE_offset(temp, i);
    }
    temp = state[0];
    for (size_t i = 1; i < STATE; ++i) {
        temp = xor(temp, state[i]);
    }
    store(tag, temp);
}

void HiAE_stream_encrypt(DATA128b* state, uint8_t *dst, const uint8_t *src, size_t size) {
    size_t rest = size % UNROLL_BLOCK_SIZE;
    size_t prefix = size - rest;
    DATA128b M[STATE], C[STATE], tmp[STATE], temp;
    #if defined(__VAES__) && defined(__x86_64__)
    // asm code optimized for VAES support devices
    
    // xmm0-xmm15 are used for State
    // xmm16-xmm23 are used for M
    // xmm24-xmm31 are used for C

    __asm__ volatile (
        // Load state into xmm0-xmm15
        "vmovdqa64 (%3), %%xmm0;"    // state[0]
        "vmovdqa64 16(%3), %%xmm1;"  // state[1]
        "vmovdqa64 32(%3), %%xmm2;"  // state[2]
        "vmovdqa64 48(%3), %%xmm3;"  // state[3]
        "vmovdqa64 64(%3), %%xmm4;"  // state[4]
        "vmovdqa64 80(%3), %%xmm5;"  // state[5]
        "vmovdqa64 96(%3), %%xmm6;"  // state[6]
        "vmovdqa64 112(%3), %%xmm7;" // state[7]
        "vmovdqa64 128(%3), %%xmm8;" // state[8]
        "vmovdqa64 144(%3), %%xmm9;" // state[9]
        "vmovdqa64 160(%3), %%xmm10;"// state[10]
        "vmovdqa64 176(%3), %%xmm11;"// state[11]
        "vmovdqa64 192(%3), %%xmm12;"// state[12]
        "vmovdqa64 208(%3), %%xmm13;"// state[13]
        "vmovdqa64 224(%3), %%xmm14;"// state[14]
        "vmovdqa64 240(%3), %%xmm15;"// state[15]

        "movq $0, %%rax;"          // Initialize counter i = 0
        "1:;"                      // Loop start
        "cmpq %2, %%rax;"          // Compare i and prefix
        "jge 2f;"                  // If i >= prefix, jump to loop end

        // round 1
        "vmovdqu64 0(%1, %%rax), %%xmm16;"    // Load M[0] into xmm16
        "vpxorq %%xmm0, %%xmm1, %%xmm24;"      // C[0] = xor(S[0], S[1])
        "vaesenc %%xmm16, %%xmm24, %%xmm24;"  // C[0] = aesenc(C[0], M[0])
        "vaesenc %%xmm24, %%xmm13, %%xmm0;"   // S[16] = aesenc(S[13], C[0])
        "vpxorq %%xmm24, %%xmm9, %%xmm24;"     // C[0] = xor(C[0], S[9])
        "vpxorq %%xmm3, %%xmm16, %%xmm3;"      // S[3] = xor(S[3], M[0])
        "vpxorq %%xmm13, %%xmm16, %%xmm13;"    // S[13] = xor(S[13], M[0])
        "vmovdqu64 %%xmm24, 0(%0, %%rax);"    // Write back C[0] to dst[i:i+16]

        // round 2
        "vmovdqu64 16(%1, %%rax), %%xmm17;"   // Load M[1] into xmm17
        "vpxorq %%xmm1, %%xmm2, %%xmm25;"      // C[1] = xor(S[1], S[2])
        "vaesenc %%xmm17, %%xmm25, %%xmm25;"  // C[1] = aesenc(C[1], M[1])
        "vaesenc %%xmm25, %%xmm14, %%xmm1;"   // S[17] = aesenc(S[14], C[1])
        "vpxorq %%xmm25, %%xmm10, %%xmm25;"    // C[1] = xor(C[1], S[10])
        "vpxorq %%xmm4, %%xmm17, %%xmm4;"      // S[4] = xor(S[4], M[1])
        "vpxorq %%xmm14, %%xmm17, %%xmm14;"    // S[14] = xor(S[14], M[1])
        "vmovdqu64 %%xmm25, 16(%0, %%rax);"   // Write back C[1] to dst[i+16:i+32]

        // round 3
        "vmovdqu64 32(%1, %%rax), %%xmm18;"   // Load M[2] into xmm18
        "vpxorq %%xmm2, %%xmm3, %%xmm26;"      // C[2] = xor(S[2], S[3])
        "vaesenc %%xmm18, %%xmm26, %%xmm26;"  // C[2] = aesenc(C[2], M[2])
        "vaesenc %%xmm26, %%xmm15, %%xmm2;"   // S[18] = aesenc(S[15], C[2])
        "vpxorq %%xmm26, %%xmm11, %%xmm26;"    // C[2] = xor(C[2], S[11])
        "vpxorq %%xmm5, %%xmm18, %%xmm5;"      // S[5] = xor(S[5], M[2])
        "vpxorq %%xmm15, %%xmm18, %%xmm15;"    // S[15] = xor(S[15], M[2])
        "vmovdqu64 %%xmm26, 32(%0, %%rax);"   // Write back C[2] to dst[i+32:i+48]

        // round 4
        "vmovdqu64 48(%1, %%rax), %%xmm19;"   // Load M[3] into xmm19
        "vpxorq %%xmm3, %%xmm4, %%xmm27;"      // C[3] = xor(S[3], S[4])
        "vaesenc %%xmm19, %%xmm27, %%xmm27;"  // C[3] = aesenc(C[3], M[3])
        "vaesenc %%xmm27, %%xmm0, %%xmm3;"    // S[19] = aesenc(S[0], C[3])
        "vpxorq %%xmm27, %%xmm12, %%xmm27;"    // C[3] = xor(C[3], S[12])
        "vpxorq %%xmm6, %%xmm19, %%xmm6;"      // S[6] = xor(S[6], M[3])
        "vpxorq %%xmm0, %%xmm19, %%xmm0;"      // S[0] = xor(S[0], M[3])
        "vmovdqu64 %%xmm27, 48(%0, %%rax);"   // Write back C[3] to dst[i+48:i+64]

        // round 5
        "vmovdqu64 64(%1, %%rax), %%xmm20;"   // Load M[4] into xmm20
        "vpxorq %%xmm4, %%xmm5, %%xmm28;"      // C[4] = xor(S[4], S[5])
        "vaesenc %%xmm20, %%xmm28, %%xmm28;"  // C[4] = aesenc(C[4], M[4])
        "vaesenc %%xmm28, %%xmm1, %%xmm4;"    // S[20] = aesenc(S[1], C[4])
        "vpxorq %%xmm28, %%xmm13, %%xmm28;"    // C[4] = xor(C[4], S[13])
        "vpxorq %%xmm7, %%xmm20, %%xmm7;"      // S[7] = xor(S[7], M[4])
        "vpxorq %%xmm1, %%xmm20, %%xmm1;"      // S[1] = xor(S[1], M[4])
        "vmovdqu64 %%xmm28, 64(%0, %%rax);"   // Write back C[4] to dst[i+64:i+80]

        // round 6
        "vmovdqu64 80(%1, %%rax), %%xmm21;"   // Load M[5] into xmm21
        "vpxorq %%xmm5, %%xmm6, %%xmm29;"      // C[5] = xor(S[5], S[6])
        "vaesenc %%xmm21, %%xmm29, %%xmm29;"  // C[5] = aesenc(C[5], M[5])
        "vaesenc %%xmm29, %%xmm2, %%xmm5;"    // S[21] = aesenc(S[2], C[5])
        "vpxorq %%xmm29, %%xmm14, %%xmm29;"    // C[5] = xor(C[5], S[14])
        "vpxorq %%xmm8, %%xmm21, %%xmm8;"      // S[8] = xor(S[8], M[5])
        "vpxorq %%xmm2, %%xmm21, %%xmm2;"      // S[2] = xor(S[2], M[5])
        "vmovdqu64 %%xmm29, 80(%0, %%rax);"   // Write back C[5] to dst[i+80:i+96]

        // round 7
        "vmovdqu64 96(%1, %%rax), %%xmm22;"   // Load M[6] into xmm22
        "vpxorq %%xmm6, %%xmm7, %%xmm30;"      // C[6] = xor(S[6], S[7])
        "vaesenc %%xmm22, %%xmm30, %%xmm30;"  // C[6] = aesenc(C[6], M[6])
        "vaesenc %%xmm30, %%xmm3, %%xmm6;"    // S[22] = aesenc(S[3], C[6])
        "vpxorq %%xmm30, %%xmm15, %%xmm30;"    // C[6] = xor(C[6], S[15])
        "vpxorq %%xmm9, %%xmm22, %%xmm9;"      // S[9] = xor(S[9], M[6])
        "vpxorq %%xmm3, %%xmm22, %%xmm3;"      // S[3] = xor(S[3], M[6])
        "vmovdqu64 %%xmm30, 96(%0, %%rax);"   // Write back C[6] to dst[i+96:i+112]

        // round 8
        "vmovdqu64 112(%1, %%rax), %%xmm23;"  // Load M[7] into xmm23
        "vpxorq %%xmm7, %%xmm8, %%xmm31;"      // C[7] = xor(S[7], S[8])
        "vaesenc %%xmm23, %%xmm31, %%xmm31;"  // C[7] = aesenc(C[7], M[7])
        "vaesenc %%xmm31, %%xmm4, %%xmm7;"    // S[23] = aesenc(S[4], C[7])
        "vpxorq %%xmm31, %%xmm0, %%xmm31;"     // C[7] = xor(C[7], S[0])
        "vpxorq %%xmm10, %%xmm23, %%xmm10;"    // S[10] = xor(S[10], M[7])
        "vpxorq %%xmm4, %%xmm23, %%xmm4;"      // S[4] = xor(S[4], M[7])
        "vmovdqu64 %%xmm31, 112(%0, %%rax);"  // Write back C[7] to dst[i+112:i+128]

        // round 9
        "vmovdqa64 128(%1, %%rax), %%xmm16;"    // Load M[8] into xmm16
        "vpxorq %%xmm8, %%xmm9, %%xmm24;"        // C[8] = xor(S[8], S[9])
        "vaesenc %%xmm16, %%xmm24, %%xmm24;"    // C[8] = aesenc(M[8], C[8])
        "vaesenc %%xmm24, %%xmm5, %%xmm8;"      // S[24] = aesenc(C[8], S[5])
        "vpxorq %%xmm24, %%xmm1, %%xmm24;"       // C[8] = xor(C[8], S[1])
        "vpxorq %%xmm11, %%xmm16, %%xmm11;"      // S[11] = xor(S[11], M[8])
        "vpxorq %%xmm5, %%xmm16, %%xmm5;"        // S[5] = xor(S[5], M[8])
        "vmovdqa64 %%xmm24, 128(%0, %%rax);"    // Write back C[8] to dst[i+128:i+144]

        // round 10
        "vmovdqa64 144(%1, %%rax), %%xmm17;"    // Load M[9] into xmm17
        "vpxorq %%xmm9, %%xmm10, %%xmm25;"       // C[9] = xor(S[9], S[10])
        "vaesenc %%xmm17, %%xmm25, %%xmm25;"    // C[9] = aesenc(M[9], C[9])
        "vaesenc %%xmm25, %%xmm6, %%xmm9;"      // S[25] = aesenc(C[9], S[6])
        "vpxorq %%xmm25, %%xmm2, %%xmm25;"       // C[9] = xor(C[9], S[2])
        "vpxorq %%xmm12, %%xmm17, %%xmm12;"      // S[12] = xor(S[12], M[9])
        "vpxorq %%xmm6, %%xmm17, %%xmm6;"        // S[6] = xor(S[6], M[9])
        "vmovdqa64 %%xmm25, 144(%0, %%rax);"    // Write back C[9] to dst[i+144:i+160]

        // round 11
        "vmovdqa64 160(%1, %%rax), %%xmm18;"    // Load M[10] into xmm18
        "vpxorq %%xmm10, %%xmm11, %%xmm26;"      // C[10] = xor(S[10], S[11])
        "vaesenc %%xmm18, %%xmm26, %%xmm26;"    // C[10] = aesenc(M[10], C[10])
        "vaesenc %%xmm26, %%xmm7, %%xmm10;"     // S[26] = aesenc(C[10], S[7])
        "vpxorq %%xmm26, %%xmm3, %%xmm26;"       // C[10] = xor(C[10], S[3])
        "vpxorq %%xmm13, %%xmm18, %%xmm13;"      // S[13] = xor(S[13], M[10])
        "vpxorq %%xmm7, %%xmm18, %%xmm7;"        // S[7] = xor(S[7], M[10])
        "vmovdqa64 %%xmm26, 160(%0, %%rax);"    // Write back C[10] to dst[i+160:i+176]

        // round 12
        "vmovdqa64 176(%1, %%rax), %%xmm19;"    // Load M[11] into xmm19
        "vpxorq %%xmm11, %%xmm12, %%xmm27;"      // C[11] = xor(S[11], S[12])
        "vaesenc %%xmm19, %%xmm27, %%xmm27;"    // C[11] = aesenc(M[11], C[11])
        "vaesenc %%xmm27, %%xmm8, %%xmm11;"     // S[27] = aesenc(C[11], S[8])
        "vpxorq %%xmm27, %%xmm4, %%xmm27;"       // C[11] = xor(C[11], S[4])
        "vpxorq %%xmm14, %%xmm19, %%xmm14;"      // S[14] = xor(S[14], M[11])
        "vpxorq %%xmm8, %%xmm19, %%xmm8;"        // S[8] = xor(S[8], M[11])
        "vmovdqa64 %%xmm27, 176(%0, %%rax);"    // Write back C[11] to dst[i+176:i+192]

        // round 13
        "vmovdqa64 192(%1, %%rax), %%xmm20;"    // Load M[12] into xmm20
        "vpxorq %%xmm12, %%xmm13, %%xmm28;"      // C[12] = xor(S[12], S[13])
        "vaesenc %%xmm20, %%xmm28, %%xmm28;"    // C[12] = aesenc(M[12], C[12])
        "vaesenc %%xmm28, %%xmm9, %%xmm12;"     // S[28] = aesenc(C[12], S[9])
        "vpxorq %%xmm28, %%xmm5, %%xmm28;"       // C[12] = xor(C[12], S[5])
        "vpxorq %%xmm15, %%xmm20, %%xmm15;"      // S[15] = xor(S[15], M[12])
        "vpxorq %%xmm9, %%xmm20, %%xmm9;"        // S[9] = xor(S[9], M[12])
        "vmovdqa64 %%xmm28, 192(%0, %%rax);"    // Write back C[12] to dst[i+192:i+208]

        // round 14
        "vmovdqa64 208(%1, %%rax), %%xmm21;"    // Load M[13] into xmm21
        "vpxorq %%xmm13, %%xmm14, %%xmm29;"      // C[13] = xor(S[13], S[14])
        "vaesenc %%xmm21, %%xmm29, %%xmm29;"    // C[13] = aesenc(M[13], C[13])
        "vaesenc %%xmm29, %%xmm10, %%xmm13;"    // S[29] = aesenc(C[13], S[10])
        "vpxorq %%xmm29, %%xmm6, %%xmm29;"       // C[13] = xor(C[13], S[6])
        "vpxorq %%xmm0, %%xmm21, %%xmm0;"        // S[0] = xor(S[0], M[13])
        "vpxorq %%xmm10, %%xmm21, %%xmm10;"      // S[10] = xor(S[10], M[13])
        "vmovdqa64 %%xmm29, 208(%0, %%rax);"    // Write back C[13] to dst[i+208:i+224]

        // round 15
        "vmovdqa64 224(%1, %%rax), %%xmm22;"    // Load M[14] into xmm22
        "vpxorq %%xmm14, %%xmm15, %%xmm30;"      // C[14] = xor(S[14], S[15])
        "vaesenc %%xmm22, %%xmm30, %%xmm30;"    // C[14] = aesenc(M[14], C[14])
        "vaesenc %%xmm30, %%xmm11, %%xmm14;"    // S[30] = aesenc(C[14], S[11])
        "vpxorq %%xmm30, %%xmm7, %%xmm30;"       // C[14] = xor(C[14], S[7])
        "vpxorq %%xmm1, %%xmm22, %%xmm1;"        // S[1] = xor(S[1], M[14])
        "vpxorq %%xmm11, %%xmm22, %%xmm11;"      // S[11] = xor(S[11], M[14])
        "vmovdqa64 %%xmm30, 224(%0, %%rax);"    // Write back C[14] to dst[i+224:i+240]

        // round 16
        "vmovdqa64 240(%1, %%rax), %%xmm23;"    // Load M[15] into xmm23
        "vpxorq %%xmm15, %%xmm0, %%xmm31;"       // C[15] = xor(S[15], S[0])
        "vaesenc %%xmm23, %%xmm31, %%xmm31;"    // C[15] = aesenc(M[15], C[15])
        "vaesenc %%xmm31, %%xmm12, %%xmm15;"    // S[31] = aesenc(C[15], S[12])
        "vpxorq %%xmm31, %%xmm8, %%xmm31;"       // C[15] = xor(C[15], S[8])
        "vpxorq %%xmm2, %%xmm23, %%xmm2;"        // S[2] = xor(S[2], M[15])
        "vpxorq %%xmm12, %%xmm23, %%xmm12;"      // S[12] = xor(S[12], M[15])
        "vmovdqa64 %%xmm31, 240(%0, %%rax);"    // Write back C[15] to dst[i+240:i+256]

                
        "addq $256, %%rax;"                 // i += 256
        "jmp 1b;"                           // Loop back

        "2:;"                               // Loop end

        // Write back state
        "vmovdqa64 %%xmm0, (%3);"         
        "vmovdqa64 %%xmm1, 16(%3);"     
        "vmovdqa64 %%xmm2, 32(%3);"     
        "vmovdqa64 %%xmm3, 48(%3);"        
        "vmovdqa64 %%xmm4, 64(%3);"     
        "vmovdqa64 %%xmm5, 80(%3);"    
        "vmovdqa64 %%xmm6, 96(%3);"    
        "vmovdqa64 %%xmm7, 112(%3);"    
        "vmovdqa64 %%xmm8, 128(%3);"       
        "vmovdqa64 %%xmm9, 144(%3);"       
        "vmovdqa64 %%xmm10, 160(%3);"    
        "vmovdqa64 %%xmm11, 176(%3);"    
        "vmovdqa64 %%xmm12, 192(%3);"     
        "vmovdqa64 %%xmm13, 208(%3);"   
        "vmovdqa64 %%xmm14, 224(%3);"    
        "vmovdqa64 %%xmm15, 240(%3);" 

        :
        : "r"(dst), "r"(src), "r"(prefix), "r"(state) // input dst, src, prefix, state
        : "%rax", "%xmm0", "%xmm1", "%xmm2", "%xmm3",
          "%xmm4", "%xmm5", "%xmm6", "%xmm7",
          "%xmm8", "%xmm9", "%xmm10", "%xmm11",
          "%xmm12", "%xmm13", "%xmm14", "%xmm15",
          "%xmm16", "%xmm17", "%xmm18", "%xmm19",
          "%xmm20", "%xmm21", "%xmm22", "%xmm23",
          "%xmm24", "%xmm25", "%xmm26", "%xmm27",
          "%xmm28", "%xmm29", "%xmm30", "%xmm31",
          "memory"
    );

    #else
    for(size_t i = 0; i < prefix; i += UNROLL_BLOCK_SIZE) {
        ENCRYPT_1_STEP(0);
        ENCRYPT_1_STEP(1);
        ENCRYPT_1_STEP(2);
        ENCRYPT_1_STEP(3);
        ENCRYPT_1_STEP(4);
        ENCRYPT_1_STEP(5);
        ENCRYPT_1_STEP(6);
        ENCRYPT_1_STEP(7);
        ENCRYPT_1_STEP(8);
        ENCRYPT_1_STEP(9);
        ENCRYPT_1_STEP(10);
        ENCRYPT_1_STEP(11);
        ENCRYPT_1_STEP(12);
        ENCRYPT_1_STEP(13);
        ENCRYPT_1_STEP(14);
        ENCRYPT_1_STEP(15);
    }
    #endif

    for(size_t i = 0; i < rest; i += BLOCK_SIZE) {
        M[0] = load(src + i + prefix);
        ENC_offset(M[0], C[0], 0);
        STATE_SHIFT;
        store(dst + i + prefix, C[0]);
    }
}

void HiAE_stream_decrypt(DATA128b* state, uint8_t *dst, const uint8_t *src, size_t size) {
    size_t rest = size % UNROLL_BLOCK_SIZE;
    size_t prefix = size - rest;
    DATA128b M[STATE], C[STATE], tmp[STATE], temp;

    #if defined(__VAES__) && defined(__x86_64__)
    // asm code optimized for VAES support devices
    
    // xmm0-xmm15 are used for State
    // xmm16-xmm23 are used for M
    // xmm24-xmm31 are used for C

    __asm__ volatile (
        // Load state into xmm0-xmm15
        "vmovdqa64 (%3), %%xmm0;"    // state[0]
        "vmovdqa64 16(%3), %%xmm1;"  // state[1]
        "vmovdqa64 32(%3), %%xmm2;"  // state[2]
        "vmovdqa64 48(%3), %%xmm3;"  // state[3]
        "vmovdqa64 64(%3), %%xmm4;"  // state[4]
        "vmovdqa64 80(%3), %%xmm5;"  // state[5]
        "vmovdqa64 96(%3), %%xmm6;"  // state[6]
        "vmovdqa64 112(%3), %%xmm7;" // state[7]
        "vmovdqa64 128(%3), %%xmm8;" // state[8]
        "vmovdqa64 144(%3), %%xmm9;" // state[9]
        "vmovdqa64 160(%3), %%xmm10;"// state[10]
        "vmovdqa64 176(%3), %%xmm11;"// state[11]
        "vmovdqa64 192(%3), %%xmm12;"// state[12]
        "vmovdqa64 208(%3), %%xmm13;"// state[13]
        "vmovdqa64 224(%3), %%xmm14;"// state[14]
        "vmovdqa64 240(%3), %%xmm15;"// state[15]

        "movq $0, %%rax;"          // Initialize counter i = 0
        "1:;"                      // Loop start
        "cmpq %2, %%rax;"          // Compare i and prefix
        "jge 2f;"                  // If i >= prefix, jump to loop end
        

        // round 1
        "vmovdqu64 0(%1, %%rax), %%xmm24;"    // Load C[0] into xmm24
        "vpxorq %%xmm0, %%xmm1, %%xmm16;"     // M[0] = xor(S[0], S[1])
        "vpxorq %%xmm24, %%xmm9, %%xmm24;"    // C[0] = xor(S[9], C[0])
        "vaesenc %%xmm24, %%xmm13, %%xmm0;"   // S[16] = aesenc(S[13], C[0])
        "vaesenc %%xmm24, %%xmm16, %%xmm16;"  // M[0] = aesenc(C[0], M[0])
        "vpxorq %%xmm3, %%xmm16, %%xmm3;"     // S[3] = xor(S[3], M[0])
        "vpxorq %%xmm13, %%xmm16, %%xmm13;"   // S[13] = xor(S[13], M[0])
        "vmovdqu64 %%xmm16, 0(%0, %%rax);"    // Write back M[0] to dst[i+0:i+16]

        // round 2
        "vmovdqu64 16(%1, %%rax), %%xmm25;"    // Load C[1] into xmm25
        "vpxorq %%xmm1, %%xmm2, %%xmm17;"     // M[1] = xor(S[1], S[2])
        "vpxorq %%xmm25, %%xmm10, %%xmm25;"    // C[1] = xor(S[10], C[1])
        "vaesenc %%xmm25, %%xmm14, %%xmm1;"   // S[17] = aesenc(S[14], C[1])
        "vaesenc %%xmm25, %%xmm17, %%xmm17;"  // M[1] = aesenc(C[1], M[1])
        "vpxorq %%xmm4, %%xmm17, %%xmm4;"     // S[4] = xor(S[4], M[1])
        "vpxorq %%xmm14, %%xmm17, %%xmm14;"   // S[14] = xor(S[14], M[1])
        "vmovdqu64 %%xmm17, 16(%0, %%rax);"    // Write back M[1] to dst[i+16:i+32]

        // round 3
        "vmovdqu64 32(%1, %%rax), %%xmm26;"    // Load C[2] into xmm26
        "vpxorq %%xmm2, %%xmm3, %%xmm18;"     // M[2] = xor(S[2], S[3])
        "vpxorq %%xmm26, %%xmm11, %%xmm26;"    // C[2] = xor(S[11], C[2])
        "vaesenc %%xmm26, %%xmm15, %%xmm2;"   // S[18] = aesenc(S[15], C[2])
        "vaesenc %%xmm26, %%xmm18, %%xmm18;"  // M[2] = aesenc(C[2], M[2])
        "vpxorq %%xmm5, %%xmm18, %%xmm5;"     // S[5] = xor(S[5], M[2])
        "vpxorq %%xmm15, %%xmm18, %%xmm15;"   // S[15] = xor(S[15], M[2])
        "vmovdqu64 %%xmm18, 32(%0, %%rax);"    // Write back M[2] to dst[i+32:i+48]

        // round 4
        "vmovdqu64 48(%1, %%rax), %%xmm27;"    // Load C[3] into xmm27
        "vpxorq %%xmm3, %%xmm4, %%xmm19;"     // M[3] = xor(S[3], S[4])
        "vpxorq %%xmm27, %%xmm12, %%xmm27;"    // C[3] = xor(S[12], C[3])
        "vaesenc %%xmm27, %%xmm0, %%xmm3;"   // S[19] = aesenc(S[16], C[3])
        "vaesenc %%xmm27, %%xmm19, %%xmm19;"  // M[3] = aesenc(C[3], M[3])
        "vpxorq %%xmm6, %%xmm19, %%xmm6;"     // S[6] = xor(S[6], M[3])
        "vpxorq %%xmm0, %%xmm19, %%xmm0;"   // S[16] = xor(S[16], M[3])
        "vmovdqu64 %%xmm19, 48(%0, %%rax);"    // Write back M[3] to dst[i+48:i+64]

        // round 5
        "vmovdqu64 64(%1, %%rax), %%xmm28;"    // Load C[4] into xmm28
        "vpxorq %%xmm4, %%xmm5, %%xmm20;"     // M[4] = xor(S[4], S[5])
        "vpxorq %%xmm28, %%xmm13, %%xmm28;"    // C[4] = xor(S[13], C[4])
        "vaesenc %%xmm28, %%xmm1, %%xmm4;"   // S[20] = aesenc(S[17], C[4])
        "vaesenc %%xmm28, %%xmm20, %%xmm20;"  // M[4] = aesenc(C[4], M[4])
        "vpxorq %%xmm7, %%xmm20, %%xmm7;"     // S[7] = xor(S[7], M[4])
        "vpxorq %%xmm1, %%xmm20, %%xmm1;"   // S[17] = xor(S[17], M[4])
        "vmovdqu64 %%xmm20, 64(%0, %%rax);"    // Write back M[4] to dst[i+64:i+80]

        // round 6
        "vmovdqu64 80(%1, %%rax), %%xmm29;"    // Load C[5] into xmm29
        "vpxorq %%xmm5, %%xmm6, %%xmm21;"     // M[5] = xor(S[5], S[6])
        "vpxorq %%xmm29, %%xmm14, %%xmm29;"    // C[5] = xor(S[14], C[5])
        "vaesenc %%xmm29, %%xmm2, %%xmm5;"   // S[21] = aesenc(S[18], C[5])
        "vaesenc %%xmm29, %%xmm21, %%xmm21;"  // M[5] = aesenc(C[5], M[5])
        "vpxorq %%xmm8, %%xmm21, %%xmm8;"     // S[8] = xor(S[8], M[5])
        "vpxorq %%xmm2, %%xmm21, %%xmm2;"   // S[18] = xor(S[18], M[5])
        "vmovdqu64 %%xmm21, 80(%0, %%rax);"    // Write back M[5] to dst[i+80:i+96]

        // round 7
        "vmovdqu64 96(%1, %%rax), %%xmm30;"    // Load C[6] into xmm30
        "vpxorq %%xmm6, %%xmm7, %%xmm22;"     // M[6] = xor(S[6], S[7])
        "vpxorq %%xmm30, %%xmm15, %%xmm30;"    // C[6] = xor(S[15], C[6])
        "vaesenc %%xmm30, %%xmm3, %%xmm6;"   // S[22] = aesenc(S[19], C[6])
        "vaesenc %%xmm30, %%xmm22, %%xmm22;"  // M[6] = aesenc(C[6], M[6])
        "vpxorq %%xmm9, %%xmm22, %%xmm9;"     // S[9] = xor(S[9], M[6])
        "vpxorq %%xmm3, %%xmm22, %%xmm3;"   // S[19] = xor(S[19], M[6])
        "vmovdqu64 %%xmm22, 96(%0, %%rax);"    // Write back M[6] to dst[i+96:i+112]

        // round 8
        "vmovdqu64 112(%1, %%rax), %%xmm31;"    // Load C[7] into xmm31
        "vpxorq %%xmm7, %%xmm8, %%xmm23;"     // M[7] = xor(S[7], S[8])
        "vpxorq %%xmm31, %%xmm0, %%xmm31;"    // C[7] = xor(S[16], C[7])
        "vaesenc %%xmm31, %%xmm4, %%xmm7;"   // S[23] = aesenc(S[20], C[7])
        "vaesenc %%xmm31, %%xmm23, %%xmm23;"  // M[7] = aesenc(C[7], M[7])
        "vpxorq %%xmm10, %%xmm23, %%xmm10;"     // S[10] = xor(S[10], M[7])
        "vpxorq %%xmm4, %%xmm23, %%xmm4;"   // S[20] = xor(S[20], M[7])
        "vmovdqu64 %%xmm23, 112(%0, %%rax);"    // Write back M[7] to dst[i+112:i+128]

        // round 9
        "vmovdqu64 128(%1, %%rax), %%xmm24;"    // Load C[8] into xmm24
        "vpxorq %%xmm8, %%xmm9, %%xmm16;"     // M[8] = xor(S[8], S[9])
        "vpxorq %%xmm24, %%xmm1, %%xmm24;"    // C[8] = xor(S[17], C[8])
        "vaesenc %%xmm24, %%xmm5, %%xmm8;"   // S[24] = aesenc(S[21], C[8])
        "vaesenc %%xmm24, %%xmm16, %%xmm16;"  // M[8] = aesenc(C[8], M[8])
        "vpxorq %%xmm11, %%xmm16, %%xmm11;"     // S[11] = xor(S[11], M[8])
        "vpxorq %%xmm5, %%xmm16, %%xmm5;"   // S[21] = xor(S[21], M[8])
        "vmovdqu64 %%xmm16, 128(%0, %%rax);"    // Write back M[8] to dst[i+128:i+144]

        // round 10
        "vmovdqu64 144(%1, %%rax), %%xmm25;"    // Load C[9] into xmm25
        "vpxorq %%xmm9, %%xmm10, %%xmm17;"     // M[9] = xor(S[9], S[10])
        "vpxorq %%xmm25, %%xmm2, %%xmm25;"    // C[9] = xor(S[18], C[9])
        "vaesenc %%xmm25, %%xmm6, %%xmm9;"   // S[25] = aesenc(S[22], C[9])
        "vaesenc %%xmm25, %%xmm17, %%xmm17;"  // M[9] = aesenc(C[9], M[9])
        "vpxorq %%xmm12, %%xmm17, %%xmm12;"     // S[12] = xor(S[12], M[9])
        "vpxorq %%xmm6, %%xmm17, %%xmm6;"   // S[22] = xor(S[22], M[9])
        "vmovdqu64 %%xmm17, 144(%0, %%rax);"    // Write back M[9] to dst[i+144:i+160]

        // round 11
        "vmovdqu64 160(%1, %%rax), %%xmm26;"    // Load C[10] into xmm26
        "vpxorq %%xmm10, %%xmm11, %%xmm18;"     // M[10] = xor(S[10], S[11])
        "vpxorq %%xmm26, %%xmm3, %%xmm26;"    // C[10] = xor(S[19], C[10])
        "vaesenc %%xmm26, %%xmm7, %%xmm10;"   // S[26] = aesenc(S[23], C[10])
        "vaesenc %%xmm26, %%xmm18, %%xmm18;"  // M[10] = aesenc(C[10], M[10])
        "vpxorq %%xmm13, %%xmm18, %%xmm13;"     // S[13] = xor(S[13], M[10])
        "vpxorq %%xmm7, %%xmm18, %%xmm7;"   // S[23] = xor(S[23], M[10])
        "vmovdqu64 %%xmm18, 160(%0, %%rax);"    // Write back M[10] to dst[i+160:i+176]

        // round 12
        "vmovdqu64 176(%1, %%rax), %%xmm27;"    // Load C[11] into xmm27
        "vpxorq %%xmm11, %%xmm12, %%xmm19;"     // M[11] = xor(S[11], S[12])
        "vpxorq %%xmm27, %%xmm4, %%xmm27;"    // C[11] = xor(S[20], C[11])
        "vaesenc %%xmm27, %%xmm8, %%xmm11;"   // S[27] = aesenc(S[24], C[11])
        "vaesenc %%xmm27, %%xmm19, %%xmm19;"  // M[11] = aesenc(C[11], M[11])
        "vpxorq %%xmm14, %%xmm19, %%xmm14;"     // S[14] = xor(S[14], M[11])
        "vpxorq %%xmm8, %%xmm19, %%xmm8;"   // S[24] = xor(S[24], M[11])
        "vmovdqu64 %%xmm19, 176(%0, %%rax);"    // Write back M[11] to dst[i+176:i+192]

        // round 13
        "vmovdqu64 192(%1, %%rax), %%xmm28;"    // Load C[12] into xmm28
        "vpxorq %%xmm12, %%xmm13, %%xmm20;"     // M[12] = xor(S[12], S[13])
        "vpxorq %%xmm28, %%xmm5, %%xmm28;"    // C[12] = xor(S[21], C[12])
        "vaesenc %%xmm28, %%xmm9, %%xmm12;"   // S[28] = aesenc(S[25], C[12])
        "vaesenc %%xmm28, %%xmm20, %%xmm20;"  // M[12] = aesenc(C[12], M[12])
        "vpxorq %%xmm15, %%xmm20, %%xmm15;"     // S[15] = xor(S[15], M[12])
        "vpxorq %%xmm9, %%xmm20, %%xmm9;"   // S[25] = xor(S[25], M[12])
        "vmovdqu64 %%xmm20, 192(%0, %%rax);"    // Write back M[12] to dst[i+192:i+208]

        // round 14
        "vmovdqu64 208(%1, %%rax), %%xmm29;"    // Load C[13] into xmm29
        "vpxorq %%xmm13, %%xmm14, %%xmm21;"     // M[13] = xor(S[13], S[14])
        "vpxorq %%xmm29, %%xmm6, %%xmm29;"    // C[13] = xor(S[22], C[13])
        "vaesenc %%xmm29, %%xmm10, %%xmm13;"   // S[29] = aesenc(S[26], C[13])
        "vaesenc %%xmm29, %%xmm21, %%xmm21;"  // M[13] = aesenc(C[13], M[13])
        "vpxorq %%xmm0, %%xmm21, %%xmm0;"     // S[16] = xor(S[16], M[13])
        "vpxorq %%xmm10, %%xmm21, %%xmm10;"   // S[26] = xor(S[26], M[13])
        "vmovdqu64 %%xmm21, 208(%0, %%rax);"    // Write back M[13] to dst[i+208:i+224]

        // round 15
        "vmovdqu64 224(%1, %%rax), %%xmm30;"    // Load C[14] into xmm30
        "vpxorq %%xmm14, %%xmm15, %%xmm22;"     // M[14] = xor(S[14], S[15])
        "vpxorq %%xmm30, %%xmm7, %%xmm30;"    // C[14] = xor(S[23], C[14])
        "vaesenc %%xmm30, %%xmm11, %%xmm14;"   // S[30] = aesenc(S[27], C[14])
        "vaesenc %%xmm30, %%xmm22, %%xmm22;"  // M[14] = aesenc(C[14], M[14])
        "vpxorq %%xmm1, %%xmm22, %%xmm1;"     // S[17] = xor(S[17], M[14])
        "vpxorq %%xmm11, %%xmm22, %%xmm11;"   // S[27] = xor(S[27], M[14])
        "vmovdqu64 %%xmm22, 224(%0, %%rax);"    // Write back M[14] to dst[i+224:i+240]

        // round 16
        "vmovdqu64 240(%1, %%rax), %%xmm31;"    // Load C[15] into xmm31
        "vpxorq %%xmm15, %%xmm0, %%xmm23;"     // M[15] = xor(S[15], S[16])
        "vpxorq %%xmm31, %%xmm8, %%xmm31;"    // C[15] = xor(S[24], C[15])
        "vaesenc %%xmm31, %%xmm12, %%xmm15;"   // S[31] = aesenc(S[28], C[15])
        "vaesenc %%xmm31, %%xmm23, %%xmm23;"  // M[15] = aesenc(C[15], M[15])
        "vpxorq %%xmm2, %%xmm23, %%xmm2;"     // S[18] = xor(S[18], M[15])
        "vpxorq %%xmm12, %%xmm23, %%xmm12;"   // S[28] = xor(S[28], M[15])
        "vmovdqu64 %%xmm23, 240(%0, %%rax);"    // Write back M[15] to dst[i+240:i+256]
           
        "addq $256, %%rax;"                 // i += 256
        "jmp 1b;"                           // Loop back

        "2:;"                               // Loop end

        // Write back state
        "vmovdqa64 %%xmm0, (%3);"         
        "vmovdqa64 %%xmm1, 16(%3);"     
        "vmovdqa64 %%xmm2, 32(%3);"     
        "vmovdqa64 %%xmm3, 48(%3);"        
        "vmovdqa64 %%xmm4, 64(%3);"     
        "vmovdqa64 %%xmm5, 80(%3);"    
        "vmovdqa64 %%xmm6, 96(%3);"    
        "vmovdqa64 %%xmm7, 112(%3);"    
        "vmovdqa64 %%xmm8, 128(%3);"       
        "vmovdqa64 %%xmm9, 144(%3);"       
        "vmovdqa64 %%xmm10, 160(%3);"    
        "vmovdqa64 %%xmm11, 176(%3);"    
        "vmovdqa64 %%xmm12, 192(%3);"     
        "vmovdqa64 %%xmm13, 208(%3);"   
        "vmovdqa64 %%xmm14, 224(%3);"    
        "vmovdqa64 %%xmm15, 240(%3);" 

        :
        : "r"(dst), "r"(src), "r"(prefix), "r"(state) // input dst, src, prefix, state
        : "%rax", "%xmm0", "%xmm1", "%xmm2", "%xmm3",
          "%xmm4", "%xmm5", "%xmm6", "%xmm7",
          "%xmm8", "%xmm9", "%xmm10", "%xmm11",
          "%xmm12", "%xmm13", "%xmm14", "%xmm15",
          "%xmm16", "%xmm17", "%xmm18", "%xmm19",
          "%xmm20", "%xmm21", "%xmm22", "%xmm23",
          "%xmm24", "%xmm25", "%xmm26", "%xmm27",
          "%xmm28", "%xmm29", "%xmm30", "%xmm31",
          "memory"
    );

    #else

    for(size_t i = 0; i < prefix; i += UNROLL_BLOCK_SIZE) {
        DECRYPT_1_STEP(0);
        DECRYPT_1_STEP(1);
        DECRYPT_1_STEP(2);
        DECRYPT_1_STEP(3);
        DECRYPT_1_STEP(4);
        DECRYPT_1_STEP(5);
        DECRYPT_1_STEP(6);
        DECRYPT_1_STEP(7);
        DECRYPT_1_STEP(8);
        DECRYPT_1_STEP(9);
        DECRYPT_1_STEP(10);
        DECRYPT_1_STEP(11);
        DECRYPT_1_STEP(12);
        DECRYPT_1_STEP(13);
        DECRYPT_1_STEP(14);
        DECRYPT_1_STEP(15);
    }

    #endif

    for(size_t i = 0; i < rest; i += BLOCK_SIZE) {
        C[0] = load(src + i + prefix);
        DEC_offset(M[0], C[0], 0);
        STATE_SHIFT;
        store(dst + i + prefix, M[0]);
    }
}

void HiAE(uint8_t *key, uint8_t *iv, uint8_t *plain, uint8_t *cipher, uint8_t *ad, uint8_t *tag) {
    DATA128b state[STATE];

    HiAE_stream_init(state, key, iv);
    HiAE_stream_proc_ad(state, ad, strlen(ad));
    HiAE_stream_encrypt(state, plain, cipher, strlen(plain));
    HiAE_stream_finalize(state, strlen(ad), strlen(plain), tag);

}