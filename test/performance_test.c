#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "HiAE.h"
#include <time.h>

#define REPEAT 262144

const int len_test_case = 9;
size_t test_case[9] = {16, 64, 256, 512, 1024, 2048, 4096, 8192, 16384};

void print_data(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

double speed_test_ad_work(size_t len) {
    uint8_t key[32];
    memset(key, 1, 32);
    uint8_t iv[16];
    memset(iv, 1, 16);
    size_t ad_len = len;
    uint8_t *ad = (uint8_t *) malloc(ad_len);
    memset(ad, 1, ad_len);
    clock_t start, end;
    uint8_t tag[16];
    start = clock();
    for (size_t iter = REPEAT; iter > 0; iter --) {
        HiAE_verification(key, iv, ad, ad_len, tag);
    }
    end = clock();

    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    double speed = ((double) REPEAT * len) / (cpu_time_used*(125000000));

    return speed;
}

double speed_test_encode_work(size_t len, int AEAD) {
    uint8_t key[32];
    memset(key, 1, 32);
    uint8_t iv[16];
    memset(iv, 1, 16);
    size_t ad_len = 48;
    uint8_t *ad = (uint8_t *) malloc(ad_len);
    memset(ad, 1, ad_len);
    size_t plain_len = len;
    uint8_t *plain = (uint8_t *) malloc(plain_len);
    uint8_t *cipher = (uint8_t *) malloc(plain_len);
    memset(plain, 0x1, plain_len);
    clock_t start, end;

    if(AEAD == 1) {
        uint8_t tag[16];
        start = clock();
        for (size_t iter = REPEAT; iter > 0; iter --) {
            HiAE_AEAD_encrypt(key, iv, plain, cipher, plain_len, ad, ad_len, tag);
        }
        end = clock();
    }
    else {
        start = clock();
        for (size_t iter = REPEAT; iter > 0; iter --) {
            HiAE_encrypt(key, iv, plain, cipher, plain_len);
        }
        end = clock();
    }

    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    double speed = ((double) REPEAT * plain_len) / (cpu_time_used*(125000000));

    return speed;
}

double speed_test_decode_work(size_t len, int AEAD) {
    uint8_t key[32];
    memset(key, 1, 32);
    uint8_t iv[16];
    memset(iv, 1, 16);
    size_t ad_len = 48;
    uint8_t *ad = (uint8_t *) malloc(ad_len);
    memset(ad, 1, ad_len);
    size_t plain_len = len;
    uint8_t *plain = (uint8_t *) malloc(plain_len);
    uint8_t *cipher = (uint8_t *) malloc(plain_len);
    memset(plain, 0x1, plain_len);
    clock_t start, end;
    
    if(AEAD == 1) {
        uint8_t tag[16];
        start = clock();
        for (size_t iter = REPEAT; iter > 0; iter --) {
            HiAE_AEAD_decrypt(key, iv, plain, cipher, plain_len, ad, ad_len, tag);
        }
        end = clock();
    }
    else {
        start = clock();
        for (size_t iter = REPEAT; iter > 0; iter --) {
            HiAE_decrypt(key, iv, plain, cipher, plain_len);
        }
        end = clock();
    }
    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    double speed = ((double) REPEAT * plain_len) / (cpu_time_used*(125000000.0));

    return speed;
}

void speed_test_encryption() {
    double encrypto_speed[len_test_case];
    double decrypto_speed[len_test_case];
    printf("--------speed test Encryption Only(Gbps)----------\n");
    for (int i = 0; i < len_test_case; i++)
    {
        encrypto_speed[i] = speed_test_encode_work(test_case[i], 0);
        decrypto_speed[i] = speed_test_decode_work(test_case[i], 0);
        printf("length: %ld, encrypt: %.2f, decrypt: %.2f\n", test_case[i], encrypto_speed[i], decrypto_speed[i]);
    }
}

void speed_test_ad_only() {
    printf("--------speed test AD Only(Gbps)----------\n");
    for (int i = 0; i < len_test_case; i++)
    {
        double ad = speed_test_ad_work(test_case[i]);
        printf("length: %ld, AD: %.2f\n", test_case[i], ad);
    }
}

void speed_test_aead() {
    double encrypto_speed[len_test_case];
    double decrypto_speed[len_test_case];
    printf("--------speed test AEAD(Gbps)----------\n");
    for (int i = 0; i < len_test_case; i++)
    {
        encrypto_speed[i] = speed_test_encode_work(test_case[i], 1);
        decrypto_speed[i] = speed_test_decode_work(test_case[i], 1);
        printf("length: %ld, encrypt: %.2f, decrypt: %.2f\n", test_case[i], encrypto_speed[i], decrypto_speed[i]);
    }
}

int main() {
    printf("========HiAE Performance test========\n");
    speed_test_encryption();
    speed_test_ad_only();
    speed_test_aead();
}
