#include "HiAE.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

size_t H_Mac(const char* input_file, const uint8_t* key, const uint8_t* iv, uint8_t* tag, size_t buffer_size) {
    FILE* in = fopen(input_file, "rb");
    if (in == NULL) {
        printf("Error: Could not open input file\n");
        return 0;
    }

    if (buffer_size % 16 != 0) {
        printf("Error: Buffer size must be a multiple of 16\n");
        fclose(in);
        return 0;
    }

    uint8_t* buffer = (uint8_t*)malloc(buffer_size);
    if (buffer == NULL) {
        printf("Error: Could not allocate buffer\n");
        fclose(in);
        return 0;
    }


    DATA128b state[16];
    HiAE_stream_init(state, key, iv);
    fseek(in, 0, SEEK_END);
    size_t total_size = ftell(in);
    fseek(in, 0, SEEK_SET);
    size_t read_size = 0;
    while (read_size < total_size) {
        size_t read = fread(buffer, 1, buffer_size, in);
        read_size += read;
        HiAE_stream_proc_ad(state, buffer, read);
    }

    HiAE_stream_finalize(state, total_size, 0, tag);

    free(buffer);
    fclose(in);
    return total_size;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: %s <input_file> <key> <iv> [buffer_size (MB)]\n", argv[0]);
        return 1;
    }

    // check key and iv length
    if (strlen(argv[2]) > 64) {
        printf("Error: Key must be in 32 characters\n");
        return 1;
    }
    if (strlen(argv[3]) > 32) {
        printf("Error: IV must be in 16 characters\n");
        return 1;
    }

    uint8_t key[32];
    uint8_t iv[16];
    memset(key, 0, 32);
    memset(iv, 0, 16);
    //str to hex
    for (int i = 0; i < strlen(argv[2]); i += 2) {
        sscanf(argv[2] + i, "%2hhx", &key[i / 2]);
    }
    for (int i = 0; i < strlen(argv[3]); i += 2) {
        sscanf(argv[3] + i, "%2hhx", &iv[i / 2]);
    }

    size_t buffer_size = 4 * 1024 * 1024; // default buffer size is 4MB

    if (argc > 4) {
        size_t buffer_size_temp = atoi(argv[4]);
        if (buffer_size_temp < 1) {
            printf("Error: Buffer size must be greater than 0\n");
            return 1;
        }
        buffer_size = buffer_size_temp * 1024 * 1024; // convert MB to bytes
    }

    printf("KEY = ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", key[i]);
    }
    printf("\nIV = ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");
    
    clock_t start = clock();
    uint8_t tag[16];
    size_t file_size = H_Mac(argv[1], key, iv, tag, buffer_size);
    printf("MAC: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", tag[i]);
    }    printf("\n");
    clock_t end = clock();
    printf("MAC file %s (%lu bytes) in %f seconds\n", argv[1], file_size, (double)(end - start) / CLOCKS_PER_SEC);
    double speed = (double)file_size / (1024 * 1024 * 1024) / ((double)(end - start) / CLOCKS_PER_SEC);
    printf("Speed: %f GB/s\n", speed);

    return 0;
}
