#include "HiAE.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

size_t encrypt_file(const char* input_file, const char* output_file, const char* key, const char* iv, size_t buffer_size) {
    FILE* in = fopen(input_file, "rb");
    if (in == NULL) {
        printf("Error: Could not open input file\n");
        return 0;
    }
    FILE* out = fopen(output_file, "wb");
    if (out == NULL) {
        printf("Error: Could not open output file\n");
        fclose(in);
        return 0;
    }

    uint8_t* buffer = (uint8_t*)malloc(buffer_size);
    if (buffer == NULL) {
        printf("Error: Could not allocate buffer\n");
        fclose(in);
        fclose(out);
        return 0;
    }

    uint8_t* cipher = (uint8_t*)malloc(buffer_size);
    if (cipher == NULL) {
        printf("Error: Could not allocate cipher buffer\n");
        free(buffer);
        fclose(in);
        fclose(out);
        return 0;
    }

    uint8_t* tag = (uint8_t*)malloc(16);

    uint8_t key_data[32];
    uint8_t iv_data[16];
    memcpy(key_data, key, 32);
    memcpy(iv_data, iv, 16);

    DATA128b state[16];
    HiAE_stream_init(state, key_data, iv_data);
    fseek(in, 0, SEEK_END);
    size_t total_size = ftell(in);
    fseek(in, 0, SEEK_SET);
    size_t read_size = 0;
    while (read_size < total_size) {
        size_t read = fread(buffer, 1, buffer_size, in);
        read_size += read;
        if (read_size > total_size) {
            read -= read_size - total_size;
            //pad to 16x bytes
            size_t pad = 16 - (read % 16);
            if (pad != 16) {
                memset(buffer + read, 0, pad);
                read += pad;
            }
        }
        HiAE_stream_encrypt(state, cipher, buffer, read);
        fwrite(cipher, 1, read, out);
    }

    HiAE_stream_finalize(state, 0, total_size, tag);
    fwrite(tag, 1, 16, out);

    free(buffer);
    free(cipher);
    free(tag);
    fclose(in);
    fclose(out);

    return total_size;
}

size_t decrypt_file(const char* input_file, const char* output_file, const char* key, const char* iv, size_t buffer_size) {
    FILE* in = fopen(input_file, "rb");
    if (in == NULL) {
        printf("Error: Could not open input file\n");
        return 0;
    }
    FILE* out = fopen(output_file, "wb");
    if (out == NULL) {
        printf("Error: Could not open output file\n");
        fclose(in);
        return 0;
    }

    uint8_t* buffer = (uint8_t*)malloc(buffer_size);
    if (buffer == NULL) {
        printf("Error: Could not allocate buffer\n");
        fclose(in);
        fclose(out);
        return 0;
    }

    uint8_t* plain = (uint8_t*)malloc(buffer_size);
    if (plain == NULL) {
        printf("Error: Could not allocate plain buffer\n");
        free(buffer);
        fclose(in);
        fclose(out);
        return 0;
    }

    uint8_t tag[16];
    fseek(in, -16, SEEK_END);
    size_t tag_len = fread(tag, 1, 16, in);
    if (tag_len != 16) {
        printf("Error: Could not read tag\n");
        free(buffer);
        free(plain);
        fclose(in);
        fclose(out);
        return 0;
    }
    fseek(in, 0, SEEK_SET);

    uint8_t key_data[32];
    uint8_t iv_data[16];
    memcpy(key_data, key, 32);
    memcpy(iv_data, iv, 16);

    DATA128b state[16];
    HiAE_stream_init(state, key_data, iv_data);

    //read in[0, -16] into buffer, decrypt, write to out, dont read last 16 bytes
    fseek(in, 0, SEEK_END);
    size_t total_size = ftell(in) - 16;
    fseek(in, 0, SEEK_SET);
    size_t read_size = 0;
    while (read_size < total_size) {
        size_t read = fread(buffer, 1, buffer_size, in);
        read_size += read;
        if (read_size > total_size) {
            read -= read_size - total_size;
        }
        HiAE_stream_decrypt(state, plain, buffer, read);
        fwrite(plain, 1, read, out);
    }

    uint8_t tag_check[16];
    HiAE_stream_finalize(state, 0, total_size, tag_check);

    if (memcmp(tag, tag_check, 16) != 0) {
        printf("Error: Tag mismatch\n");
    }

    free(buffer);
    free(plain);
    fclose(in);
    fclose(out);

    return total_size;
}

int main(int argc, char** argv) {
    if (argc < 5) {
        printf("Usage: %s <encrypt/decrypt> <input_file> <output_file> <key> <iv> [buffer_size]\n", argv[0]);
        return 1;
    }

    // check key and iv length
    if (strlen(argv[4]) != 32) {
        printf("Error: Key must be 32 characters\n");
        return 1;
    }
    if (strlen(argv[5]) != 16) {
        printf("Error: IV must be 16 characters\n");
        return 1;
    }

    size_t buffer_size = 65536;

    if (argc > 6) {
        size_t buffer_size_temp = atoi(argv[6]);
        if (buffer_size_temp < 16) {
            printf("Error: Buffer size must be at least 16\n");
            return 1;
        }
        if (buffer_size_temp % 16 != 0) {
            printf("Error: Buffer size must be a multiple of 16\n");
            return 1;
        }
        buffer_size = buffer_size_temp;
    }

    if (strcmp(argv[1], "encrypt") == 0) {
        clock_t start = clock();
        size_t file_size = encrypt_file(argv[2], argv[3], argv[4], argv[5], buffer_size);
        clock_t end = clock();
        printf("Encrypted %s to %s (%lu bytes) in %f seconds\n", argv[2], argv[3], file_size, (double)(end - start) / CLOCKS_PER_SEC);
        double speed = (double)file_size / (1024 * 1024 * 1024) / ((double)(end - start) / CLOCKS_PER_SEC);
        printf("Speed: %f GB/s\n", speed);
    } else if (strcmp(argv[1], "decrypt") == 0) {
        clock_t start = clock();
        size_t file_size = decrypt_file(argv[2], argv[3], argv[4], argv[5], buffer_size);
        clock_t end = clock();
        printf("Decrypted %s to %s (%lu bytes) in %f seconds\n", argv[2], argv[3], file_size, (double)(end - start) / CLOCKS_PER_SEC);
        double speed = (double)file_size / (1024 * 1024 * 1024) / ((double)(end - start) / CLOCKS_PER_SEC);
        printf("Speed: %f GB/s\n", speed);
    } else {
        printf("Usage: %s <encrypt/decrypt> <input_file> <output_file> <key> <iv> [buffer_size]\n", argv[0]);
        return 1;
    }

    return 0;
}

/* Test ENC:  
 *
 */
