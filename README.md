# HiAE
Official implementation of paper "HiAE: A High-Throughput Authenticated Encryption Algorithm for Cross-Platform Efficiency"

## Design Rational

The HiAE is an AES-based AEAD cipher that mainly focuses on cross-platform efficiency(ARM and x86) and achieves the fastest speed on the latest ARM and x86 architectures.

#### XAXX Structure

![XAXX.drawio (1)](image/README/XAXX.drawio%20(1).png)

## Speed Benchmark

View the full speed benchmark [here](https://concyclics.github.io/HiAE/Speed/speed.html)

![image-20241128165224697](image/README/image-20241128165224697.png)

## Applications

#### File AEAD Encryption & Decryption

The File encryption will auto append the AEAD tag after the file for integrity protection.

**compile**
```bash
#For x86
gcc -O3 -march=native -I code/ code/HiAE.c app/file_enc.c -o FileHiAE
#For armv8
gcc -O3 -march=armv8-a+crypto -I code/ code/HiAE.c app/file_enc.c -o FileHiAE
```

**Usage**
```bash
./FileHiAE <encrypt/decrypt> <input_file> <output_file> <key: 32 chars> <iv: 16 chars> [buffer_size: Default 65536]
```

