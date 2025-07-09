/*
 * HiAE Test Vector Validation
 * Test vectors from draft-pham-cfrg-hiae
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "../code/HiAE.h"

// Helper function to convert hex string to bytes
static int hex_to_bytes(const char* hex, uint8_t* bytes, size_t max_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return -1;
    
    size_t byte_len = len / 2;
    if (byte_len > max_len) return -1;
    
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2*i, "%2x", &byte) != 1) return -1;
        bytes[i] = (uint8_t)byte;
    }
    return byte_len;
}

// Helper function to print hex bytes
static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Test vector structure
typedef struct {
    const char* name;
    const char* key;
    const char* nonce;
    const char* ad;
    const char* plaintext;
    const char* ciphertext;
    const char* tag;
} TestVector;

static const TestVector test_vectors[] = {
    // Test Vector 1
    {
        .name = "Test Vector 1",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe",
        .plaintext = "3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b2735602dd674f9e8227ab7a555fb3588ee61c43cc038ec51cab2dd39f075a518aa054580793f689bb920400f1b769709d75b46",
        .ciphertext = "ff9fcccf03188954a27c74821b76332bd2490761f9d3e3be14613e91ab0af720cc63177cc72a63eea503bed4cb70b0c42d38551b47b7bbda52f23374a4feea06b8b9c9d3c888935e4a78de02ec329bc866053c77fdabe930f273adc0175802ca31b645d1958afc28806843a671347301130d23a94f3adee985fb2e60f0d5d024",
        .tag = "78674481574ba946b2b1e03e0aab2bd5"
    },
    // Test Vector 2
    {
        .name = "Test Vector 2",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d",
        .plaintext = "855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b2735602dd674f9e8227ab7a555fb3588ee61c43cc038ec51cab2dd39f075a518aa054580793f689bb920400f1b769709d75b46979332e85de4c697d53b3cede5413265ba71ce552bee963a090cd113e32d597bc08b631e7029b54564f132493264afecd67d41016bd73b74e30c87c739e042fa6ca518dccfcd2133be537df0b72cdc8da91d8e14f5c988d8d6109f0ff0e1095c87213856ee5989acac069c643278f1db9680ef8b4978631f88032f78e438d56b5a0dc148674bf513519177840a695fa0e94f2b32c78e524f9181c776b99ce113aaa35c11ee51243fe29cc3ec05238cee72b72039467288d7f34f4dadec2fc096d21ca7c06dcbff5067c33c6ce6c95a58",
        .ciphertext = "17cd9eac8632514382d4cfc2d93954a2e3464bd599563524543140c972f65260453d8f2975609fc41960b20ac522fa73ff9fcccf03188954a27c74821b76332bd2490761f9d3e3be14613e91ab0af720cc63177cc72a63eea503bed4cb70b0c42d38551b47b7bbda52f23374a4feea06b8b9c9d3c888935e4a78de02ec329bc866053c77fdabe930f273adc0175802ca31b645d1958afc28806843a671347301130d23a94f3adee985fb2e60f0d5d024dab94f8fd41ccfef27898e5581c4add205d3ac44b51df43854cb6a10292ea986c9725ea6db27695f7ec1c31299e24f8be1d44953afb66707179cf873e94a273de5fb369ae0314013560e3c597fda5178c254cf457d3dde55441267fda2145ad52a16fbb2d9fa63c6ce8f2175086e5a9dda2089bc5890f2c7ed81d8049e491035e0cff5abf178e1dfbbcd1ab7ec47ea8d854419a04f9f8cdd1542c27da97c30e0bea2f4a7710d72346e0c7369202692ba5a43850d5a349d4410155f2bc700a655d2aa57ab9cfa6dd2db0918c4a43a8628",
        .tag = "a8267a259a0cdbcb92d4687697239390"
    },
    // Test Vector 3
    {
        .name = "Test Vector 3",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b273560",
        .plaintext = "2dd674f9e8227ab7a555fb3588ee61c4",
        .ciphertext = "66053c77fdabe930f273adc0175802ca",
        .tag = "553e1e4c2feb9466e4c44813dcbb2add"
    },
    // Test Vector 4
    {
        .name = "Test Vector 4",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "",
        .plaintext = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b2735602dd674f9e8227ab7a555fb3588ee61c43cc038ec51cab2dd39f075a518aa054580793f689bb920400f1b769709d75b46979332e85de4c697d53b3cede5413265ba71ce552bee963a090cd113e32d597bc08b631e7029b54564f132493264afecd67d41016bd73b74e30c87c739e042fa6ca518dccfcd2133be537df0b72cdc8da91d8e14f5c988d8d6109f0ff0e1095c87213856ee5989acac069c643278f1db9680ef8b4978631f88032f78e438d56b5a0dc148674bf513519177840a695fa0e94f2b32c78e524f9181c776b99ce113aaa35c11ee51243fe29cc3ec05238cee72b72039467288d7f34f4dadec2fc096d21ca7c06dcbff5067c33c6ce6c95a58807b91c6ed199ee168eb8e541a4eeaec6b91acd85dac28c46f6531552e8badae",
        .ciphertext = "d716f4983b0025a57cd4c3c3c94a146d6cb665a4a5f33032ae3f86dc1a6caed05243a1cd70688710da9b9bf9b1e3209217cd9eac8632514382d4cfc2d93954a2e3464bd599563524543140c972f65260453d8f2975609fc41960b20ac522fa73ff9fcccf03188954a27c74821b76332bd2490761f9d3e3be14613e91ab0af720cc63177cc72a63eea503bed4cb70b0c42d38551b47b7bbda52f23374a4feea06b8b9c9d3c888935e4a78de02ec329bc866053c77fdabe930f273adc0175802ca31b645d1958afc28806843a671347301130d23a94f3adee985fb2e60f0d5d024dab94f8fd41ccfef27898e5581c4add205d3ac44b51df43854cb6a10292ea986c9725ea6db27695f7ec1c31299e24f8be1d44953afb66707179cf873e94a273de5fb369ae0314013560e3c597fda5178c254cf457d3dde55441267fda2145ad52a16fbb2d9fa63c6ce8f2175086e5a9dda2089bc5890f2c7ed81d8049e491035e0cff5abf178e1dfbbcd1ab7ec47ea8d854419a04f9f8cdd1542c27da97c30e0bea2f4a7710d72346e0c7369202692ba5a43850d5a349d4410155f2bc700a655d2aa57ab9cfa6dd2db0918c4a43a862898f538a011f96f60e25662c66df7ccd173615cfed071632089825c791163fabe",
        .tag = "fe54d31dd99820339ec2e7f4b2bbcb39"
    },
    // Test Vector 5
    {
        .name = "Test Vector 5",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b2735602dd674f9e8227ab7a555fb3588ee61c43cc038ec51cab2dd39f075a518aa054580793f689bb920400f1b769709d75b46",
        .plaintext = "979332e85de4c697d53b3cede5413265ba71ce552bee963a090cd113e32d597bc08b631e7029b54564f132493264afecd67d41016bd73b74e30c87c739e042fa6ca518dccfcd2133be537df0b72cdc8da91d8e14f5c988d8d6109f0ff0e1095c87213856ee5989acac069c643278f1db",
        .ciphertext = "dab94f8fd41ccfef27898e5581c4add205d3ac44b51df43854cb6a10292ea986c9725ea6db27695f7ec1c31299e24f8be1d44953afb66707179cf873e94a273de5fb369ae0314013560e3c597fda5178c254cf457d3dde55441267fda2145ad52a16fbb2d9fa63c6ce8f2175086e5a9d",
        .tag = "28105018df476e2ee537698d758f00df"
    },
    // Test Vector 6
    {
        .name = "Test Vector 6",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "",
        .plaintext = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b2735602dd674f9e8227ab7a555fb3588ee61c43cc038ec51cab2dd39f075a518aa054580793f689bb920400f1b769709d75b46979332e85de4c697d53b3cede5413265ba71ce552bee963a090cd113e32d597bc08b631e7029b54564f132493264afecd67d41016bd73b74e30c87c739e042fa6ca518dccfcd2133be537df0b72cdc8da91d8e14f5c988d8d6109f0ff0e1095c87213856ee5989acac069c643278f1db9680ef8b4978631f88032f78e438d56b5a0dc148674bf513519177840a695fa0",
        .ciphertext = "d716f4983b0025a57cd4c3c3c94a146d6cb665a4a5f33032ae3f86dc1a6caed05243a1cd70688710da9b9bf9b1e3209217cd9eac8632514382d4cfc2d93954a2e3464bd599563524543140c972f65260453d8f2975609fc41960b20ac522fa73ff9fcccf03188954a27c74821b76332bd2490761f9d3e3be14613e91ab0af720cc63177cc72a63eea503bed4cb70b0c42d38551b47b7bbda52f23374a4feea06b8b9c9d3c888935e4a78de02ec329bc866053c77fdabe930f273adc0175802ca31b645d1958afc28806843a671347301130d23a94f3adee985fb2e60f0d5d024dab94f8fd41ccfef27898e5581c4add205d3ac44b51df43854cb6a10292ea986c9725ea6db27695f7ec1c31299e24f8be1d44953afb66707179cf873e94a273de5fb369ae0314013560e3c597fda5178c254cf457d3dde55441267fda2145ad52a16fbb2d9fa63c6ce8f2175086e5a9dda2089bc5890f2c7ed81d8049e491035e0cff5abf178e1dfbbcd1ab7ec47ea8d",
        .tag = "1dd3be970c3d597c333a747f2a978413"
    },
    // Test Vector 7
    {
        .name = "Test Vector 7",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "",
        .plaintext = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c",
        .ciphertext = "d716f4983b0025a57cd4c3c3c94a146d6cb665a4a5f33032ae3f86dc1a6caed05243a1cd70688710da9b9bf9b1e3209217cd9eac8632514382d4cfc2d93954a2e3464bd599563524543140c972f65260453d8f2975609fc41960b20ac522fa73ff9fcccf03188954a27c74821b76332bd2490761f9d3e3be14613e91ab0af720cc63177cc72a63eea503bed4cb70b0c42d38551b47b7bbda52f23374a4feea06",
        .tag = "709a9dae7d9d82b14f3ddf0ab429c2af"
    },
    // Test Vector 8
    {
        .name = "Test Vector 8",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b2735602dd674f9e8227ab7a555fb3588ee61c43cc038ec51cab2dd39f075a518aa054580793f689bb920400f1b769709d75b46",
        .plaintext = "979332e85de4c697d53b3cede5413265ba71ce552bee963a090cd113e32d597bc08b631e7029b54564f132493264afecd67d41016bd73b74e30c87c739e042fa6ca518dccfcd2133be537df0b72cdc8da91d8e14f5c988d8d6109f0ff0e1095c87213856ee5989acac069c643278f1db9680ef8b4978631f88032f78e438d56b5a0dc148674bf513519177840a695fa0e94f2b32c78e524f9181c776b99ce113aaa35c11ee51243fe29cc3ec05238cee72b72039467288d7f34f4dadec2fc096d21ca7c06dcbff5067c33c6ce6c95a58807b91c6ed199ee168eb8e541a4eeaec6b91acd85dac28c46f6531552e8badae063e75f45713d5bffe631419b1fe051c90b2f5ed5e1db1cd82e222b06ecf5f740dd46864e73d23e5a037fe5236046ec6b663b3148164e1034703b4b5d21329dfe79243cecf66b3709eb2c2d4b6309a6c944d8015b16118f864ccad36dfd715c669589438be48a85cfa6a30b09bca1c2f179c44c9fd5cc161296f970846accfaf0463e7c2ab901fa5fa4f55951a71c4310d08fa0a65bc6b8e2b029671ae6520b2c907757497941a92e36f27fde1ec2feef429f959e564e710677e8115e3a1c8aca93d2140d13bd2b4aafab28be6e17ada",
        .ciphertext = "dab94f8fd41ccfef27898e5581c4add205d3ac44b51df43854cb6a10292ea986c9725ea6db27695f7ec1c31299e24f8be1d44953afb66707179cf873e94a273de5fb369ae0314013560e3c597fda5178c254cf457d3dde55441267fda2145ad52a16fbb2d9fa63c6ce8f2175086e5a9dda2089bc5890f2c7ed81d8049e491035e0cff5abf178e1dfbbcd1ab7ec47ea8d854419a04f9f8cdd1542c27da97c30e0bea2f4a7710d72346e0c7369202692ba5a43850d5a349d4410155f2bc700a655d2aa57ab9cfa6dd2db0918c4a43a862898f538a011f96f60e25662c66df7ccd173615cfed071632089825c791163fabe5d64c6912c9df6ab0a4ef97b5c848cf4226172cb26dde45b1f5803b51dcabeb9088430aafd7ef86f75d161db607b6eaea93ceff57bee877b8035f081f17fbb0d38b5258ed3c2a25dd7f1776207e7882d8321b0f1fb6ef6360616c06945f42035e069001b5d20b6a1d7573e53fe89cb61b9dc3e6e4b5b17875550ff2f639fd370e7b89d24db4613bc1dfdc4c06a62a515f1c7df93c4ad8596e9016ba98137814d0dcc3f39306d2a4743d05b429d2b669ad09ac2f2320653fa84e24a3fc456bb652d74782e4d8e7b2412a0c2daeb48db4a",
        .tag = "cf0674e589dbd26a06fec5f9136c7439"
    },
    // Test Vector 9
    {
        .name = "Test Vector 9",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d",
        .plaintext = "855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b2735602dd674f9e8227ab7a555fb3588ee61c43cc038ec51cab2dd39f075a518aa054580793f689bb920400f1b769709d75b46",
        .ciphertext = "17cd9eac8632514382d4cfc2d93954a2e3464bd599563524543140c972f65260453d8f2975609fc41960b20ac522fa73ff9fcccf03188954a27c74821b76332bd2490761f9d3e3be14613e91ab0af720cc63177cc72a63eea503bed4cb70b0c42d38551b47b7bbda52f23374a4feea06b8b9c9d3c888935e4a78de02ec329bc866053c77fdabe930f273adc0175802ca31b645d1958afc28806843a671347301130d23a94f3adee985fb2e60f0d5d024",
        .tag = "e5fc60ac015673741586dc74bb6155ac"
    },
    // Test Vector 10
    {
        .name = "Test Vector 10",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d",
        .plaintext = "855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b2735602dd674f9e8227ab7a555fb3588ee61c43cc038ec51cab2dd39f075a518aa054580793f689bb920400f1b769709d75b46979332e85de4c697d53b3cede5413265ba71ce552bee963a090cd113e32d597bc08b631e7029b54564f132493264afecd67d41016bd73b74e30c87c739e042fa6ca518dccfcd2133be537df0b72cdc8da91d8e14f5c988d8d6109f0ff0e1095c87213856ee5989acac069c643278f1db9680ef8b4978631f88032f78e438d56b5a0dc148674bf513519177840a695fa0e94f2b32c78e524f9181c776b99ce113aaa35c11ee51243fe29cc3ec05238cee72b72039467288d7f34f4dadec2fc096d21ca7c06dcbff5067c33c6ce6c95a58",
        .ciphertext = "17cd9eac8632514382d4cfc2d93954a2e3464bd599563524543140c972f65260453d8f2975609fc41960b20ac522fa73ff9fcccf03188954a27c74821b76332bd2490761f9d3e3be14613e91ab0af720cc63177cc72a63eea503bed4cb70b0c42d38551b47b7bbda52f23374a4feea06b8b9c9d3c888935e4a78de02ec329bc866053c77fdabe930f273adc0175802ca31b645d1958afc28806843a671347301130d23a94f3adee985fb2e60f0d5d024dab94f8fd41ccfef27898e5581c4add205d3ac44b51df43854cb6a10292ea986c9725ea6db27695f7ec1c31299e24f8be1d44953afb66707179cf873e94a273de5fb369ae0314013560e3c597fda5178c254cf457d3dde55441267fda2145ad52a16fbb2d9fa63c6ce8f2175086e5a9dda2089bc5890f2c7ed81d8049e491035e0cff5abf178e1dfbbcd1ab7ec47ea8d854419a04f9f8cdd1542c27da97c30e0bea2f4a7710d72346e0c7369202692ba5a43850d5a349d4410155f2bc700a655d2aa57ab9cfa6dd2db0918c4a43a8628",
        .tag = "a8267a259a0cdbcb92d4687697239390"
    },
    // Test Vector 11: Empty AD and empty plaintext
    {
        .name = "Test Vector 11",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "",
        .plaintext = "",
        .ciphertext = "",
        .tag = "d5057fdfa5a309ce2be6d2651e7232fb"
    },
    // Test Vector 12: Empty AD and 16-byte plaintext
    {
        .name = "Test Vector 12",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "",
        .plaintext = "9fd7339411b6d56373f4a9697200eeaa",
        .ciphertext = "d716f4983b0025a57cd4c3c3c94a146d",
        .tag = "02a6e6a7267c402a3f625522577efe56"
    },
    // Test Vector 13: Empty plaintext and 16-byte AD
    {
        .name = "Test Vector 13",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "9fd7339411b6d56373f4a9697200eeaa",
        .plaintext = "",
        .ciphertext = "",
        .tag = "891b7b5e3d8f8ed8e80e2da57af4cb4d"
    }
};

static const size_t num_test_vectors = sizeof(test_vectors) / sizeof(test_vectors[0]);

// Run a single test vector
static int run_test_vector(const TestVector* tv) {
    uint8_t key[32], nonce[16], tag[16];
    uint8_t ad[2048], plaintext[2048], ciphertext[2048];
    uint8_t computed_ciphertext[2048], computed_tag[16];
    uint8_t decrypted[2048];
    
    // Parse inputs
    if (hex_to_bytes(tv->key, key, sizeof(key)) != 32) {
        printf("  ERROR: Failed to parse key\n");
        return 0;
    }
    
    if (hex_to_bytes(tv->nonce, nonce, sizeof(nonce)) != 16) {
        printf("  ERROR: Failed to parse nonce\n");
        return 0;
    }
    
    int ad_len = hex_to_bytes(tv->ad, ad, sizeof(ad));
    if (ad_len < 0) {
        printf("  ERROR: Failed to parse AD\n");
        return 0;
    }
    
    int pt_len = hex_to_bytes(tv->plaintext, plaintext, sizeof(plaintext));
    if (pt_len < 0) {
        printf("  ERROR: Failed to parse plaintext\n");
        return 0;
    }
    
    int ct_len = hex_to_bytes(tv->ciphertext, ciphertext, sizeof(ciphertext));
    if (ct_len < 0 || ct_len != pt_len) {
        printf("  ERROR: Failed to parse ciphertext or length mismatch\n");
        return 0;
    }
    
    if (hex_to_bytes(tv->tag, tag, sizeof(tag)) != 16) {
        printf("  ERROR: Failed to parse tag\n");
        return 0;
    }
    
    // Test encryption
    HiAE_AEAD_encrypt(key, nonce, plaintext, computed_ciphertext, pt_len, ad, ad_len, computed_tag);
    
    // Verify ciphertext
    if (memcmp(computed_ciphertext, ciphertext, ct_len) != 0) {
        printf("  ERROR: Ciphertext mismatch\n");
        printf("  Expected: ");
        print_hex("", ciphertext, ct_len > 32 ? 32 : ct_len);
        if (ct_len > 32) printf("  ...\n");
        printf("  Computed: ");
        print_hex("", computed_ciphertext, ct_len > 32 ? 32 : ct_len);
        if (ct_len > 32) printf("  ...\n");
        return 0;
    }
    
    // Verify tag
    if (memcmp(computed_tag, tag, 16) != 0) {
        printf("  ERROR: Tag mismatch\n");
        print_hex("  Expected", tag, 16);
        print_hex("  Computed", computed_tag, 16);
        return 0;
    }
    
    // Test decryption
    int auth_result = HiAE_AEAD_decrypt(key, nonce, decrypted, ciphertext, ct_len, ad, ad_len, tag);
    
    if (auth_result != 0) {
        printf("  ERROR: Authentication failed during decryption (returned %d)\n", auth_result);
        return 0;
    }
    
    if (memcmp(decrypted, plaintext, pt_len) != 0) {
        printf("  ERROR: Decrypted plaintext mismatch\n");
        return 0;
    }
    
    return 1;
}

int main() {
    printf("========================================\n");
    printf("HiAE IETF Test Vector Validation\n");
    printf("Test vectors from draft-pham-cfrg-hiae.md\n");
    printf("========================================\n\n");
    
    int passed = 0;
    int failed = 0;
    
    for (size_t i = 0; i < num_test_vectors; i++) {
        const TestVector* tv = &test_vectors[i];
        printf("%s:\n", tv->name);
        printf("  AD length: %zu bytes\n", strlen(tv->ad) / 2);
        printf("  Message length: %zu bytes\n", strlen(tv->plaintext) / 2);
        
        if (run_test_vector(tv)) {
            printf("  PASSED\n");
            passed++;
        } else {
            printf("  FAILED\n");
            failed++;
        }
        printf("\n");
    }
    
    printf("========================================\n");
    printf("Summary: %d passed, %d failed\n", passed, failed);
    printf("========================================\n");
    
    return failed > 0 ? 1 : 0;
}
