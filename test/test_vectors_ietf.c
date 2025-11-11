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
        .ciphertext = "fe70c630cc9c965f092dbdad0463778a8adf8065833f4d61303f65870e5b6e264a22b491d4dd8e28384bbb34149ef9312b2e4d1623dff31674b4768a8d34e605128b1ed7157fdcf927cd9e7d8d448cfd6c804d11b41607cf6be320835f627c82ae26b718908b9323b41a9b555ada2c9367bc3e4a228ac5c64d8521c5114fee00",
        .tag = "2197de38ddcf5bd57cfb6436c056d16d"
    },
    // Test Vector 2
    {
        .name = "Test Vector 2",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d",
        .plaintext = "855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b2735602dd674f9e8227ab7a555fb3588ee61c43cc038ec51cab2dd39f075a518aa054580793f689bb920400f1b769709d75b46979332e85de4c697d53b3cede5413265ba71ce552bee963a090cd113e32d597bc08b631e7029b54564f132493264afecd67d41016bd73b74e30c87c739e042fa6ca518dccfcd2133be537df0b72cdc8da91d8e14f5c988d8d6109f0ff0e1095c87213856ee5989acac069c643278f1db9680ef8b4978631f88032f78e438d56b5a0dc148674bf513519177840a695fa0e94f2b32c78e524f9181c776b99ce113aaa35c11ee51243fe29cc3ec05238cee72b72039467288d7f34f4dadec2fc096d21ca7c06dcbff5067c33c6ce6c95a58",
        .ciphertext = "c1d6435b193601ffe6118a45d42afce974c5f53731d6d8800be331922728f9ebabb50488e10008295a578d10333152cbfe70c630cc9c965f092dbdad0463778a8adf8065833f4d61303f65870e5b6e264a22b491d4dd8e28384bbb34149ef9312b2e4d1623dff31674b4768a8d34e605128b1ed7157fdcf927cd9e7d8d448cfd6c804d11b41607cf6be320835f627c82ae26b718908b9323b41a9b555ada2c9367bc3e4a228ac5c64d8521c5114fee00aab61e4bd37148237511519d08633d261f8eae3dbd946d7e115bd52cd9112b37d9135fd52d2ec92bca4975952cd59e59ef5d734f84208c1ef58d5c4fbf7af992da8786326e8c570a629d654fb515d3c379e50cf728e9c21186b0259a5f60754ab4f991bd52f8813df90a660ce2cbdec27e61bc77fee1321e0b23b13d2f308629ecce9ca79a4934b92abfdc5c5c67829f9775b481c1c2e5a485b0257b621fb8819b59aa58e16224f031dfe76f79735a4f27ca1179f914a4e2c65514c6bbd24ff17aa253b93154ca80f6136839cb882113",
        .tag = "e398c17a2fce501dd0b8b102e257beb1"
    },
    // Test Vector 3
    {
        .name = "Test Vector 3",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b273560",
        .plaintext = "2dd674f9e8227ab7a555fb3588ee61c4",
        .ciphertext = "6c804d11b41607cf6be320835f627c82",
        .tag = "0cee7cb493af6ad1a52a5efab3105cce"
    },
    // Test Vector 4
    {
        .name = "Test Vector 4",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "",
        .plaintext = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b2735602dd674f9e8227ab7a555fb3588ee61c43cc038ec51cab2dd39f075a518aa054580793f689bb920400f1b769709d75b46979332e85de4c697d53b3cede5413265ba71ce552bee963a090cd113e32d597bc08b631e7029b54564f132493264afecd67d41016bd73b74e30c87c739e042fa6ca518dccfcd2133be537df0b72cdc8da91d8e14f5c988d8d6109f0ff0e1095c87213856ee5989acac069c643278f1db9680ef8b4978631f88032f78e438d56b5a0dc148674bf513519177840a695fa0e94f2b32c78e524f9181c776b99ce113aaa35c11ee51243fe29cc3ec05238cee72b72039467288d7f34f4dadec2fc096d21ca7c06dcbff5067c33c6ce6c95a58807b91c6ed199ee168eb8e541a4eeaec6b91acd85dac28c46f6531552e8badae",
        .ciphertext = "09d473dbc6278d2d65ff3caad126104ff04ab6d39c2048e37d53d52ac737a449825ab7e188be7f0912fb4ff6ef82fb82c1d6435b193601ffe6118a45d42afce974c5f53731d6d8800be331922728f9ebabb50488e10008295a578d10333152cbfe70c630cc9c965f092dbdad0463778a8adf8065833f4d61303f65870e5b6e264a22b491d4dd8e28384bbb34149ef9312b2e4d1623dff31674b4768a8d34e605128b1ed7157fdcf927cd9e7d8d448cfd6c804d11b41607cf6be320835f627c82ae26b718908b9323b41a9b555ada2c9367bc3e4a228ac5c64d8521c5114fee00aab61e4bd37148237511519d08633d261f8eae3dbd946d7e115bd52cd9112b37d9135fd52d2ec92bca4975952cd59e59ef5d734f84208c1ef58d5c4fbf7af992da8786326e8c570a629d654fb515d3c379e50cf728e9c21186b0259a5f60754ab4f991bd52f8813df90a660ce2cbdec27e61bc77fee1321e0b23b13d2f308629ecce9ca79a4934b92abfdc5c5c67829f9775b481c1c2e5a485b0257b621fb8819b59aa58e16224f031dfe76f79735a4f27ca1179f914a4e2c65514c6bbd24ff17aa253b93154ca80f6136839cb8821136b677f0a17cbe6cc03e05d68850f9500e37a34429519b19dff477d3882e7845d",
        .tag = "a0f16003338700105956ad446ed7357f"
    },    
    // Test Vector 5
    {
        .name = "Test Vector 5",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b2735602dd674f9e8227ab7a555fb3588ee61c43cc038ec51cab2dd39f075a518aa054580793f689bb920400f1b769709d75b46",
        .plaintext = "979332e85de4c697d53b3cede5413265ba71ce552bee963a090cd113e32d597bc08b631e7029b54564f132493264afecd67d41016bd73b74e30c87c739e042fa6ca518dccfcd2133be537df0b72cdc8da91d8e14f5c988d8d6109f0ff0e1095c87213856ee5989acac069c643278f1db",
        .ciphertext = "aab61e4bd37148237511519d08633d261f8eae3dbd946d7e115bd52cd9112b37d9135fd52d2ec92bca4975952cd59e59ef5d734f84208c1ef58d5c4fbf7af992da8786326e8c570a629d654fb515d3c379e50cf728e9c21186b0259a5f60754ab4f991bd52f8813df90a660ce2cbdec2",
        .tag = "2bdc925c4bddcd8250eca6ef4f0f5e62"
    },
    // Test Vector 6
    {
        .name = "Test Vector 6",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "",
        .plaintext = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b2735602dd674f9e8227ab7a555fb3588ee61c43cc038ec51cab2dd39f075a518aa054580793f689bb920400f1b769709d75b46979332e85de4c697d53b3cede5413265ba71ce552bee963a090cd113e32d597bc08b631e7029b54564f132493264afecd67d41016bd73b74e30c87c739e042fa6ca518dccfcd2133be537df0b72cdc8da91d8e14f5c988d8d6109f0ff0e1095c87213856ee5989acac069c643278f1db9680ef8b4978631f88032f78e438d56b5a0dc148674bf513519177840a695fa0",
        .ciphertext = "09d473dbc6278d2d65ff3caad126104ff04ab6d39c2048e37d53d52ac737a449825ab7e188be7f0912fb4ff6ef82fb82c1d6435b193601ffe6118a45d42afce974c5f53731d6d8800be331922728f9ebabb50488e10008295a578d10333152cbfe70c630cc9c965f092dbdad0463778a8adf8065833f4d61303f65870e5b6e264a22b491d4dd8e28384bbb34149ef9312b2e4d1623dff31674b4768a8d34e605128b1ed7157fdcf927cd9e7d8d448cfd6c804d11b41607cf6be320835f627c82ae26b718908b9323b41a9b555ada2c9367bc3e4a228ac5c64d8521c5114fee00aab61e4bd37148237511519d08633d261f8eae3dbd946d7e115bd52cd9112b37d9135fd52d2ec92bca4975952cd59e59ef5d734f84208c1ef58d5c4fbf7af992da8786326e8c570a629d654fb515d3c379e50cf728e9c21186b0259a5f60754ab4f991bd52f8813df90a660ce2cbdec27e61bc77fee1321e0b23b13d2f308629ecce9ca79a4934b92abfdc5c5c67829f",
        .tag = "001705aeeb42e3476f29f744ce310448"
    },
    // Test Vector 7
    {
        .name = "Test Vector 7",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "",
        .plaintext = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c",
        .ciphertext = "09d473dbc6278d2d65ff3caad126104ff04ab6d39c2048e37d53d52ac737a449825ab7e188be7f0912fb4ff6ef82fb82c1d6435b193601ffe6118a45d42afce974c5f53731d6d8800be331922728f9ebabb50488e10008295a578d10333152cbfe70c630cc9c965f092dbdad0463778a8adf8065833f4d61303f65870e5b6e264a22b491d4dd8e28384bbb34149ef9312b2e4d1623dff31674b4768a8d34e605",
        .tag = "a682de1a42fa85b1f41303a7c15aa3e7"
    },
    // Test Vector 8
    {
        .name = "Test Vector 8",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b2735602dd674f9e8227ab7a555fb3588ee61c43cc038ec51cab2dd39f075a518aa054580793f689bb920400f1b769709d75b46",
        .plaintext = "979332e85de4c697d53b3cede5413265ba71ce552bee963a090cd113e32d597bc08b631e7029b54564f132493264afecd67d41016bd73b74e30c87c739e042fa6ca518dccfcd2133be537df0b72cdc8da91d8e14f5c988d8d6109f0ff0e1095c87213856ee5989acac069c643278f1db9680ef8b4978631f88032f78e438d56b5a0dc148674bf513519177840a695fa0e94f2b32c78e524f9181c776b99ce113aaa35c11ee51243fe29cc3ec05238cee72b72039467288d7f34f4dadec2fc096d21ca7c06dcbff5067c33c6ce6c95a58807b91c6ed199ee168eb8e541a4eeaec6b91acd85dac28c46f6531552e8badae063e75f45713d5bffe631419b1fe051c90b2f5ed5e1db1cd82e222b06ecf5f740dd46864e73d23e5a037fe5236046ec6b663b3148164e1034703b4b5d21329dfe79243cecf66b3709eb2c2d4b6309a6c944d8015b16118f864ccad36dfd715c669589438be48a85cfa6a30b09bca1c2f179c44c9fd5cc161296f970846accfaf0463e7c2ab901fa5fa4f55951a71c4310d08fa0a65bc6b8e2b029671ae6520b2c907757497941a92e36f27fde1ec2feef429f959e564e710677e8115e3a1c8aca93d2140d13bd2b4aafab28be6e17ada",
        .ciphertext = "aab61e4bd37148237511519d08633d261f8eae3dbd946d7e115bd52cd9112b37d9135fd52d2ec92bca4975952cd59e59ef5d734f84208c1ef58d5c4fbf7af992da8786326e8c570a629d654fb515d3c379e50cf728e9c21186b0259a5f60754ab4f991bd52f8813df90a660ce2cbdec27e61bc77fee1321e0b23b13d2f308629ecce9ca79a4934b92abfdc5c5c67829f9775b481c1c2e5a485b0257b621fb8819b59aa58e16224f031dfe76f79735a4f27ca1179f914a4e2c65514c6bbd24ff17aa253b93154ca80f6136839cb8821136b677f0a17cbe6cc03e05d68850f9500e37a34429519b19dff477d3882e7845d6f6bab65d787602540b7357001f8e3f40a2d967882134f6dd808d577075f35db3aef0028706a490af583b2cf76a5d0cac489440c0613413e5e41cc0697be6060f4197f665ee3ae5e368fa137e208cde24a0f2e88d68aeb79eeaa37d62812e4b163fd5e06ce497b81129ec69728c4c6c3a03ec8b625ce130b0e7ba7ec85c215d87b9e9c971559cb281e80f66691696f72eb23de03ceee624e41c8b3f2cde3ea1a3516725c1c47f209cdbdee95849739297685363ebfb8ff70db613a4c0bcab9f40d0b3b7af0d08fa25827021bafade565",
        .tag = "d819e1ec0e3bfed35538d710fa32cbb8"
    },
    // Test Vector 9
    {
        .name = "Test Vector 9",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d",
        .plaintext = "855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b2735602dd674f9e8227ab7a555fb3588ee61c43cc038ec51cab2dd39f075a518aa054580793f689bb920400f1b769709d75b46",
        .ciphertext = "c1d6435b193601ffe6118a45d42afce974c5f53731d6d8800be331922728f9ebabb50488e10008295a578d10333152cbfe70c630cc9c965f092dbdad0463778a8adf8065833f4d61303f65870e5b6e264a22b491d4dd8e28384bbb34149ef9312b2e4d1623dff31674b4768a8d34e605128b1ed7157fdcf927cd9e7d8d448cfd6c804d11b41607cf6be320835f627c82ae26b718908b9323b41a9b555ada2c9367bc3e4a228ac5c64d8521c5114fee00",
        .tag = "5dba71e7e11cb772588c195e0cd951cd"
    },
    // Test Vector 10
    {
        .name = "Test Vector 10",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d",
        .plaintext = "855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b2735602dd674f9e8227ab7a555fb3588ee61c43cc038ec51cab2dd39f075a518aa054580793f689bb920400f1b769709d75b46979332e85de4c697d53b3cede5413265ba71ce552bee963a090cd113e32d597bc08b631e7029b54564f132493264afecd67d41016bd73b74e30c87c739e042fa6ca518dccfcd2133be537df0b72cdc8da91d8e14f5c988d8d6109f0ff0e1095c87213856ee5989acac069c643278f1db9680ef8b4978631f88032f78e438d56b5a0dc148674bf513519177840a695fa0e94f2b32c78e524f9181c776b99ce113aaa35c11ee51243fe29cc3ec05238cee72b72039467288d7f34f4dadec2fc096d21ca7c06dcbff5067c33c6ce6c95a58",
        .ciphertext = "c1d6435b193601ffe6118a45d42afce974c5f53731d6d8800be331922728f9ebabb50488e10008295a578d10333152cbfe70c630cc9c965f092dbdad0463778a8adf8065833f4d61303f65870e5b6e264a22b491d4dd8e28384bbb34149ef9312b2e4d1623dff31674b4768a8d34e605128b1ed7157fdcf927cd9e7d8d448cfd6c804d11b41607cf6be320835f627c82ae26b718908b9323b41a9b555ada2c9367bc3e4a228ac5c64d8521c5114fee00aab61e4bd37148237511519d08633d261f8eae3dbd946d7e115bd52cd9112b37d9135fd52d2ec92bca4975952cd59e59ef5d734f84208c1ef58d5c4fbf7af992da8786326e8c570a629d654fb515d3c379e50cf728e9c21186b0259a5f60754ab4f991bd52f8813df90a660ce2cbdec27e61bc77fee1321e0b23b13d2f308629ecce9ca79a4934b92abfdc5c5c67829f9775b481c1c2e5a485b0257b621fb8819b59aa58e16224f031dfe76f79735a4f27ca1179f914a4e2c65514c6bbd24ff17aa253b93154ca80f6136839cb882113",
        .tag = "e398c17a2fce501dd0b8b102e257beb1"
    },
    // Test Vector 11: Empty AD and empty plaintext
    {
        .name = "Test Vector 11",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "",
        .plaintext = "",
        .ciphertext = "",
        .tag = "8300c4f515fd521f14847c434b8f7112"
    },
    // Test Vector 12: Empty AD and 16-byte plaintext
    {
        .name = "Test Vector 12",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "",
        .plaintext = "9fd7339411b6d56373f4a9697200eeaa",
        .ciphertext = "09d473dbc6278d2d65ff3caad126104f",
        .tag = "867ae4bb2374d028d504f053522b11c3"
    },
    // Test Vector 13: Empty plaintext and 16-byte AD
    {
        .name = "Test Vector 13",
        .key = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
        .nonce = "381d72b1a195e7f3dc185a35eedb6326",
        .ad = "9fd7339411b6d56373f4a9697200eeaa",
        .plaintext = "",
        .ciphertext = "",
        .tag = "548e7ff03203fe6fd097a21086e21ee6"
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
        printf("=======================================\n");
        //print all computed ciphertext
        printf("  Full Computed Ciphertext: ");
        print_hex("", computed_ciphertext, ct_len);

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
