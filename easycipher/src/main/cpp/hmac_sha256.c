
#include <stdlib.h>
#include "string.h"

#include "sha256.h"
#include "hmac_sha256.h"

#define SHA256_BLOCK_SIZE  64

void xor_key(uint8_t *ikey, uint8_t *okey, const uint8_t *key, int len) {
    int n = len >> 3;
    int remain = len & 7;
    uint64_t *p_ikey = (uint64_t *) ikey;
    uint64_t *p_okey = (uint64_t *) okey;
    for (int i = 0; i < n; i++) {
        uint64_t x = ((uint64_t *) key)[i];
        p_ikey[i] ^= x;
        p_okey[i] ^= x;
    }
    for (int i = len - remain; i < len; i++) {
        uint8_t x = key[i];
        ikey[i] ^= x;
        okey[i] ^= x;
    }
}

void hmac_sha256(ByteArray *input, ByteArray *key, uint8_t mac[SHA256_DIGEST_LEN]) {
    uint8_t ikey[SHA256_BLOCK_SIZE];
    uint8_t okey[SHA256_BLOCK_SIZE];
    uint8_t buffer[SHA256_DIGEST_LEN];
    SHA256_CTX ctx;

    uint64_t *p_ikey = (uint64_t *) ikey;
    uint64_t *p_okey = (uint64_t *) okey;
    int n = SHA256_BLOCK_SIZE >> 3;
    for (int i = 0; i < n; i++) {
        p_ikey[i] = 0x3636363636363636L; // 0x36 00110110
        p_okey[i] = 0x5c5c5c5c5c5c5c5cL; // 0x5c 01011100
    }

    if (key->len <= SHA256_BLOCK_SIZE) {
        xor_key(ikey, okey, key->value, key->len);
    } else {
        sha256_init(&ctx);
        sha256_update(&ctx, key->value, key->len);
        sha256_final(&ctx, buffer);
        xor_key(ikey, okey, buffer, SHA256_DIGEST_LEN);
    }

    sha256_init(&ctx);
    sha256_update(&ctx, ikey, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, input->value, input->len);
    sha256_final(&ctx, buffer);

    sha256_init(&ctx);
    sha256_update(&ctx, okey, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, buffer, SHA256_DIGEST_LEN);
    sha256_final(&ctx, mac);
}
