

#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#ifdef __cplusplus
extern "C" {
#endif

#include "array.h"

void hmac_sha256(ByteArray *input, ByteArray *key, uint8_t mac[SHA256_DIGEST_LEN]);

#ifdef __cplusplus
}
#endif

#endif //HMAC_SHA256_H
