
#ifndef _EASY_RSA_H_
#define _EASY_RSA_H_

#include <stdint.h>
#include "array.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CRYPT_SUCCESS = 1,
    FAILED_UNKNOWN,
    FAILED_OUT_OF_MEMORY,
    FAILED_INVALID_KEY,
    FAILED_INPUT_TOO_LARGE,
    FAILED_INVALID_INPUT,
} CryptResult;

typedef enum {
    ENCRYPT,
    DECRYPT
} CipherMode;

typedef enum {
    PRIVATE_KEY = 1,
    PUBLIC_KEY = 2
} KeyType;

typedef struct {
    ByteArray *exponent;
    ByteArray *modulus;
    KeyType key_type;
} RSAKey;


/**
 * @param input : bytes to encrypt/decrypt.
 * @param key : The RSAKey.
 * @param mode : cipher mode.
 * @param output : The result will place this param,
 *        be sure it's 'value' point the a space equal or large the modulus.
 * @return The crypt result, an enum value.
 */
CryptResult rsa_crypt(const ByteArray *input,const RSAKey *key, const CipherMode mode, ByteArray *output);

#ifdef __cplusplus
}
#endif

#endif