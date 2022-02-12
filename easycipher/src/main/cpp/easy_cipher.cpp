#include <jni.h>
#include <cstdlib>

#include "aes_cbc.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include "rsa.h"
#include "ecc.h"

void throwIllegalArgumentException(JNIEnv *env, const char *message) {
    env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"), message);
}

void throwIllegalStateException(JNIEnv *env, const char *message) {
    env->ThrowNew(env->FindClass("java/lang/IllegalStateException"), message);
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_io_easycipher_EasyAES_crypt(
        JNIEnv *env,
        jclass type,
        jbyteArray input,
        jbyteArray key,
        jbyteArray iv,
        jboolean isEncrypt) {
    if (key == nullptr) {
        throwIllegalArgumentException(env, "key is null");
        return nullptr;
    }
    int keyLen = env->GetArrayLength(key);
    if (keyLen != 16 && keyLen != 32) {
        throwIllegalArgumentException(env, "Only support the key with 16/32 bytes");
        return nullptr;
    }
    if (iv == nullptr || env->GetArrayLength(iv) != 16) {
        throwIllegalArgumentException(env, "iv's length must be 16");
        return nullptr;
    }

    if (input == nullptr) {
        return nullptr;
    }

    int inputLen = env->GetArrayLength(input);
    if (!isEncrypt && (inputLen < 16 || ((inputLen & 15) != 0))) {
        throwIllegalArgumentException(env, "Illegal block size");
        return nullptr;
    }

    jbyte *p_key = env->GetByteArrayElements(key, JNI_FALSE);
    jbyte *p_iv = env->GetByteArrayElements(iv, JNI_FALSE);
    jbyte *p_input = env->GetByteArrayElements(input, JNI_FALSE);
    if (p_key == nullptr || p_iv == nullptr || p_input == nullptr) {
        throwIllegalStateException(env, "Get params failed");
        return nullptr;
    }

    ByteArray content;
    content.value = (uint8_t *) p_input;
    content.len = inputLen;

    ByteArray aesKey;
    aesKey.value = (uint8_t *) p_key;
    aesKey.len = keyLen;

    ByteArray cipher;
    if (isEncrypt) {
        cipher = aes_cbc_encrypt(&aesKey, (uint8_t *) p_iv, &content);
    } else {
        cipher = aes_cbc_decrypt(&aesKey, (uint8_t *) p_iv, &content);
    }

    env->ReleaseByteArrayElements(input, p_input, 0);
    env->ReleaseByteArrayElements(key, p_key, 0);
    env->ReleaseByteArrayElements(iv, p_iv, 0);

    if (cipher.value != nullptr) {
        jbyteArray result = env->NewByteArray(cipher.len);
        env->SetByteArrayRegion(result, 0, cipher.len, (jbyte *) cipher.value);
        free(cipher.value);
        return result;
    } else {
        if (isEncrypt) {
            throwIllegalStateException(env, "encrypt failed");
        } else {
            if (cipher.len == 0) {
                throwIllegalStateException(env, "decrypt failed");
            } else {
                throwIllegalArgumentException(env, "Bad padding");
            }
        }
        return nullptr;
    }
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_io_easycipher_EasySHA_sha256(JNIEnv *env, jclass clazz, jbyteArray input) {
    if (input == nullptr) {
        throwIllegalArgumentException(env, "input is null");
        return nullptr;
    }

    int inputLen = env->GetArrayLength(input);
    jbyte *p_input = env->GetByteArrayElements(input, JNI_FALSE);
    if (p_input == nullptr) {
        throwIllegalStateException(env, "Get params failed");
        return nullptr;
    }

    BYTE buf[SHA256_DIGEST_LEN];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (BYTE *) p_input, inputLen);
    sha256_final(&ctx, buf);

    env->ReleaseByteArrayElements(input, p_input, 0);

    jbyteArray result = env->NewByteArray(SHA256_DIGEST_LEN);
    env->SetByteArrayRegion(result, 0, SHA256_DIGEST_LEN, (jbyte *) buf);
    return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_io_easycipher_EasySHA_hmacSHA256(JNIEnv *env, jclass clazz, jbyteArray input,
                                      jbyteArray key) {
    if (input == nullptr) {
        throwIllegalArgumentException(env, "input is null");
        return nullptr;
    }
    if (key == nullptr) {
        throwIllegalArgumentException(env, "key is null");
        return nullptr;
    }
    int keyLen = env->GetArrayLength(key);
    if (keyLen == 0) {
        throwIllegalArgumentException(env, "key is empty");
        return nullptr;
    }

    int inputLen = env->GetArrayLength(input);
    jbyte *p_input = env->GetByteArrayElements(input, JNI_FALSE);
    jbyte *p_key = env->GetByteArrayElements(key, JNI_FALSE);
    if (p_input == nullptr || p_key == nullptr) {
        throwIllegalStateException(env, "Get params failed");
        return nullptr;
    }

    ByteArray inputArray;
    inputArray.value = (uint8_t *) p_input;
    inputArray.len = inputLen;

    ByteArray keyArray;
    keyArray.value = (uint8_t *) p_key;
    keyArray.len = keyLen;

    BYTE mac[SHA256_DIGEST_LEN];
    hmac_sha256(&inputArray, &keyArray, mac);

    env->ReleaseByteArrayElements(input, p_input, 0);
    env->ReleaseByteArrayElements(key, p_key, 0);

    jbyteArray result = env->NewByteArray(SHA256_DIGEST_LEN);
    env->SetByteArrayRegion(result, 0, SHA256_DIGEST_LEN, (jbyte *) mac);
    return result;
}


extern "C"
JNIEXPORT jbyteArray JNICALL
Java_io_easycipher_EasyRSA_crypt(JNIEnv *env,
                                 jclass clazz,
                                 jbyteArray input,
                                 jbyteArray exponent,
                                 jbyteArray modulus,
                                 jboolean isPrivate,
                                 jboolean isEncrypt) {
    if (input == nullptr || exponent == nullptr || modulus == nullptr) {
        throwIllegalArgumentException(env, "params can't be null");
        return nullptr;
    }

    int inputLen = env->GetArrayLength(input);
    int expLen = env->GetArrayLength(exponent);
    int modLen = env->GetArrayLength(modulus);

    if (modLen == 0 || expLen == 0) {
        throwIllegalArgumentException(env, "invalid param");
        return nullptr;
    }

    if (inputLen == 0) {
        return input;
    }

    jbyte *p_input = env->GetByteArrayElements(input, JNI_FALSE);
    jbyte *p_exp = env->GetByteArrayElements(exponent, JNI_FALSE);
    jbyte *p_mod = env->GetByteArrayElements(modulus, JNI_FALSE);
    if (p_input == nullptr || p_exp == nullptr || p_mod == nullptr) {
        throwIllegalArgumentException(env, "Get params failed");
        return nullptr;
    }

    ByteArray in, exp, mod, out;
    in.value = (uint8_t *) p_input;
    in.len = inputLen;
    exp.value = (uint8_t *) p_exp;
    exp.len = expLen;
    mod.value = (uint8_t *) p_mod;
    mod.len = modLen;

    uint8_t buffer[256];
    out.value = buffer;
    out.len = 0;

    RSAKey key;
    key.exponent = &exp;
    key.modulus = &mod;
    key.key_type = isPrivate ? PRIVATE_KEY : PUBLIC_KEY;
    CipherMode mode = isEncrypt ? ENCRYPT : DECRYPT;

    int ret = rsa_crypt(&in, &key, mode, &out);

    env->ReleaseByteArrayElements(input, p_input, 0);
    env->ReleaseByteArrayElements(exponent, p_exp, 0);
    env->ReleaseByteArrayElements(modulus, p_mod, 0);

    if (ret == CRYPT_SUCCESS) {
        jsize len = out.len;
        jbyteArray result = env->NewByteArray(len);
        env->SetByteArrayRegion(result, 0, len, (jbyte *) out.value);
        return result;
    } else {
        if (ret == FAILED_INVALID_KEY) {
            throwIllegalArgumentException(env, "invalid key");
        } else if (ret == FAILED_INPUT_TOO_LARGE) {
            throwIllegalArgumentException(env, "input too large");
        } else if (ret == FAILED_INVALID_INPUT) {
            throwIllegalArgumentException(env, "invalid input");
        } else if (ret == FAILED_OUT_OF_MEMORY) {
            throwIllegalStateException(env, "out of memory");
        } else {
            throwIllegalStateException(env, "crypt failed");
        }
        return nullptr;
    }
}


extern "C"
JNIEXPORT jbyteArray JNICALL
Java_io_easycipher_EasyECC_makeKey(JNIEnv *env, jclass type) {
    int totalLen = ECC_PUBLIC_KEY_LEN + ECC_PRIVATE_KEY_LEN;
    uint8_t p_key[totalLen];
    uint8_t *p_pub = p_key;
    uint8_t *p_pri = p_key + ECC_PUBLIC_KEY_LEN;
    int success = ecc_make_key(p_pub, p_pri);
    if (success == 0) {
        return nullptr;
    }
    jbyteArray result = env->NewByteArray(totalLen);
    env->SetByteArrayRegion(result, 0, totalLen, (jbyte *) p_key);
    return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_io_easycipher_EasyECC_ecdhSecret(JNIEnv *env, jclass type,
                                      jbyteArray public_key,
                                      jbyteArray private_key) {
    if (public_key == nullptr || env->GetArrayLength(public_key) != ECC_PUBLIC_KEY_LEN ||
        private_key == nullptr || env->GetArrayLength(private_key) != ECC_PRIVATE_KEY_LEN) {
        throwIllegalArgumentException(env, "Invalid Key");
        return nullptr;
    }

    jbyte *pub_key = env->GetByteArrayElements(public_key, nullptr);
    jbyte *pri_key = env->GetByteArrayElements(private_key, nullptr);

    uint8_t secret[ECC_BYTES];
    int success = ecdh_shared_secret((uint8_t *) pub_key, (uint8_t *) pri_key, secret);

    env->ReleaseByteArrayElements(private_key, pri_key, 0);
    env->ReleaseByteArrayElements(public_key, pub_key, 0);

    if (success == 0) {
        return nullptr;
    }

    jbyteArray result = env->NewByteArray(ECC_BYTES);
    env->SetByteArrayRegion(result, 0, ECC_BYTES, (jbyte *) secret);
    return result;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_io_easycipher_EasyECC_ecdsaSign(JNIEnv *env, jclass clazz, jbyteArray private_key,
                                     jbyteArray hash) {
    if (env->GetArrayLength(private_key) != ECC_PRIVATE_KEY_LEN) {
        throwIllegalArgumentException(env,  "Invalid key");
        return nullptr;
    }
    if (env->GetArrayLength(hash) != ECC_HASH_LEN) {
        throwIllegalArgumentException(env,  "Invalid hash");
        return nullptr;
    }

    jbyte *pri_key = env->GetByteArrayElements(private_key, nullptr);
    jbyte *p_hash = env->GetByteArrayElements(hash, nullptr);

    uint8_t signature[ECC_SIGNATURE_LEN];
    int success = ecdsa_sign((uint8_t *) pri_key, (uint8_t *) p_hash, signature);

    env->ReleaseByteArrayElements(private_key, pri_key, 0);
    env->ReleaseByteArrayElements(hash, p_hash, 0);

    if (success == 0) {
        return nullptr;
    }

    jbyteArray result = env->NewByteArray(ECC_SIGNATURE_LEN);
    env->SetByteArrayRegion(result, 0, ECC_SIGNATURE_LEN, (jbyte *) signature);
    return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_io_easycipher_EasyECC_ecdsaVerify(JNIEnv *env, jclass clazz, jbyteArray public_key,
                                       jbyteArray hash, jbyteArray signature) {
    if (env->GetArrayLength(public_key) != ECC_PUBLIC_KEY_LEN) {
        throwIllegalArgumentException(env, "Invalid key");
        return false;
    }
    if (env->GetArrayLength(hash) != ECC_HASH_LEN) {
        throwIllegalArgumentException(env,  "Invalid hash");
        return false;
    }
    if (env->GetArrayLength(signature) != ECC_SIGNATURE_LEN) {
        throwIllegalArgumentException(env, "Invalid signature");
        return false;
    }

    jbyte *pub_key = env->GetByteArrayElements(public_key, nullptr);
    jbyte *p_hash = env->GetByteArrayElements(hash, nullptr);
    jbyte *p_sign = env->GetByteArrayElements(signature, nullptr);

    int success = ecdsa_verify((uint8_t *) pub_key, (uint8_t *) p_hash, (uint8_t *) p_sign);

    env->ReleaseByteArrayElements(public_key, pub_key, 0);
    env->ReleaseByteArrayElements(hash, p_hash, 0);
    env->ReleaseByteArrayElements(signature, p_sign, 0);

    return success != 0;
}