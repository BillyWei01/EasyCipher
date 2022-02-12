package io.easycipher;

public class EasyRSA extends Cipher {
    /**
     * Encrypt bytes with RSA/ECB/PKCS1Padding.
     *
     * @param input The bytes to encrypt.
     *              The input length must less or equal than (blockSize - 11),
     *              blockSize may be 128 or 256 bytes.
     * @param key The RSA private/public key, only accept the key with 1024 or 2048 bits.
     * @return The encoded bytes.
     * @throws IllegalArgumentException If the input or key is illegal.
     * @throws IllegalStateException If some error happened.
     */
    public static byte[] encrypt(byte[] input, RSAKey key) {
        checkParam(input, key);
        return crypt(input, key.exponent, key.modulus, key.isPrivate, true);
    }

    /**
     * Decrypt bytes with RSA/ECB/PKCS1Padding.
     *
     * @param input The bytes to decrypt.
     *              The input length must less or equal than (blockSize - 11),
     *              blockSize may be 128 or 256 bytes.
     * @param key The RSA private/public key, only accept the key with 1024 or 2048 bits.
     * @return The encoded bytes.
     * @throws IllegalArgumentException If the input or key is illegal.
     * @throws IllegalStateException If some error happened.
     */
    public static byte[] decrypt(byte[] input, RSAKey key) {
        checkParam(input, key);
        return crypt(input, key.exponent, key.modulus, key.isPrivate, false);
    }

    private static void checkParam(byte[] input, RSAKey key) {
        if (input == null || key == null) {
            throw new IllegalArgumentException("input and key can't be null");
        }
    }

    private native static byte[] crypt(byte[] input, byte[] exponent, byte[] modulus, boolean isPrivate, boolean isEncrypt);
}
