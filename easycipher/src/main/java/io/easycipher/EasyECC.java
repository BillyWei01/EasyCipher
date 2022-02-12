package io.easycipher;

/**
 * Implement of ECDH and ECDSA.
 */
public class EasyECC  extends Cipher {
    private static final int ECC_BYTES = 32;
    public static final int ECC_PUBLIC_KEY_LEN = ECC_BYTES + 1;
    public static final int ECC_PRIVATE_KEY_LEN = ECC_BYTES;
    public static final int ECC_SIGNATURE_LEN = ECC_BYTES * 2;
    public static final int ECC_HASH_LEN = ECC_BYTES;

    /**
     * Generate key pair.
     *
     * @return ecc public key and private key, return null if error occurred.
     */
    public static ECCKey generateKey() {
        byte[] keys = makeKey();
        if (keys == null) {
            return null;
        }
        byte[] publicKey = new byte[ECC_PUBLIC_KEY_LEN];
        byte[] privateKey = new byte[ECC_PRIVATE_KEY_LEN];
        System.arraycopy(keys, 0, publicKey, 0, ECC_PUBLIC_KEY_LEN);
        System.arraycopy(keys, ECC_PUBLIC_KEY_LEN, privateKey, 0, ECC_PRIVATE_KEY_LEN);
        return new ECCKey(publicKey, privateKey);
    }

    /**
     * Get ECDH secret.
     * Compute a shared secret given your private key and someone else's public key.
     * Note: It is recommended that you hash the secret before using it for symmetric encryption or HMAC.
     *
     * @param publicKey The public key of remote.
     * @param privateKey Your private key.
     * @return The share secret, should be 32 bytes. Return null if error occurred.
     * @throws IllegalArgumentException If the key is null or not match the length.
     */
    public static byte[] getSecret(byte[] publicKey, byte[] privateKey) {
        if (publicKey == null || privateKey == null) {
            throw new IllegalArgumentException("Keys can't be null");
        }
        if (publicKey.length != ECC_PUBLIC_KEY_LEN || privateKey.length != ECC_PRIVATE_KEY_LEN) {
            throw new IllegalArgumentException("Invalid key length");
        }
        return ecdhSecret(publicKey, privateKey);
    }

    /**
     * Sigh the hash with ECDSA.
     *
     * @param privateKey Your private key.
     * @param hash The message hash to sign, must be length of 32 bytes.
     * @return The signature of hash, should be 64 bytes, return null if error occurred.
     * @throws IllegalArgumentException If the params is illegal.
     */
    public static byte[] sign(byte[] privateKey, byte[] hash) {
        if (privateKey == null || privateKey.length != ECC_PRIVATE_KEY_LEN) {
            throw new IllegalArgumentException("Invalid key");
        }
        if (hash == null || hash.length != ECC_HASH_LEN) {
            throw new IllegalArgumentException("Invalid hash");
        }
        return ecdsaSign(privateKey, hash);
    }

    /**
     * Verify the signature with ECDSA.
     *
     * @param publicKey The public key of remote.
     * @param hash The message hash to sign, must be length of 32 bytes.
     * @param signature The signature of hash.
     * @return True if the signature match.
     */
    public static boolean verify(byte[] publicKey, byte[] hash, byte[] signature) {
        if (publicKey == null || publicKey.length != ECC_PUBLIC_KEY_LEN) {
            throw new IllegalArgumentException("Invalid key");
        }
        if (hash == null || hash.length != ECC_HASH_LEN) {
            throw new IllegalArgumentException("Invalid hash");
        }
        if (signature == null || signature.length != ECC_SIGNATURE_LEN) {
            throw new IllegalArgumentException("Invalid signature");
        }
        return ecdsaVerify(publicKey, hash, signature);
    }

    private static native byte[] makeKey();

    private static native byte[] ecdhSecret(byte[] publicKey, byte[] privateKey);

    private static native byte[] ecdsaSign(byte[] privateKey, byte[] hash);

    private static native boolean ecdsaVerify(byte[] publicKey, byte[] hash, byte[] signature);
}
