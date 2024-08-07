package io.easycipher.test;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES support by SDK
 */
class DefaultAES {
    public static byte[] encrypt(byte[] input, byte[] key, byte[] iv) {
        return code(input, key, iv, Cipher.ENCRYPT_MODE);
    }

    public static byte[] decrypt(byte[] input, byte[] key, byte[] iv) {
        return code(input, key, iv, Cipher.DECRYPT_MODE);
    }

    private static byte[] code(byte[] bytes, byte[] key, byte[] iv, int mode) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            if(cipher != null){
                if (iv == null) {
                    cipher.init(mode, keySpec);
                } else {
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    cipher.init(mode, keySpec, ivSpec);
                }
                return cipher.doFinal(bytes);
            }
            return null;
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }
}
