package io.easycipher;

public class EasySHA extends Cipher {
    public native static byte[] sha256(byte[] input);

    public native static byte[] hmacSHA256(byte[] input, byte[] key);
}
