package io.easycipher.test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Digest {
    public static byte[] sha256(byte[] msg) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(msg);
    }
}
