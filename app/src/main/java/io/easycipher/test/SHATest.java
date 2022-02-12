package io.easycipher.test;

import android.util.Log;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import io.easycipher.EasySHA;

public class SHATest {
    private static final Random r = RandomUtil.random;

    public static boolean testSHA256() throws Exception {
        final int n = 1000;
        for (int i = 0; i < n; i++) {
            int len = r.nextInt(1024);
            byte[] bytes = new byte[len];
            r.nextBytes(bytes);
            byte[] h1 = Digest.sha256(bytes);
            byte[] h2 = EasySHA.sha256(bytes);
            if(!Arrays.equals(h1, h2)){
                Log.d("test", "Test sha256 failed");
                return false;
            }
        }
        Log.d("aes test", "Test sha256 success");
        return true;
    }

    public static boolean testHmacSHA256() throws Exception{
        final int n = 1000;
        Mac mac = Mac.getInstance("HmacSHA256");
        for (int i = 0; i < n; i++) {
            int keyLen = r.nextInt(128) + 1;
            byte[] key = new byte[keyLen];
            r.nextBytes(key);
            int len = r.nextInt(512);
            byte[] bytes = new byte[len];
            r.nextBytes(key);
            SecretKeySpec secret_key = new SecretKeySpec(key, "HmacSHA256");
            mac.init(secret_key);
            byte[] m1 = mac.doFinal(bytes);
            byte[] m2 = EasySHA.hmacSHA256(bytes, key);
            if(!Arrays.equals(m1, m2)){
                Log.d("test", "Test hmac-sha256 failed");
                return false;
            }
        }
        Log.d("test", "Test hmac-sha256 success");
        return true;
    }
}
