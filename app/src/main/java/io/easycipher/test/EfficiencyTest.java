package io.easycipher.test;

import android.util.Log;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Random;

import io.easycipher.EasyAES;


public class EfficiencyTest {
    public static void compareTime() throws Exception {
        Random r = new Random();
        int n = 500;

        ArrayList<byte[]> testData = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            int len = r.nextInt(128);
            byte[] bytes = new byte[len];
            r.nextBytes(bytes);
            testData.add(bytes);
        }

        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        r.nextBytes(iv);
        r.nextBytes(key);

        long t1 = System.nanoTime();
        for (byte[] data : testData) {
            byte[] cipher = EasyAES.encrypt(data, key, iv);
            EasyAES.decrypt(cipher, key, iv);
        }
        long t2 = System.nanoTime();
        for (byte[] data : testData) {
            byte[] cipher = DefaultAES.encrypt(data, key, iv);
            DefaultAES.decrypt(cipher, key, iv);
        }
        long t3 = System.nanoTime();

        // Log.d("test", "AES efficiency test:");
        Log.d("test", "AES EasyCipher: " + getTime(t2, t1) );
        Log.d("test", "AES Default: " + getTime(t3, t2));
    }

    private static long getTime(long end, long start) {
        return (end - start) / 1000000L;
    }
}
