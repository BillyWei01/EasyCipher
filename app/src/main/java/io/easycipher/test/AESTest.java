package io.easycipher.test;


import android.util.Log;

import java.util.Arrays;
import java.util.Random;

import io.easycipher.EasyAES;


public class AESTest {
    private static final String TAG = "MyTag";

    private static final Random r = RandomUtil.random;

    public static boolean test() {
        if (checkAES(128) && checkAES(256)) {
            Log.d(TAG, "Test AES success");
            return true;
        } else {
            Log.d(TAG, "Test AES failed");
            return false;
        }
    }

    private static boolean checkAES(int bits) {
        final int n = 2000;

        int keyLen = (bits == 128) ? 16 : 32;
        byte[] key = new byte[keyLen];
        r.nextBytes(key);
        for (int i = 0; i < n; i++) {
            int len = r.nextInt(128);
            byte[] bytes = new byte[len];
            byte[] iv = new byte[16];
            r.nextBytes(bytes);
            r.nextBytes(iv);
            byte[] cipherBytes = EasyAES.encrypt(bytes, key, iv);

            if (!Arrays.equals(bytes, EasyAES.decrypt(cipherBytes, key, iv))) {
                return false;
            }

            if (!Arrays.equals(cipherBytes, DefaultAES.encrypt(bytes, key, iv))) {
                return false;
            }
        }
        return true;
    }
}
