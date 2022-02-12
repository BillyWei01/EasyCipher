package io.easycipher.test;

import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import io.easycipher.ECCKey;
import io.easycipher.EasyECC;

public class EccTest {
    private static final String TAG = "MyTag";

    public static boolean test() {
        int n = 20;
        for (int i = 0; i < n; i++) {
            if (!testOneTime()) {
                return false;
            }
        }
        return true;
    }

    private static boolean testOneTime() {
        try {
            ECCKey serverKey = EasyECC.generateKey();
            ECCKey clientKey = EasyECC.generateKey();
            byte[] s1 = EasyECC.getSecret(serverKey.publicKey, clientKey.privateKey);
            byte[] s2 = EasyECC.getSecret(clientKey.publicKey, serverKey.privateKey);
            boolean equal = Arrays.equals(s1, s2);

            String message = "Hello World!";
            byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] hash = Digest.sha256(bytes);
            byte[] signature = EasyECC.sign(serverKey.privateKey, hash);
            boolean success = EasyECC.verify(serverKey.publicKey, hash, signature);
            return equal && success;
        } catch (Exception e) {
            Log.d(TAG, e.getMessage(), e);
        }
        return false;
    }
}
