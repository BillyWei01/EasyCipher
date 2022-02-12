package io.easycipher.test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;

import io.easycipher.EasyRSA;
import io.easycipher.RSAKey;
import io.rsautil.RSAUtil;

import android.util.Base64;

public class RSATest {
    private static final String TAG = "MyTag";
    private static final Random random = RandomUtil.random;

    public static boolean testCrypt() throws Exception {
        byte[] src = "Hello World!".getBytes(StandardCharsets.UTF_8);
        // Log.i(TAG, "RSA 1024");
        String mod = "00b956f80f06d1008924fd6e2ee1b6630c521ee356b3dd961b5778603cabf44fe7e921985f4823b6c2b3ba650501370bcd9f4d73f45d239f16c9721b0af80b6af8c7ba3f906f6125ddb83014045fbe3359706bc1838483dd4c16731680b189b6681cf452247b2ef50904c05102f6963a6997a7824e3c5eb2bbf24ea6f676db4f97";
        String pri = "0090137d6e20fc641038c311de3bf44e770b779b7e9100166a56caeaf4ff2f42d6a3324c82f54f5e096931e2c9cb320168ed0786b655991558df6c667d566979d36bdffe7365c0f44cf09494840ffcb00da73bc546a0668cdcf83767e382b31b288a06578ecf3b9c96e4c92c8a21ef598d99d97cd0a14d4f60618b9403772f9be1";
        String pub = "010001";
        if (!testStatic(src, mod, pri, pub)) {
            return false;
        }

        // Log.i(TAG, "RSA 2048");
        mod = "0083bf56a3a76033538bef59e751fd67dc74760bb1b247b143ed7503f3d77eafe8a9133f9be0de592188b50b01643bd2663e047fcb87964a4433cda46a97ed456aa7282eff8b75149fca500d56edd5f96696213d94bdc0511776e3664e841887a9f3d3d0541a8a77a3433f4d7a82467fa1b20f6b6054cbd9943c86c862042609b0402b76a345723d85e487dbfbd41db2928a1d98f34ef74e65eda88c3c6344b703f6b5a9b12ed0728fd7deb92f54c36e3fac370a870466c184c90dbb1b3f2179f9dda246e94eae7457cbaaf0a1021555c08ab885b528e94c4a5f878a3db9e6b7c19af15c2b19735a528a3af7ebcebce3118311291488b63867fd55e796ae5dc01b";
        pri = "089787dcf06373b57520ccea2b0cada350ed09e232d03e1d41f529a6d35cedb7ec9ed6bd21b31e78f3636b2e520d1cb19245d4d7bf25ebfdfaaae4981704604c8e4e2e9277d3d0de82e1299d8bb132aca009d6ec465bae6e2b50b53155a80be0e787dec43d5ede628556318555cda731325d93111b36981ff4ba8d82e6e65c274c6f630f2179db794a7905b91a56d31e5655a28cd8a8845f14ed3074f3113819a32856ee5e2e461d03c3ee825110e2454e3210dd765b1cf61c2d5d40b377288c17acd30f0449685f3e7501f6027da04284b14ff9aaf1d052bbe8fb7ebe0c2c6a462fbd78df0e9fc8bd311c9917be30d7b414a6ef050e0cb4b9c9d219ab759ba1";
        pub = "010001";
        if (!testStatic(src, mod, pri, pub)) {
            return false;
        }

        return randomTest() && testParseKey();
    }

    private static boolean testParseKey() {
        // Generate keys file with openssl, remove head, tail and "\n".
        String publicKey = "MIIBCgKCAQEAxFEkH3FTCGFRtCnLydJES+ShgmVjY7w3KwQxw9IVW+4p4mLL4V/+" +
                "p/m8pnoEaelVKX8fDxoWcJQQ2APGobMJ32MZkpWkFurSj2M5HlxLlH8hJNPYTHoN" +
                "UNh2SFeUtM1GkH9jyJRKqKS0qkJl6jXJGRRcKklNlYchIUdC2i+zqXoZw1KOva85" +
                "ISpU5Od3oZEeOqXtrC/OSzcTHNc1EdpyqpUpGZpPoFUHZ/Y9c0cn9Mvfw/S4BEua" +
                "rHyfB8YiValNzk4QWKCvokeH7OosSboGDu68j5AVmEHxxedD/FodQAONgXy6HSws" +
                "q5GkXYbW6gSWF7MG4o81wDn7hBpUGlsuxwIDAQAB";

        String privateKey = "MIIEowIBAAKCAQEAxFEkH3FTCGFRtCnLydJES+ShgmVjY7w3KwQxw9IVW+4p4mLL" +
                "4V/+p/m8pnoEaelVKX8fDxoWcJQQ2APGobMJ32MZkpWkFurSj2M5HlxLlH8hJNPY" +
                "THoNUNh2SFeUtM1GkH9jyJRKqKS0qkJl6jXJGRRcKklNlYchIUdC2i+zqXoZw1KO" +
                "va85ISpU5Od3oZEeOqXtrC/OSzcTHNc1EdpyqpUpGZpPoFUHZ/Y9c0cn9Mvfw/S4" +
                "BEuarHyfB8YiValNzk4QWKCvokeH7OosSboGDu68j5AVmEHxxedD/FodQAONgXy6" +
                "HSwsq5GkXYbW6gSWF7MG4o81wDn7hBpUGlsuxwIDAQABAoIBAEZZgWVXGdct8LZs" +
                "J+AJ3nmH06zDomsyHl7m4OJ4XTkVTqMWnlMEMGCHaOgLX5uIhwEY0ct6oMH0/Vg7" +
                "eiml3ArWG2rg/u1Ldur1Npm/n0H2kKz+0UsOjckD2Ncxs1NbIEdVry9InLx0UV2V" +
                "76mPXqIDHsf0fr3vr5qaS8WeRHadbwHdaQtr1KEwAEGCA7oMEqXagEqQegjUDg6R" +
                "ZeS+A381oQzqH6g7v6xPh3hl3q+OOQy+6c7fTodrmjSUXXpvn9IIu5RGw/wCA7zF" +
                "CK1ZFolYTMlph6HxcO3D7XVONz4eGKwGzUrnrXLjbwhPFAKQenSlyehOVx0gdO2q" +
                "0klyOjkCgYEA4oD9Xv6kKa45zBadze8i+/lDN3AA0lhB9MgU4qXs+KGqxtTdG+dB" +
                "YEzUzUKHzFUOYtClaO+hH5bj9q5hcIlFXq5DMbq9BSdLRvtFeaHs1mvVPh42EC8f" +
                "PSojsHZUuDYjGHoXeQy9r0X/e9kXlX9ZLGlho48AdQQl5IuZiEizRY0CgYEA3eHN" +
                "ud6JTKI69WyrjvJBWL+JTF407eqsDZ0ctFnP2KkIYSEBTXdaT7GRNxJ72YgpyiND" +
                "B2ELhjS3TZ8pZQ9+QZSxwvkJQlmFRtUkDilhE1AMxYG7VIAGphj4M6lMg9Q+BOHn" +
                "PXLJriCHKRN4gbOGETXivblNB1q66Vm3mAcE/qMCgYAv0aOsRn5J/mpdV/kA3Re5" +
                "sqoqLg8+WTuzffpKz1T0OM1hJNd5aJ04w3+5xe39iYd7/Siuush9btG55p7Tr2dh" +
                "0dCF0zLMv7r4xVupjjH+Is3mS2KGkCw8MYVPX+wK6AMIy93gxHvXYSPK9c4w1a3x" +
                "3l2qtioWikWltoM3boHKkQKBgQCaaRHqT9vs4Nl3AnFBwYWIZYL/CnB7Qd0KfFQF" +
                "jpr+hGO4dGebqXvICiKs2Mgn0oKCkZeMAxUqCHWoJyN/mRCcQwaSUQ0Ih5QgfyPg" +
                "VxuffQ3mRSpA2/fEj4vrJ95/v6yJaUyrjr6b1zc4drxeRrj+MSniLppUi+eXjUAf" +
                "JINtUQKBgFr8Q+It0N8gThpSUOgexlo+Cc7k7iafozk/y6SXzH8cHXz7ucsG0BDw" +
                "RdGjMywOBwJg9hJr/bA4Tfg80QUWQ50+qT3kPKoEfPfv2Ohp1ZXGL/SeuHl1G+0I" +
                "RTYlnrEFzzSBi5C+B1/MGnuD8/0Y/gZY/FrQhBrPBBqEBVJHMziF";

        byte[] pubBytes = Base64.decode(publicKey, Base64.DEFAULT);
        byte[] priBytes = Base64.decode(privateKey, Base64.DEFAULT);

        RSAKey pubKey = RSAKey.parseKey(pubBytes, false);
        RSAKey priKey = RSAKey.parseKey(priBytes, true);

        byte[] data = "Hello World!".getBytes(StandardCharsets.UTF_8);
        byte[] x0 = EasyRSA.encrypt(data, priKey);
        byte[] y0 = EasyRSA.decrypt(x0, pubKey);
        byte[] x1 = EasyRSA.encrypt(data, pubKey);
        byte[] y1 = EasyRSA.decrypt(x1, priKey);
        return Arrays.equals(y0, data) && Arrays.equals(y1, data);
    }


    private static boolean testStatic(byte[] src, String mod, String pri, String pub) throws Exception {
        BigInteger modulus = new BigInteger(HexUtil.hex2Bytes(mod));
        BigInteger privateExponent = new BigInteger(HexUtil.hex2Bytes(pri));
        BigInteger publicExponent = new BigInteger(HexUtil.hex2Bytes(pub));
        return test(src, modulus, privateExponent, publicExponent);
    }

    private static boolean randomTest() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        int n = 2;
        for (int i = 0; i < n; i++) {
            if (!testDynamic(generator, 1024)) {
                return false;
            }
        }
        for (int i = 0; i < n; i++) {
            if (!testDynamic(generator, 2048)) {
                return false;
            }
        }
        return true;
    }

    private static boolean testDynamic(KeyPairGenerator generator, int bits) throws Exception {
        generator.initialize(bits);
        KeyPair pair = generator.genKeyPair();
        BigInteger[] publicKey = RSAUtil.getPublicExpAndMod(pair.getPublic());
        BigInteger[] privateKey = RSAUtil.getPrivateExpAndMod(pair.getPrivate());
        int bound = bits / 8 - 11;
        byte[] bytes = new byte[random.nextInt(bound)];
        random.nextBytes(bytes);
        return test(bytes, privateKey[1], privateKey[0], publicKey[0]);
    }

    private static boolean test(byte[] src, BigInteger modulus, BigInteger privateExponent, BigInteger publicExponent) throws Exception {
        if (src.length == 0) {
            return true;
        }
        src[0] = 0;
        BigInteger input = new BigInteger(src);
        byte[] in = input.toByteArray();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] jdkEncrypt = cipher.doFinal(in);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] jdkDecrypt = cipher.doFinal(jdkEncrypt);

        // Log.d("MyTag", "src:" + HexUtil.bytes2Hex(in));

        byte[] m = modulus.toByteArray();
        RSAKey priKey = new RSAKey(privateExponent.toByteArray(), m, true);
        RSAKey pubKey = new RSAKey(publicExponent.toByteArray(), m, false);
        byte[] jniEncrypt = EasyRSA.encrypt(in, priKey);
        byte[] jniDecrypt = EasyRSA.decrypt(jniEncrypt, pubKey);

//        Log.d(TAG, "jniEncrypt:" + HexUtil.bytes2Hex(jniEncrypt));
//        Log.d(TAG, "jdkEncrypt:" + HexUtil.bytes2Hex(jdkEncrypt));
//        // public encode always not equal
//        Log.i(TAG, "private encode equal:" + Arrays.equals(jdkEncrypt, jniEncrypt));
//        Log.d(TAG, "jdk pub Decrypt:" + HexUtil.bytes2Hex(jdkDecrypt));
//        Log.d(TAG, "jni pub Decrypt:" + HexUtil.bytes2Hex(jniDecrypt));
//        Log.i(TAG, "public decode equal:" + Arrays.equals(jdkDecrypt, jniDecrypt));

        if (!Arrays.equals(jdkEncrypt, jniEncrypt)) {
            return false;
        }
        if (!Arrays.equals(jdkDecrypt, jniDecrypt)) {
            return false;
        }

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        jdkEncrypt = cipher.doFinal(in);
        jniDecrypt = EasyRSA.decrypt(jdkEncrypt, priKey);

        jniEncrypt = EasyRSA.encrypt(in, pubKey);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        jdkDecrypt = cipher.doFinal(jniEncrypt);

//        Log.d(TAG, "jni pri Decrypt:" + HexUtil.bytes2Hex(jniDecrypt));
//        Log.d(TAG, "jdk pri Decrypt:" + HexUtil.bytes2Hex(jdkDecrypt));
//        Log.i(TAG, "private decode equal:" + Arrays.equals(jniDecrypt, jdkDecrypt));
        return Arrays.equals(jniDecrypt, jdkDecrypt);
    }
}
