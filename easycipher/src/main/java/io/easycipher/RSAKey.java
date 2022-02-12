package io.easycipher;

import java.nio.ByteBuffer;

public class RSAKey {
    public final byte[] exponent;
    public final byte[] modulus;
    public final boolean isPrivate;

    public RSAKey(byte[] exponent, byte[] modulus, boolean isPrivate) {
        if (exponent == null || modulus == null) {
            throw new IllegalArgumentException("exponent and modulus can't be null");
        }
        this.exponent = exponent;
        this.modulus = modulus;
        this.isPrivate = isPrivate;
    }

    /**
     * Parse RSA
     *
     * @param pkcs1Key The key with pkcs#1 format.
     * @param isPrivate Private key or public key.
     * @return RSA key pair.
     */
    public static RSAKey parseKey(byte[] pkcs1Key, boolean isPrivate) {
        byte[][] result = parseKey(ByteBuffer.wrap(pkcs1Key), isPrivate);
        return new RSAKey(result[1], result[0], isPrivate);
    }

    /*
       PKCS#1

       RSAPublicKey ::= SEQUENCE {
          modulus           INTEGER,  -- n
          publicExponent    INTEGER   -- e
       }

       RSAPrivateKey ::= SEQUENCE {
        version Version,
        modulus INTEGER, -- n
        publicExponent INTEGER, -- e
        privateExponent INTEGER, -- d
        prime1 INTEGER, -- p
        prime2 INTEGER, -- q
        exponent1 INTEGER, -- d mod (p-1)
        exponent2 INTEGER, -- d mod (q-1)
        coefficient INTEGER -- (inverse of q) mod p
       }
    */
    private static byte[][] parseKey(ByteBuffer buffer, boolean isPrivate) {
        byte[][] result = new byte[2][];
        buffer.position(1);
        getLen(buffer);
        // Get modulus
        if (isPrivate) {
            skipItem(buffer);
            result[0] = getItem(buffer);
            skipItem(buffer);
        } else {
            result[0] = getItem(buffer);
        }
        // Get exponent
        result[1] = getItem(buffer);
        return result;
    }

    private static int getLen(ByteBuffer buffer) {
        int len = buffer.get();
        if ((len & 0x80) != 0) {
            int lenOfLen = len & 0x7f;
            len = 0;
            for (int i = 0; i < lenOfLen; i++) {
                len <<= 8;
                byte b = buffer.get();
                len |= b & 0xFF;
            }
        }
        return len;
    }

    private static byte[] getItem(ByteBuffer buffer) {
        buffer.position(buffer.position() + 1);
        int len = getLen(buffer);
        byte[] bytes = new byte[len];
        buffer.get(bytes);
        return bytes;
    }

    private static void skipItem(ByteBuffer buffer) {
        buffer.position(buffer.position() + 1);
        int len = getLen(buffer);
        buffer.position(buffer.position() + len);
    }
}
