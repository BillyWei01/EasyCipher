package io.easycipher;

public class ECCKey {
    public final byte[] publicKey;
    public final byte[] privateKey;

    public ECCKey(byte[] pubKey, byte[] priKey) {
        publicKey = pubKey;
        privateKey = priKey;
    }
}
