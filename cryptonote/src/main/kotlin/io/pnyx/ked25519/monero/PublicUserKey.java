package io.pnyx.ked25519.monero;

import net.i2p.crypto.eddsa.EdDSAPublicKey;

public class PublicUserKey {
    public final EdDSAPublicKey A;
    public final EdDSAPublicKey B;

    public PublicUserKey(EdDSAPublicKey A, EdDSAPublicKey B) {
        this.A = A;
        this.B = B;
    }

    public String getStandardAddress() {
        return "TODO";//TODO
    }

    public String getTruncatedAddress() {
        return "TODO";//TODO
    }
}
