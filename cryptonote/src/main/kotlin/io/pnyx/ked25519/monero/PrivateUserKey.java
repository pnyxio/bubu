package io.pnyx.ked25519.monero;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;

public class PrivateUserKey {
    public final EdDSAPrivateKey a;
    public final EdDSAPrivateKey b;

    public PrivateUserKey(EdDSAPrivateKey a, EdDSAPrivateKey b) {
        this.a = a;
        this.b = b;
    }

    public PublicUserKey derive() {
        return new PublicUserKey(EdDSAUtils.derivePublic(a), EdDSAUtils.derivePublic(b));
    }
}
