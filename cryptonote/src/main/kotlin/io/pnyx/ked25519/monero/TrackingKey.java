package io.pnyx.ked25519.monero;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;

public class TrackingKey {
    public final EdDSAPrivateKey a;
    public final EdDSAPublicKey B;

    public TrackingKey(EdDSAPrivateKey a, EdDSAPublicKey B) {
//        Assert.isFalse(EdDSAUtils.isPair(a, B));
        this.a = a;
        this.B = B;
    }
}
