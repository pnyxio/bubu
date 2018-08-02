package io.pnyx.ked25519.monero;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Arrays;

public class EdDSAUtils {


    private static final EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
    //Signature sgr = Signature.getInstance("EdDSA", "I2P");
    public static Signature sgr() {
        try {
            return new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));//TODO thread local ? shared singleton ?
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
    public static boolean isPair(EdDSAPrivateKey pri, EdDSAPublicKey pub) {
        EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(pri.getAbyte(), spec);
        return equals(pub, new EdDSAPublicKey(pubKey));

    }

    public static EdDSAPublicKey derivePublic(EdDSAPrivateKey pri) {
        EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(pri.getAbyte(), spec);
        return new EdDSAPublicKey(pubKey);
    }

    private static boolean equals(EdDSAPublicKey pub1, EdDSAPublicKey pub2) {
//        return Arrays.equals(pub1.getEncoded(), pub2.getEncoded());
        return pub1.getParams().equals(pub2.getParams())
            && pub1.getA().equals(pub2.getA());
    }
}
