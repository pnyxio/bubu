package io.pnyx.bubu.cryptonote;

import net.corda.core.crypto.SignatureScheme;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.junit.Assert;
import org.junit.Test;

import javax.annotation.Nullable;
import java.security.*;

import static net.corda.core.crypto.Crypto.DEFAULT_SIGNATURE_SCHEME;
import static net.corda.core.crypto.Crypto.isSupportedSignatureScheme;
import static net.corda.core.crypto.CryptoUtils.newSecureRandom;
import static net.corda.core.crypto.CryptoUtils.sign;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class SignTest {
    @Test
    public void testKeypair() throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        //Signature sgr = Signature.getInstance("EdDSA", "I2P");
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));

        for (Ed25519TestVectors.TestTuple testCase : Ed25519TestVectors.testCases) {
            KeyPair kp = eddsaKeypairFromSeed(testCase.seed, spec);
            sgr.initSign(kp.getPrivate());
            sgr.update(testCase.message);
            byte[] signature = sgr.sign();
            assertThat("Test case " + testCase.caseNum + " failed sign",
                    signature, is(equalTo(testCase.sig)));

            sgr.initVerify(kp.getPublic());
            sgr.update(testCase.message);
            assertThat("Test case " + testCase.caseNum + " failed verify",
                    sgr.verify(testCase.sig), is(true));
        }
    }

    private KeyPair eddsaKeypairFromSeed(byte[] seed, EdDSAParameterSpec spec) {
        EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(seed, spec);
        EdDSAPrivateKey sKey = new EdDSAPrivateKey(privKey);

        EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(sKey.getAbyte(), spec);
        PublicKey vKey = new EdDSAPublicKey(pubKey);
        KeyPair kp = new KeyPair(vKey, sKey);
        return kp;
    }


//    @Test
//    public void testSign() throws Exception {
//        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
//        //Signature sgr = Signature.getInstance("EdDSA", "I2P");
//        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
//
//        for (Ed25519TestVectors.TestTuple testCase : Ed25519TestVectors.testCases) {
//            EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(testCase.seed, spec);
//            PrivateKey sKey = new EdDSAPrivateKey(privKey);
//            sgr.initSign(sKey);
//
//            sgr.update(testCase.message);
//
//            assertThat("Test case " + testCase.caseNum + " failed",
//                    sgr.sign(), is(equalTo(testCase.sig)));
//        }
//    }
//
//    @Test
//    public void testVerify() throws Exception {
//        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
//        //Signature sgr = Signature.getInstance("EdDSA", "I2P");
//        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
//        for (Ed25519TestVectors.TestTuple testCase : Ed25519TestVectors.testCases) {
//            EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(testCase.pk, spec);
//            PublicKey vKey = new EdDSAPublicKey(pubKey);
//            sgr.initVerify(vKey);
//
//            sgr.update(testCase.message);
//
//            assertThat("Test case " + testCase.caseNum + " failed",
//                    sgr.verify(testCase.sig), is(true));
//        }
//    }

    public static KeyPair generateKeyPair(@Nullable SignatureScheme signatureScheme) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        if(signatureScheme == null) {
            signatureScheme = DEFAULT_SIGNATURE_SCHEME;
        }
        require(isSupportedSignatureScheme(signatureScheme));
//        {
//            "Unsupported key/algorithm for schemeCodeName: ${signatureScheme.schemeCodeName}"
//        }
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(signatureScheme.getAlgorithmName()/*, providerMap(signatureScheme.providerName)*/);
        if (signatureScheme.getAlgSpec() != null)
            keyPairGenerator.initialize(signatureScheme.getAlgSpec(), newSecureRandom());
        else
            keyPairGenerator.initialize(signatureScheme.getKeySize(), newSecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    private static void require(boolean b) {
        Assert.assertTrue(b);
    }

    private static SecureRandom newSecureRandom() {
//        SystemUtils.IS_OS_LINUX -> {
//            {
        try {
            return SecureRandom.getInstance("NativePRNGNonBlocking");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
//            }
//        }
//    else -> SecureRandom::getInstanceStrong
    }
}
