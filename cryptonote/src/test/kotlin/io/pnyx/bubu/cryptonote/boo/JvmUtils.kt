package io.pnyx.bubu.cryptonote.boo

import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import org.junit.Assert
import java.security.*

internal val spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
//Signature sgr = Signature.getInstance("EdDSA", "I2P");
internal val sgr = EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm))

fun KeyPair.eddsaPrivate() = getPrivate() as EdDSAPrivateKey
fun KeyPair.eddsaPublic() = getPublic() as EdDSAPublicKey

fun EdDSAPrivateKey.toByteArray(): ByteArray = a.toByteArray()

fun EdDSAPublicKey.toByteArray(): ByteArray = getAbyte()

fun generateKeyPair() : KeyPair {
    val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance("1.3.101.112")!!
    keyPairGenerator.initialize(EdDSANamedCurveTable.getByName("ED25519"), newSecureRandom())
    return keyPairGenerator.generateKeyPair()
}

fun eddsaPrivateToPublic(sKey: EdDSAPrivateKey): EdDSAPublicKey {
    val pubKey = EdDSAPublicKeySpec(sKey.getAbyte(), spec)
    val vKey = EdDSAPublicKey(pubKey)
    return vKey
}

private fun require(b: Boolean) {
    Assert.assertTrue(b)
}

private fun newSecureRandom(): SecureRandom {
    //        SystemUtils.IS_OS_LINUX -> {
    //            {
    try {
        return SecureRandom.getInstance("NativePRNGNonBlocking")
    } catch (e: NoSuchAlgorithmException) {
        throw RuntimeException(e)
    }

    //            }
    //        }
    //    else -> SecureRandom::getInstanceStrong
}
