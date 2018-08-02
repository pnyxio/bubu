package io.pnyx.ked25519.monero

import io.pnyx.ked25519.*
import io.pnyx.ked25519.Assert
import io.pnyx.ked25519.PublicKey
import io.pnyx.ked25519.Signature
import net.corda.core.crypto.generateKeyPair
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import java.security.*

internal val spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)

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


private fun newSecureRandom(): SecureRandom {
    try {
        return SecureRandom.getInstance("NativePRNGNonBlocking")
    } catch (e: NoSuchAlgorithmException) {
        return SecureRandom()
    }
}

class CryptoOps {

    fun generate_keys(): Pair<PublicKey,SecretKey> {
        val kp = generateKeyPair()
        return Pair(kp.eddsaPublic().toByteArray(), kp.eddsaPrivate().toByteArray())
    }

    fun secret_key_to_public_key(secretKey: SecretKey): PublicKey {
        val privKey = EdDSAPrivateKeySpec(secretKey, spec)
        val sKey = EdDSAPrivateKey(privKey)
        return eddsaPrivateToPublic(sKey).toByteArray()
    }

    @Throws()
    fun generate_key_derivation(publicKey: PublicKey, secretKey: SecretKey): KeyDerivation {
        Assert.isTrue(secretKey.sc_check())
//        return (secretKey * P3(publicKey)).mul8().toP2().toCompressedPoint()//TODO _8 * E SENZA P2()
//      (_8 * (secretKey * P3(publicKey))).compress()//TODO _8 * E SENZA P2()
        val point = P3(publicKey)//TODO this throws IllegalArgumentException !!! vartime
        val point2 = (secretKey * point).toP2()//TODO is same bytearra repr as scalar ?
        val point3 = point2.mul8()
        return point3.toP2().toCompressedPoint()
    }



    fun derive_public_key(derivation: KeyDerivation, output_index: Int, base: PublicKey): PublicKey {
//        val base = P3(base)
//        return (derivation.toScalar(output_index) * base + base).compress()
        val point1 = P3(base)//TODO this throws IllegalArgumentException !!! vartime
        val scalar = derivation.toScalar(output_index)
        val point2 = (scalar * Ed25519.B).toP3()
        val point3 = point2.toCached()
        val point4 = point1 + point3
        val point5 = point4.toP2()
        return point5.toCompressedPoint()
    }

    fun derive_secret_key(derivation: KeyDerivation, output_index: Int, base: SecretKey): SecretKey {
//return base.sc_assert() + derivation.toScalar(output_index)
        var derived_key: SecretKey
        var scalar: Scal
        Assert.isTrue(base.sc_check())
        scalar = derivation.toScalar(output_index)
        derived_key = base + scalar
        return derived_key
    }

    fun derive_subaddress_public_key(out_key: PublicKey, derivation: KeyDerivation, output_index: Int): PublicKey {
        //return (P3(out_key) - derivation.toScalar(output_index) * Ed25519.B).compress()
        val point1 = P3(out_key)//thows  !!!! ge_frombytes_vartime
        val scalar = derivation.toScalar(output_index)
        val point2 = scalar * Ed25519.B
        val point3 = point2.toCached()
        val point4 = point1 - point3
        val point5 = point4.toP2()
        val derived_key: PublicKey = point5.toCompressedPoint()
        return derived_key
    }

    fun generate_signature(prefix_hash: ByteArray, pub: PublicKey, sec: SecretKey): Signature {
        val k = random_scalar()
        val tmp3 = random_scalar() * Ed25519.B
        val c =  FastHash(prefix_hash, pub, tmp3.toCompressedPoint()).reduceToScalar()
        return Signature(c, r = k - c * sec)
    }


    fun check_signature(prefix_hash: ByteArray, pub: PublicKey, sig: Signature): Boolean {
        Assert.isTrue(pub.check_key())//TODO
        val tmp3 = P3(pub, true)//TODO throws
        if (! sig.c.sc_check() || ! sig.r.sc_check()) {
            return false
        }
//        $r = a * A + b * B$ where $a = a[0]+256*a[1]+\dots+256^{31} a[31]$,
//        public GroupElement doubleScalarMultiplyVariableTime(final GroupElement A, final byte[] a, final byte[] b)
        val tmp2 = (sig.c * tmp3 + sig.r * Ed25519.B) as P2
        val c = FastHash(prefix_hash, pub, tmp2.toCompressedPoint()).reduceToScalar()

        return ! (c - sig.c).isnonzero()//TODO oh my
    }


    @Throws
    fun generate_tx_proof(prefix_hash: Hash32, R: PublicKey, A: PublicKey, B: PublicKey?, D: PublicKey, r: SecretKey): Signature {
        // sanity check
        var R_p3: P3//ge_p3
        var A_p3: P3//ge_p3
        var B_p3: P3? = null//ge_p3
        var D_p3: P3//ge_p3
        try {
            R_p3 = P3(R)
        } catch (e: IllegalArgumentException) {
            throw RuntimeException("tx pubkey is invalid")
        }
        try {
            A_p3 = P3(A)
        } catch (e: IllegalArgumentException) {
            throw RuntimeException("recipient view pubkey is invalid")
        }
        try {
            if(B != null) B_p3 = P3(B)
        } catch (e: IllegalArgumentException) {
            throw RuntimeException("recipient spend pubkey is invalid")
        }
        try {
            D_p3 = P3(D)
        } catch (e: IllegalArgumentException) {
            throw RuntimeException("key derivation is invalid")
        }

        // pick random k
        val k = random_scalar()

        //s_comm_2 buf;
        val buf_msg = prefix_hash
        val buf_D = D
        var buf_X: ByteArray
        if (B_p3 != null)
        {
            // compute X = k*B
            buf_X = (k * B_p3).toCompressedPoint()
//            var X_p2: GroupElement= GroupElement(Ed25519.curve, B.data).scalarMultiply(k)
//            buf_X = X_p2.toByteArray()
        }
        else
        {
            // compute X = k*G
            buf_X = (k * Ed25519.B).toCompressedPoint()
//            var X_p3: GroupElement = Ed25519.B.scalarMultiply(k)
//            buf_X = X_p3.toByteArray()
        }

        // compute Y = k*A
        val Y_p2 = k * A_p3//ge_p2
        val buf_Y = Y_p2.toCompressedPoint()

        // sig.c = Hs(Msg || D || X || Y)
        val hashable = buf_msg + buf_D + buf_X + buf_Y
        val c = FastHash(hashable).reduceToScalar()

        // sig.r = k - sig.c*r
        //sc_mulsub(sig.c, r.data, k)
        return Signature(c = c, r = k - c * r)
    }


    fun check_tx_proof(prefix_hash: ByteArray, R: PublicKey, A: PublicKey, B: PublicKey?, D: PublicKey, sig: Signature): Boolean {
        // sanity check
        var R_p3: P3//ge_p3
        var A_p3: P3//ge_p3
        var B_p3: P3? = null//ge_p3
        var D_p3: P3//ge_p3
        try {
            R_p3 = P3(R)
        } catch (e: IllegalArgumentException) {
            return false
        }
        try {
            A_p3 = P3(A)
        } catch (e: IllegalArgumentException) {
            return false
        }
        try {
            if (B != null) B_p3 = P3(B)
        } catch (e: IllegalArgumentException) {
            return false
        }
        try {
            D_p3 = P3(D)
        } catch (e: IllegalArgumentException) {
            return false
        }
        if (! sig.c.sc_check() || ! sig.r.sc_check()) {
            return false;
        }


        // compute sig.c*R
        var cR_p3: P3//ge_p3
        var cR_p2 = sig.c * R_p3//ge_p2
        var cR: PublicKey = cR_p2.toCompressedPoint()
        try {
            cR_p3 = P3(cR)
        } catch (e: IllegalArgumentException) {
            return false
        }

        var X_p1p1: P1P1//ge_p1p1
        if (B_p3 != null) {
            // compute X = sig.c*R + sig.r*B
            var rB_p2 = sig.r * B_p3//ge_p2
            val rB: PublicKey = rB_p2.toCompressedPoint()
            var rB_p3: P3
            try {
                rB_p3 = P3(rB)//ge_p3
            } catch (e: IllegalArgumentException) {
                return false
            }
            val rB_cached = rB_p3.toCached()//ge_cached
            X_p1p1 = cR_p3 + rB_cached
        }
        else
        {
            // compute X = sig.c*R + sig.r*G
            val rG_p3 = sig.r  * Ed25519.B
            val rG_cached = rG_p3.toCached()
            X_p1p1 = cR_p3 + rG_cached
        }
        val X_p2 = X_p1p1.toP2()

        // compute sig.c*D
        val cD_p2 = sig.c * D_p3

        // compute sig.r*A
        val rA_p2 = sig.r * A_p3

        // compute Y = sig.c*D + sig.r*A
        //TODO optimize
//        var cD = PublicKey(cD_p2.toByteArray())
//        var rA = PublicKey(rA_p2.toByteArray())
        var cD_p3 = cD_p2.toP3()
        var rA_p3 = rA_p2.toP3()
//        try {
//            cD_p3 = GroupElement(Ed25519.curve, cD.data)
//        } catch (e: IllegalArgumentException) {
//            return false
//        }
//        try {
//            rA_p3 = GroupElement(Ed25519.curve, rA.data)
//        } catch (e: IllegalArgumentException) {
//            return false
//        }
        var rA_cached = rA_p3.toCached()
        var Y_p1p1 = cD_p3 + rA_cached

        var Y_p2 = Y_p1p1.toP2()

        // compute c2 = Hs(Msg || D || X || Y)
//        val buf_msg = prefix_hash.data
//        val buf_D = D.data
//        val buf_X = X_p2.toByteArray()
//        val buf_Y = Y_p2.toByteArray()
//        val buf = buf_msg + buf_D + buf_X + buf_Y
        val c2 = FastHash(prefix_hash, D, X_p2.toCompressedPoint(), Y_p2.toCompressedPoint()).reduceToScalar()

        // test if c2 == sig.c
        return ! (c2 - sig.c).isnonzero()
    }

}


