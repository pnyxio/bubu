package io.pnyx.bubu.cryptonote.boo

import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import unsigned.Ubyte
import java.security.KeyPair
import java.util.concurrent.Semaphore

typealias uint8_t = Ubyte
/*
internal val random_lock = Semaphore(1)

fun assert(cond: Boolean, reason: String = "") {
    if(! cond) {
        throw IllegalStateException("assertion failed: $reason")
    }
}

fun argCheck(cond: Boolean, reason: String = "") {
    if(! cond) {
        throw IllegalArgumentException("illegal argument: $reason")
    }
}

class EllipticCurvePoint(val data: ByteArray/*[32]*/) {
    init { argCheck(data.size == 32) }
}

class EllipticCurveScalar(val data: ByteArray/*[32]*/) {
    init { argCheck(data.size == 32) }
}

class Hash(val data: ByteArray/*[32]*/) {
    init { argCheck(data.size == 32) }
}

class PublicKey(val data: ByteArray/*[32]*/) {
    init { argCheck(data.size == 32) }
}

class SecretKey(val data: ByteArray/*[32]*/) {
    init { argCheck(data.size == 32) }
}

class KeyDerivation(val data: ByteArray/*[32]*/) {
    init { argCheck(data.size == 32) }
}

class KeyImage(val data: ByteArray/*[32]*/) {
    init { argCheck(data.size == 32) }
}

class Signature(val data: ByteArray/*[64]*/) {
    init { argCheck(data.size == 32) }
}



class crypto_ops() {
    constructor( other: crypto_ops ) : this() {
        //TODO
    }
    //TODO void operator=(const crypto_ops &);
    //TODO ~crypto_ops();

    fun generate_keys(): Pair<PublicKey,SecretKey> {
        val kp = generateKeyPair()
        return Pair(PublicKey(kp.eddsaPublic().toCompressedPoint()), SecretKey(kp.eddsaPrivate().toCompressedPoint()))
    }

    fun check_key(publicKey: PublicKey) = true//TODO return ge_frombytes_vartime(&point, reinterpret_cast<const unsigned char*>(&key)) == 0;
    fun secret_key_to_public_key(secretKey: SecretKey): PublicKey {
        val privKey = EdDSAPrivateKeySpec(secretKey.data, spec)
        val sKey = EdDSAPrivateKey(privKey)
        return PublicKey(eddsaPrivateToPublic(sKey).toCompressedPoint())
    }

    @Throws()
    fun generate_key_derivation(publicKey: PublicKey, secretKey: SecretKey): KeyDerivation {
        ge_p3 point;
        ge_p2 point2;
        ge_p1p1 point3;
        assert(sc_check(reinterpret_cast<const unsigned char*>(&key2)) == 0);
        if (ge_frombytes_vartime(&point, reinterpret_cast<const unsigned char*>(&key1)) != 0) {
            return false;
        }
        ge_scalarmult(&point2, reinterpret_cast<const unsigned char*>(&key2), &point);
        ge_mul8(&point3, &point2);
        ge_p1p1_to_p2(&point2, &point3);
        ge_tobytes(reinterpret_cast<unsigned char*>(&derivation), &point2);
        return KeyDerivation();
    }
//    static bool derive_public_key(const KeyDerivation &, size_t, const PublicKey &, PublicKey &);
//    static bool derive_public_key(const KeyDerivation &, size_t, const PublicKey &, const uint8_t*, size_t, PublicKey &);
//    //hack for pg
//    static bool underive_public_key_and_get_scalar(const KeyDerivation &, std::size_t, const PublicKey &, PublicKey &, EllipticCurveScalar &);
//    static void generate_incomplete_key_image(const PublicKey &, EllipticCurvePoint &);
//    //
//    static void derive_secret_key(const KeyDerivation &, size_t, const SecretKey &, SecretKey &);
//    static void derive_secret_key(const KeyDerivation &, size_t, const SecretKey &, const uint8_t*, size_t, SecretKey &);
//    static bool underive_public_key(const KeyDerivation &, size_t, const PublicKey &, PublicKey &);
//    static bool underive_public_key(const KeyDerivation &, size_t, const PublicKey &, const uint8_t*, size_t, PublicKey &);
//    static void generate_signature(const Hash &, const PublicKey &, const SecretKey &, Signature &);
//    static bool check_signature(const Hash &, const PublicKey &, const Signature &);
//    static void generate_key_image(const PublicKey &, const SecretKey &, KeyImage &);
//    static void hash_data_to_ec(const uint8_t*, std::size_t, PublicKey&);
//    static void generate_ring_signature(const Hash &, const KeyImage &,
//    const PublicKey *const *, size_t, const SecretKey &, size_t, Signature *);
//    static bool check_ring_signature(const Hash &, const KeyImage &,
//    const PublicKey *const *, size_t, const Signature *);
}

object Crypto  {

}

*/