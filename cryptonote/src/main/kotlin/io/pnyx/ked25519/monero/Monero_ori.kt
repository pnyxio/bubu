//package io.pnyx.ked25519.monero
//
//import io.pnyx.ked25519.Ed25519
//import io.pnyx.ked25519.Ed25519.edDSANamedCurveSpec
//import io.pnyx.ked25519.Ed25519.getRandomByteArray
//import net.corda.core.crypto.generateKeyPair
//import net.i2p.crypto.eddsa.EdDSAEngine
//import net.i2p.crypto.eddsa.EdDSAPrivateKey
//import net.i2p.crypto.eddsa.EdDSAPublicKey
//import net.i2p.crypto.eddsa.math.FieldElement
//import net.i2p.crypto.eddsa.math.GroupElement
//import net.i2p.crypto.eddsa.math.ed25519.Ed25519FieldElement
//import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
//import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
//import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
//import java.security.*
//import java.util.concurrent.Semaphore
//
//object Assert {
//    fun isFalse(b: Boolean) {
//        if (b) {
//            throw IllegalArgumentException()
//        }
//    }
//    fun isTrue(b: Boolean) {
//        if (!b) {
//            throw IllegalArgumentException()
//        }
//    }
//}
//
//internal val random_lock = Semaphore(1)
//
//fun assert(cond: Boolean, reason: String = "") {
//    if(! cond) {
//        throw IllegalStateException("assertion failed: $reason")
//    }
//}
//
//fun argCheck(cond: Boolean, reason: String = "") {
//    if(! cond) {
//        throw IllegalArgumentException("illegal argument: $reason")
//    }
//}
//
//class EllipticCurvePoint(val data: ByteArray/*[32]*/) {
//    init { argCheck(data.size == 32) }
//}
//
//class EllipticCurveScalar(val data: ByteArray/*[32]*/) {
//    init { argCheck(data.size == 32) }
//}
//
//class Hash(val data: ByteArray/*[32]*/) {
//    init { argCheck(data.size == 32) }
//}
//
//class PublicKey(val data: ByteArray/*[32]*/) {
//    init { argCheck(data.size == 32) }
//}
//
//class SecretKey(val data: ByteArray/*[32]*/) {
//    init { argCheck(data.size == 32) }
//}
//
//class KeyDerivation(val data: ByteArray/*[32]*/) {
//    init { argCheck(data.size == 32) }
//}
//
//class KeyImage(val data: ByteArray/*[32]*/) {
//    init { argCheck(data.size == 32) }
//}
//
//class Signature(val data: ByteArray/*[64]*/) {
//    init { argCheck(data.size == 32) }
//    var r: ByteArray = ByteArray(32)
//    var c: ByteArray = ByteArray(32)
//}
//
//internal val spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
////Signature sgr = Signature.getInstance("EdDSA", "I2P");
//internal val sgr = EdDSAEngine(MessageDigest.getInstance(spec.hashAlgorithm))
//
//fun KeyPair.eddsaPrivate() = getPrivate() as EdDSAPrivateKey
//fun KeyPair.eddsaPublic() = getPublic() as EdDSAPublicKey
//
//fun EdDSAPrivateKey.toCompressedPoint(): ByteArray = a.toCompressedPoint()
//
//fun EdDSAPublicKey.toCompressedPoint(): ByteArray = getAbyte()
//
//fun generateKeyPair() : KeyPair {
//    val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance("1.3.101.112")!!
//    keyPairGenerator.initialize(EdDSANamedCurveTable.getByName("ED25519"), newSecureRandom())
//    return keyPairGenerator.generateKeyPair()
//}
//
//fun eddsaPrivateToPublic(sKey: EdDSAPrivateKey): EdDSAPublicKey {
//    val pubKey = EdDSAPublicKeySpec(sKey.getAbyte(), spec)
//    val vKey = EdDSAPublicKey(pubKey)
//    return vKey
//}
//
//private fun require(b: Boolean) {
//    Assert.isTrue(b)
//}
//
//private fun newSecureRandom(): SecureRandom {
//    //        SystemUtils.IS_OS_LINUX -> {
//    //            {
//    try {
//        return SecureRandom.getInstance("NativePRNGNonBlocking")
//    } catch (e: NoSuchAlgorithmException) {
//        throw RuntimeException(e)
//    }
//
//    //            }
//    //        }
//    //    else -> SecureRandom::getInstanceStrong
//}
//
//fun sc_check(s: ByteArray) = true//TODO
//class crypto_ops() {
//    constructor( other: crypto_ops ) : this() {
//        //TODO
//    }
//    //TODO void operator=(const crypto_ops &);
//    //TODO ~crypto_ops();
//
//    fun generate_keys(): Pair<PublicKey,SecretKey> {
//        val kp = generateKeyPair()
//        return Pair(PublicKey(kp.eddsaPublic().toCompressedPoint()), SecretKey(kp.eddsaPrivate().toCompressedPoint()))
//    }
//
//    fun check_key(publicKey: PublicKey) = true//TODO return ge_frombytes_vartime(&point, reinterpret_cast<const unsigned char*>(&key)) == 0;
//    fun secret_key_to_public_key(secretKey: SecretKey): PublicKey {
//        val privKey = EdDSAPrivateKeySpec(secretKey.data, spec)
//        val sKey = EdDSAPrivateKey(privKey)
//        return PublicKey(eddsaPrivateToPublic(sKey).toCompressedPoint())
//    }
//
//    @Throws()
//    fun generate_key_derivation(publicKey: PublicKey, secretKey: SecretKey): KeyDerivation! {
//        Assert.isTrue(sc_check(secretKey.data))
//        var point: GroupElement//ge_p3
//        var point2: GroupElement//ge_p2
//        var point3: GroupElement//ge_p1p1
//        point = GroupElement(Ed25519.curve, publicKey.data)//TODO this throws IllegalArgumentException !!! vartime
//        point2 = point.scalarMultiply(secretKey.data).toP2()//TODO is same bytearra repr as scalar ?
//        point3 = point2.doubleScalarMultiplyVariableTime()
//        point3 = ge_mul8(point2)
//        return KeyDerivation(point3.toP2().toCompressedPoint());
//    }
//
//    fun ge_mul8(t: GroupElement/*ge_p2*/): GroupElement/*ge_p1p1*/ {//TODO miki find impl in java
//        Assert.isTrue(t.representation == GroupElement.Representation.P2)
//        return t.dbl().toP2().dbl().toP2().dbl()
//    }
//
//    fun derive_public_key(derivation: KeyDerivation, output_index: Int,
//    base: PublicKey): PublicKey {
//        var derived_key: PublicKey
//        var scalar: EllipticCurveScalar//ec_scalar
//        var point1: GroupElement//ge_p3
//        var point2: GroupElement//ge_p3
//        var point3: GroupElement//ge_cached
//        var point4: GroupElement//ge_p1p1
//        var point5: GroupElement//ge_p2
//        point1 = GroupElement(Ed25519.curve, base.data).toP3()//TODO this throws IllegalArgumentException !!! vartime
//        scalar = derivation_to_scalar(derivation, output_index)
//        point2 = Ed25519.B.scalarMultiply(scalar.data).toP3()
//        point3 = point2.toCached()
//        point4 = point1.add(point3)//TODO check p1p1
//        point5 = point4.toP2()
//        return PublicKey(point5.toCompressedPoint())
//    }
//
//    private fun derivation_to_scalar(derivation: KeyDerivation, output_index: Int): EllipticCurveScalar {
//        //TODO
////        struct {
////            key_derivation derivation;
////            char output_index[(sizeof(size_t) * 8 + 6) / 7];
////        } buf;
////        char *end = buf.output_index;
////        buf.derivation = derivation;
////        tools::write_varint(end, output_index);
////        assert(end <= buf.output_index + sizeof buf.output_index);
////        hash_to_scalar(&buf, end - reinterpret_cast<char *>(&buf), res);
//        return EllipticCurveScalar(ByteArray(32))
//    }
//
//    fun derive_secret_key(derivation: KeyDerivation, output_index: Int, base: SecretKey): SecretKey {
//        var derived_key: SecretKey
//        var scalar: EllipticCurveScalar
//        Assert.isTrue(sc_check(base.data))
//        scalar = derivation_to_scalar(derivation, output_index)
//        derived_key = SecretKey(sc_add(base.data, scalar.data))
//        return derived_key
//    }
//
//    private fun sc_add(data: ByteArray, data1: ByteArray): ByteArray {
//        //TODO
//        return ByteArray(32)
//    }
//
//    fun derive_subaddress_public_key(out_key: PublicKey, derivation: KeyDerivation, output_index: Int): PublicKey {
//        var derived_key: PublicKey
//        var scalar: EllipticCurveScalar
//        var point1: GroupElement//ge_p3
//        var point2: GroupElement//ge_p3
//        var point3: GroupElement//ge_cached
//        var point4: GroupElement//ge_p1p1
//        var point5: GroupElement//ge_p2
//        point1 = GroupElement(Ed25519.curve, out_key.data)//thows  !!!! ge_frombytes_vartime
//        scalar = derivation_to_scalar(derivation, output_index)
//        point2 = Ed25519.B.scalarMultiply(scalar.data)
//        point3 = point2.toCached()
//        point4 = ge_sub(point1, point3)
//        point5 = point4.toP2()
//        derived_key = PublicKey(point5.toCompressedPoint())
//        return derived_key
//    }
//
//    private fun ge_sub(point1: GroupElement/*ge_p3*/, point3: GroupElement/*ge_cached */): GroupElement/*ge_p1p1*/ {
//        //TODO
//        return GroupElement(Ed25519.curve, ByteArray(32))
//    }
//
////    struct s_comm {
////        hash h;
////        ec_point key;
////        ec_point comm;
////    };
////
////    struct s_comm_2 {
////        hash msg;
////        ec_point D;
////        ec_point X;
////        ec_point Y;
////    };
//
//    fun generate_signature(prefix_hash: Hash, pub: PublicKey, sec: SecretKey): Signature {
//        var sig = Signature(ByteArray(64))//TODO init with r and c
//        var tmp3: GroupElement//ge_p3
//        var k: EllipticCurveScalar
//        k = EllipticCurveScalar(random_scalar())
//        tmp3 = Ed25519.B.scalarMultiply(k.data)
//        val hashable: ByteArray = prefix_hash.data + pub.data + tmp3.toCompressedPoint()
//        sig.c = hash_to_scalar(hashable)
//        sig.r = sc_mulsub(sig.c, sec.data, k.data);
//    }
//
//    private fun hash_to_scalar(msg: ByteArray): ByteArray {
//        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
//    }
//
//    fun check_signature(prefix_hash: Hash, pub: PublicKey, sig: Signature): Boolean {
//        var tmp2: GroupElement //ge_p2
//        var tmp3: GroupElement//ge_p3
//        var c: ByteArray//EllipticCurveScalar
//
//        Assert.isTrue(check_key(pub));
//        tmp3 = GroupElement(Ed25519.curve, pub.data)//throws
//        if (! sc_check(sig.c) || ! sc_check(sig.r)) {
//            return false;
//        }
//        tmp2 = Ed25519.B.doubleScalarMultiplyVariableTime(tmp3, sig.c, sig.r)
//        val buf: ByteArray = prefix_hash.data + pub.data + tmp2.toCompressedPoint()
//        c = hash_to_scalar(buf)
//
//        val x: ByteArray = sc_sub(c, sig.c)
//        return sc_isnonzero(c)
//    }
//
//    private fun sc_isnonzero(c: ByteArray): Boolean {
//        return true
//    }
//
//    private fun sc_sub(c: ByteArray, c1: ByteArray): ByteArray {
//        return ByteArray(32)//TODO
//    }
//
//    @Throws
//    fun generate_tx_proof(prefix_hash: Hash, R: PublicKey, A:PublicKey, B: PublicKey?, D: PublicKey, r: SecretKey): Signature {
//        var sig: Signature = Signature(ByteArray(64))//TODO init c r
//        // sanity check
//        var R_p3: GroupElement//ge_p3
//        var A_p3: GroupElement//ge_p3
//        var B_p3: GroupElement?//ge_p3
//        var D_p3: GroupElement//ge_p3
//        try {
//            R_p3 = GroupElement(Ed25519.curve, R.data)
//        } catch (e: IllegalArgumentException) {
//            throw RuntimeException("tx pubkey is invalid")
//        }
//        try {
//            A_p3 = GroupElement(Ed25519.curve, A.data)
//        } catch (e: IllegalArgumentException) {
//            throw RuntimeException("recipient view pubkey is invalid")
//        }
//        try {
//            if(B != null) B_p3 = GroupElement(Ed25519.curve, B.data)
//        } catch (e: IllegalArgumentException) {
//            throw RuntimeException("recipient spend pubkey is invalid")
//        }
//        try {
//            D_p3 = GroupElement(Ed25519.curve, D.data)
//        } catch (e: IllegalArgumentException) {
//            throw RuntimeException("key derivation is invalid")
//        }
//
//        // pick random k
//        val k = random_scalar()
//
//        //s_comm_2 buf;
//        val buf_msg = prefix_hash.data;
//        val buf_D = D.data;
//        var buf_X: ByteArray
//        if (B != null)
//        {
//            // compute X = k*B
//            var X_p2: GroupElement= GroupElement(Ed25519.curve, B.data).scalarMultiply(k)
//            buf_X = X_p2.toCompressedPoint()
//        }
//        else
//        {
//            // compute X = k*G
//            var X_p3: GroupElement = Ed25519.B.scalarMultiply(k)
//            buf_X = X_p3.toCompressedPoint()
//        }
//
//        // compute Y = k*A
//        val Y_p2 = A_p3.scalarMultiply(k)//ge_p2
//        val buf_Y = Y_p2.toCompressedPoint()
//
//        // sig.c = Hs(Msg || D || X || Y)
//        val hashable = buf_msg + buf_D + buf_X + buf_Y
//        sig.c = hash_to_scalar(hashable)
//
//        // sig.r = k - sig.c*r
//        sig.r = sc_mulsub(sig.c, r.data, k)
//
//        return sig
//    }
//
//
//    fun check_tx_proof(prefix_hash: Hash, R: PublicKey, A: PublicKey, B: PublicKey?, D: PublicKey, sig: Signature): Boolean {
//        // sanity check
//        var R_p3: GroupElement//ge_p3
//        var A_p3: GroupElement//ge_p3
//        var B_p3: GroupElement? = null//ge_p3
//        var D_p3: GroupElement//ge_p3
//        try {
//            R_p3 = GroupElement(Ed25519.curve, R.data)
//        } catch (e: IllegalArgumentException) {
//            return false
//        }
//        try {
//            A_p3 = GroupElement(Ed25519.curve, A.data)
//        } catch (e: IllegalArgumentException) {
//            return false
//        }
//        try {
//            if (B != null) B_p3 = GroupElement(Ed25519.curve, B.data)
//        } catch (e: IllegalArgumentException) {
//            return false
//        }
//        try {
//            D_p3 = GroupElement(Ed25519.curve, D.data)
//        } catch (e: IllegalArgumentException) {
//            return false
//        }
//        if (! sc_check(sig.c) || ! sc_check(sig.r)) {
//            return false;
//        }
//
//
//        // compute sig.c*R
//        var cR_p3: GroupElement//ge_p3
//            var cR_p2: GroupElement = R_p3.scalarMultiply(sig.c)//ge_p2
//            var cR = PublicKey(cR_p2.toCompressedPoint())
//            try {
//                cR_p3 = GroupElement(Ed25519.curve, cR.data)
//            } catch (e: IllegalArgumentException) {
//                return false
//            }
//
//        var X_p1p1: GroupElement//ge_p1p1
//        if (B != null) {
//            // compute X = sig.c*R + sig.r*B
//            var rB_p2: GroupElement = B_p3!!.scalarMultiply(sig.r)//ge_p2
//            val rB = PublicKey(rB_p2.toCompressedPoint())
//            var rB_p3: GroupElement
//            try {
//                rB_p3 = GroupElement(Ed25519.curve, rB.data)//ge_p3
//            } catch (e: IllegalArgumentException) {
//                return false
//            }
//            val rB_cached: GroupElement = rB_p3.toCached()//ge_cached
//            X_p1p1 = cR_p3.add(rB_cached)
//        }
//        else
//        {
//            // compute X = sig.c*R + sig.r*G
//            var rG_p3 = Ed25519.B.scalarMultiply(sig.r)
//            var rG_cached = rG_p3.toCached()
//            X_p1p1 = cR_p3.add(rG_cached)
//        }
//        var X_p2 = X_p1p1.toP2()
//
//        // compute sig.c*D
//        val cD_p2 = D_p3.scalarMultiply(sig.c)
//
//        // compute sig.r*A
//        val rA_p2 = A_p3.scalarMultiply(sig.r)
//
//        // compute Y = sig.c*D + sig.r*A
//        //TODO optimize
//        var cD = PublicKey(cD_p2.toCompressedPoint())
//        var rA = PublicKey(rA_p2.toCompressedPoint())
//        var cD_p3: GroupElement
//        var rA_p3: GroupElement
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
//        var rA_cached = rA_p3.toCached()
//        var Y_p1p1 = cD_p3.add(rA_cached)
//
//        var Y_p2 = Y_p1p1.toP2()
//
//        // compute c2 = Hs(Msg || D || X || Y)
//        val buf_msg = prefix_hash.data
//        val buf_D = D.data
//        val buf_X = X_p2.toCompressedPoint()
//        val buf_Y = Y_p2.toCompressedPoint()
//        val buf = buf_msg + buf_D + buf_X + buf_Y
//        val c2: ByteArray = hash_to_scalar(buf)
//
//        // test if c2 == sig.c
//        return sc_isnonzero(sc_sub(c2, sig.c))
//    }
//
//
///*
//Input:
//  a[0]+256*a[1]+...+256^31*a[31] = a
//  b[0]+256*b[1]+...+256^31*b[31] = b
//  c[0]+256*c[1]+...+256^31*c[31] = c
//
//Output:
//  s[0]+256*s[1]+...+256^31*s[31] = (c-ab) mod l
//  where l = 2^252 + 27742317777372353535851937790883648493.
//*/
//
//    private fun sc_mulsub(a: ByteArray, b: ByteArray, c: ByteArray): ByteArray {
//        //TODO
//        return ByteArray(32)
//    }
//    private fun random_scalar(): ByteArray = getRandomByteArray(32)
//
//    companion object {
//        fun hash_to_ec(key: PublicKey): GroupElement {
//            var res: GroupElement//ge_p3
//            var h: Hash
//            var point: GroupElement//ge_p2
//            var point2: GroupElement//ge_p1p1
//            cn_fast_hash(std::addressof(key), sizeof(public_key), h);
//            ge_fromfe_frombytes_vartime(&point, reinterpret_cast<const unsigned char *>(&h));
//            ge_mul8(&point2, &point);
//            ge_p1p1_to_p3(&res, &point2);
//        }
//
//    }
//}
//fun cn_fast_hash
////    static bool derive_public_key(const KeyDerivation &, size_t, const PublicKey &, const uint8_t*, size_t, PublicKey &);
////    //hack for pg
////    static bool underive_public_key_and_get_scalar(const KeyDerivation &, std::size_t, const PublicKey &, PublicKey &, EllipticCurveScalar &);
////    static void generate_incomplete_key_image(const PublicKey &, EllipticCurvePoint &);
////    //
////    static void derive_secret_key(const KeyDerivation &, size_t, const SecretKey &, SecretKey &);
////    static void derive_secret_key(const KeyDerivation &, size_t, const SecretKey &, const uint8_t*, size_t, SecretKey &);
////    static bool underive_public_key(const KeyDerivation &, size_t, const PublicKey &, PublicKey &);
////    static bool underive_public_key(const KeyDerivation &, size_t, const PublicKey &, const uint8_t*, size_t, PublicKey &);
////    static void generate_signature(const Hash &, const PublicKey &, const SecretKey &, Signature &);
////    static bool check_signature(const Hash &, const PublicKey &, const Signature &);
////    static void generate_key_image(const PublicKey &, const SecretKey &, KeyImage &);
////    static void hash_data_to_ec(const uint8_t*, std::size_t, PublicKey&);
////    static void generate_ring_signature(const Hash &, const KeyImage &,
////    const PublicKey *const *, size_t, const SecretKey &, size_t, Signature *);
////    static bool check_ring_signature(const Hash &, const KeyImage &,
////    const PublicKey *const *, size_t, const Signature *);
//}
