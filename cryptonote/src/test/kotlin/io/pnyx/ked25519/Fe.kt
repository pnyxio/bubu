package io.pnyx.ked25519

import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.math.Field
import net.i2p.crypto.eddsa.math.ed25519.Ed25519FieldElement
import net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding
import org.bouncycastle.math.ec.ECFieldElement
import org.bouncycastle.math.ec.custom.djb.Curve25519Field
import org.bouncycastle.math.ec.custom.djb.Curve25519FieldElement
import org.bouncycastle.math.raw.Nat256
import java.math.BigInteger

class Fe private constructor(private val x: Ed25519FieldElement) {

    fun toBigInteger(): BigInteger {
        return BigInteger(x.toByteArray())
    }

    operator fun plus(other: Fe) = Fe(x.add(other.x ) as Ed25519FieldElement)
    companion object {
        fun fe(bi: BigInteger) = Fe(ed25519field.encoding.decode(bi.toByteArray()) as Ed25519FieldElement)
        private val ed25519field = Field(
                256, // b
                Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
                Ed25519LittleEndianEncoding())
    }
}