package io.pnyx.ked25519

import net.i2p.crypto.eddsa.Utils
import java.math.BigInteger
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util.getCurve
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec
import java.security.SecureRandom
import org.hamcrest.core.IsEqual
import net.i2p.crypto.eddsa.math.GroupElement
import net.i2p.crypto.eddsa.math.FieldElement
import net.i2p.crypto.eddsa.Utils.bit
import net.i2p.crypto.eddsa.math.ed25519.Ed25519FieldElement
import net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding
import net.i2p.crypto.eddsa.Utils.hexToBytes
import net.i2p.crypto.eddsa.math.Field
import org.junit.Assert
import org.junit.Test
import kotlin.experimental.and


fun bi(l: Long): BigInteger {
    return BigInteger.valueOf(l)
}

fun bi(i: Int): BigInteger {
    return BigInteger.valueOf(i.toLong())
}

fun bi(s: String): BigInteger {
    return BigInteger(s)
}

object MathUtils {
    private val exponents = intArrayOf(0, 26, 26 + 25, 2 * 26 + 25, 2 * 26 + 2 * 25, 3 * 26 + 2 * 25, 3 * 26 + 3 * 25, 4 * 26 + 3 * 25, 4 * 26 + 4 * 25, 5 * 26 + 4 * 25)
    val random = SecureRandom()
    private val ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
    val curve = ed25519.curve
    private val d = BigInteger("-121665").multiply(BigInteger("121666").modInverse(getQ()))
    private val groupOrder = BigInteger.ONE.shiftLeft(252).add(BigInteger("27742317777372353535851937790883648493"))


    /**
     * Gets q = 2^255 - 19 as BigInteger.
     */
    fun getQ(): BigInteger {
        return BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
    }

    /**
     * Gets group order = 2^252 + 27742317777372353535851937790883648493 as BigInteger.
     */
    fun getGroupOrder(): BigInteger {
        return groupOrder
    }

    /**
     * Gets the underlying finite field with q=2^255 - 19 elements.
     *
     * @return The finite field.
     */
    fun getField(): Field {
        return Field(
                256, // b
                hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
                Ed25519LittleEndianEncoding())
    }

// region field element

    /**
     * Converts a 2^25.5 bit representation to a BigInteger.
     *
     *
     * Value: 2^exponents[0] * t[0] + 2^exponents[1] * t[1] + ... + 2^exponents[9] * t[9]
     *
     * @param t The 2^25.5 bit representation.
     * @return The BigInteger.
     */
    fun toBigInteger(t: IntArray): BigInteger {
        var b = BigInteger.ZERO
        for (i in 0..9) {
            b = b.add(BigInteger.ONE.multiply(BigInteger.valueOf(t[i].toLong())).shiftLeft(exponents[i]))
        }

        return b
    }

    /**
     * Converts a 2^8 bit representation to a BigInteger.
     *
     *
     * Value: bytes[0] + 2^8 * bytes[1] + ...
     *
     * @param bytes The 2^8 bit representation.
     * @return The BigInteger.
     */
    fun toBigInteger(bytes: ByteArray): BigInteger {
        var b = BigInteger.ZERO
        for (i in bytes.indices) {
            b = b.add(BigInteger.ONE.multiply(BigInteger.valueOf((
                    java.lang.Byte.toUnsignedLong(bytes[i])//bytes[i] and 0xff
                    ).toLong())).shiftLeft(i * 8))//TODO miki
        }

        return b
    }

    /**
     * Converts a field element to a BigInteger.
     *
     * @param f The field element.
     * @return The BigInteger.
     */
    fun toBigInteger(f: FieldElement): BigInteger {
        return toBigInteger(f.toByteArray())
    }

    /**
     * Converts a BigInteger to a field element.
     *
     * @param b The BigInteger.
     * @return The field element.
     */
    fun toFieldElement(b: BigInteger): FieldElement {
        return getField().getEncoding().decode(toByteArray(b))
    }

    /**
     * Converts a BigInteger to a little endian 32 byte representation.
     *
     * @param b The BigInteger.
     * @return The 32 byte representation.
     */
    fun toByteArray(b: BigInteger): ByteArray {
        if (b.compareTo(BigInteger.ONE.shiftLeft(256)) >= 0) {
            throw RuntimeException("only numbers < 2^256 are allowed")
        }
        val bytes = ByteArray(32)
        val original = b.toByteArray()

        // Although b < 2^256, original can have length > 32 with some bytes set to 0.
        val offset = if (original.size > 32) original.size - 32 else 0
        for (i in 0 until original.size - offset) {
            bytes[original.size - i - offset - 1] = original[i + offset]
        }

        return bytes
    }

    /**
     * Reduces an integer in 2^8 bit representation modulo the group order and returns the result.
     *
     * @param bytes The integer in 2^8 bit representation.
     * @return The mod group order reduced integer.
     */
    fun reduceModGroupOrder(bytes: ByteArray): ByteArray {
        val b = toBigInteger(bytes).mod(groupOrder)
        return toByteArray(b)
    }

    /**
     * Calculates (a * b + c) mod group order and returns the result.
     *
     *
     * a, b and c are given in 2^8 bit representation.
     *
     * @param a The first integer.
     * @param b The second integer.
     * @param c The third integer.
     * @return The mod group order reduced result.
     */
    fun multiplyAndAddModGroupOrder(a: ByteArray, b: ByteArray, c: ByteArray): ByteArray {
        val result = toBigInteger(a).multiply(toBigInteger(b)).add(toBigInteger(c)).mod(groupOrder)
        return toByteArray(result)
    }

    fun getRandomByteArray(length: Int): ByteArray {
        val bytes = ByteArray(length)
        random.nextBytes(bytes)
        return bytes
    }

    /**
     * Gets a random field element where |t[i]| <= 2^24 for 0 <= i <= 9.
     *
     * @return The field element.
     */
    fun getRandomFieldElement(): FieldElement {
        val t = IntArray(10)
        for (j in 0..9) {
            t[j] = random.nextInt(1 shl 25) - (1 shl 24)
        }
        return Ed25519FieldElement(getField(), t)
    }

// endregion

// region group element

    /**
     * Gets a random group element in P3 representation.
     *
     * @return The group element.
     */
    fun getRandomGroupElement(): GroupElement {
        return getRandomGroupElement(false)
    }

    /**
     * Gets a random group element in P3 representation, with precmp and dblPrecmp populated.
     *
     * @return The group element.
     */
    fun getRandomGroupElement(precompute: Boolean): GroupElement {
        val bytes = ByteArray(32)
        while (true) {
            try {
                random.nextBytes(bytes)
                return GroupElement(curve, bytes, precompute)
            } catch (e: IllegalArgumentException) {
                // Will fail in about 87.5%, so try again.
            }

        }
    }

    /**
     * Creates a group element from a byte array.
     *
     *
     * Bit 0 to 254 are the affine y-coordinate, bit 255 is the sign of the affine x-coordinate.
     *
     * @param bytes the byte array.
     * @return The group element.
     */
    fun toGroupElement(bytes: ByteArray): GroupElement {
        val shouldBeNegative = bytes[31] /*miki*/.toInt()/**/ shr 7 != 0//TODO
        bytes[31] = bytes[31] and 0x7f
        val y = MathUtils.toBigInteger(bytes)

        // x = sign(x) * sqrt((y^2 - 1) / (d * y^2 + 1))
        val u = y.multiply(y).subtract(BigInteger.ONE).mod(getQ())
        val v = d.multiply(y).multiply(y).add(BigInteger.ONE).mod(getQ())
        val tmp = u.multiply(v.pow(7)).modPow(BigInteger.ONE.shiftLeft(252).subtract(BigInteger("3")), getQ()).mod(getQ())
        var x = tmp.multiply(u).multiply(v.pow(3)).mod(getQ())
        if (v.multiply(x).multiply(x).subtract(u).mod(getQ()) != BigInteger.ZERO) {
            if (v.multiply(x).multiply(x).add(u).mod(getQ()) != BigInteger.ZERO) {
                throw IllegalArgumentException("not a valid GroupElement")
            }
            x = x.multiply(toBigInteger(curve.i)).mod(getQ())
        }
        val isNegative = x.mod(BigInteger("2")) == BigInteger.ONE
        if (shouldBeNegative && !isNegative || !shouldBeNegative && isNegative) {
            x = x.negate().mod(getQ())
        }

        return GroupElement.p3(curve, toFieldElement(x), toFieldElement(y), getField().ONE, toFieldElement(x.multiply(y).mod(getQ())))
    }

    /**
     * Converts a group element from one representation to another.
     * This method is a helper used to test various methods in GroupElement.
     *
     * @param g The group element.
     * @param repr The desired representation.
     * @return The same group element in the new representation.
     */
    fun toRepresentation(g: GroupElement, repr: GroupElement.Representation): GroupElement {
        val x: BigInteger
        val y: BigInteger
        val gX = toBigInteger(g.x.toByteArray())
        val gY = toBigInteger(g.y.toByteArray())
        val gZ = toBigInteger(g.z.toByteArray())
        val gT = if (null == g.t) null else toBigInteger(g.t.toByteArray())

        // Switch to affine coordinates.
        when (g.representation) {
            GroupElement.Representation.P2, GroupElement.Representation.P3, GroupElement.Representation.P3PrecomputedDouble -> {
                x = gX.multiply(gZ.modInverse(getQ())).mod(getQ())
                y = gY.multiply(gZ.modInverse(getQ())).mod(getQ())
            }
            GroupElement.Representation.P1P1 -> {
                x = gX.multiply(gZ.modInverse(getQ())).mod(getQ())
                y = gY.multiply(gT!!.modInverse(getQ())).mod(getQ())
            }
            GroupElement.Representation.CACHED -> {
                x = gX.subtract(gY).multiply(gZ.multiply(BigInteger("2")).modInverse(getQ())).mod(getQ())
                y = gX.add(gY).multiply(gZ.multiply(BigInteger("2")).modInverse(getQ())).mod(getQ())
            }
            GroupElement.Representation.PRECOMP -> {
                x = gX.subtract(gY).multiply(BigInteger("2").modInverse(getQ())).mod(getQ())
                y = gX.add(gY).multiply(BigInteger("2").modInverse(getQ())).mod(getQ())
            }
            else -> throw UnsupportedOperationException()
        }

        // Now back to the desired representation.
        when (repr) {
            GroupElement.Representation.P2 -> return GroupElement.p2(
                    curve,
                    toFieldElement(x),
                    toFieldElement(y),
                    getField().ONE)
            GroupElement.Representation.P3 -> return GroupElement.p3(
                    curve,
                    toFieldElement(x),
                    toFieldElement(y),
                    getField().ONE,
                    toFieldElement(x.multiply(y).mod(getQ())), false)
            GroupElement.Representation.P3PrecomputedDouble -> return GroupElement.p3(
                    curve,
                    toFieldElement(x),
                    toFieldElement(y),
                    getField().ONE,
                    toFieldElement(x.multiply(y).mod(getQ())), true)
            GroupElement.Representation.P1P1 -> return GroupElement.p1p1(
                    curve,
                    toFieldElement(x),
                    toFieldElement(y),
                    getField().ONE,
                    getField().ONE)
            GroupElement.Representation.CACHED -> return GroupElement.cached(
                    curve,
                    toFieldElement(y.add(x).mod(getQ())),
                    toFieldElement(y.subtract(x).mod(getQ())),
                    getField().ONE,
                    toFieldElement(d.multiply(BigInteger("2")).multiply(x).multiply(y).mod(getQ())))
            GroupElement.Representation.PRECOMP -> return GroupElement.precomp(
                    curve,
                    toFieldElement(y.add(x).mod(getQ())),
                    toFieldElement(y.subtract(x).mod(getQ())),
                    toFieldElement(d.multiply(BigInteger("2")).multiply(x).multiply(y).mod(getQ())))
            else -> throw UnsupportedOperationException()
        }
    }

    /**
     * Adds two group elements and returns the result in P3 representation.
     * It uses BigInteger arithmetic and the affine representation.
     * This method is a helper used to test the projective group addition formulas in GroupElement.
     *
     * @param g1 The first group element.
     * @param g2 The second group element.
     * @return The result of the addition.
     */
    fun addGroupElements(g1: GroupElement, g2: GroupElement): GroupElement {
        // Relying on a special representation of the group elements.
        if (g1.representation != GroupElement.Representation.P2 && g1.representation != GroupElement.Representation.P3 || g2.representation != GroupElement.Representation.P2 && g2.representation != GroupElement.Representation.P3) {
            throw IllegalArgumentException("g1 and g2 must have representation P2 or P3")
        }

        // Projective coordinates
        val g1X = toBigInteger(g1.x.toByteArray())
        val g1Y = toBigInteger(g1.y.toByteArray())
        val g1Z = toBigInteger(g1.z.toByteArray())
        val g2X = toBigInteger(g2.x.toByteArray())
        val g2Y = toBigInteger(g2.y.toByteArray())
        val g2Z = toBigInteger(g2.z.toByteArray())

        // Affine coordinates
        val g1x = g1X.multiply(g1Z.modInverse(getQ())).mod(getQ())
        val g1y = g1Y.multiply(g1Z.modInverse(getQ())).mod(getQ())
        val g2x = g2X.multiply(g2Z.modInverse(getQ())).mod(getQ())
        val g2y = g2Y.multiply(g2Z.modInverse(getQ())).mod(getQ())

        // Addition formula for affine coordinates. The formula is complete in our case.
        //
        // (x3, y3) = (x1, y1) + (x2, y2) where
        //
        // x3 = (x1 * y2 + x2 * y1) / (1 + d * x1 * x2 * y1 * y2) and
        // y3 = (x1 * x2 + y1 * y2) / (1 - d * x1 * x2 * y1 * y2) and
        // d = -121665/121666
        val dx1x2y1y2 = d.multiply(g1x).multiply(g2x).multiply(g1y).multiply(g2y).mod(getQ())
        val x3 = g1x.multiply(g2y).add(g2x.multiply(g1y))
                .multiply(BigInteger.ONE.add(dx1x2y1y2).modInverse(getQ())).mod(getQ())
        val y3 = g1x.multiply(g2x).add(g1y.multiply(g2y))
                .multiply(BigInteger.ONE.subtract(dx1x2y1y2).modInverse(getQ())).mod(getQ())
        val t3 = x3.multiply(y3).mod(getQ())

        return GroupElement.p3(g1.curve, toFieldElement(x3), toFieldElement(y3), getField().ONE, toFieldElement(t3))
    }

    /**
     * Doubles a group element and returns the result in P3 representation.
     * It uses BigInteger arithmetic and the affine representation.
     * This method is a helper used to test the projective group doubling formula in GroupElement.
     *
     * @param g The group element.
     * @return g+g.
     */
    fun doubleGroupElement(g: GroupElement): GroupElement {
        return addGroupElements(g, g)
    }

    /**
     * Scalar multiply the group element by the field element.
     *
     * @param g The group element.
     * @param f The field element.
     * @return The resulting group element.
     */
    fun scalarMultiplyGroupElement(g: GroupElement, f: FieldElement): GroupElement {
        val bytes = f.toByteArray()
        var h = curve.getZero(GroupElement.Representation.P3)
        for (i in 254 downTo 0) {
            h = doubleGroupElement(h)
            if (Utils.bit(bytes, i) === 1) {
                h = addGroupElements(h, g)
            }
        }

        return h
    }

    /**
     * Calculates f1 * g1 + f2 * g2.
     *
     * @param g1 The first group element.
     * @param f1 The first multiplier.
     * @param g2 The second group element.
     * @param f2 The second multiplier.
     * @return The resulting group element.
     */
    fun doubleScalarMultiplyGroupElements(
            g1: GroupElement,
            f1: FieldElement,
            g2: GroupElement,
            f2: FieldElement): GroupElement {
        val h1 = scalarMultiplyGroupElement(g1, f1)
        val h2 = scalarMultiplyGroupElement(g2, f2)
        return addGroupElements(h1, h2)
    }

    /**
     * Negates a group element.
     *
     * @param g The group element.
     * @return The negated group element.
     */
    fun negateGroupElement(g: GroupElement): GroupElement {
        if (g.representation != GroupElement.Representation.P3) {
            throw IllegalArgumentException("g must have representation P3")
        }

        return GroupElement.p3(g.curve, g.x.negate(), g.y, g.z, g.t.negate())
    }

    // Start TODO BR: Remove when finished!

}