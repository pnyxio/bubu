package io.pnyx.ked25519

import io.pnyx.ked25519.Fe.Companion.fe
import io.pnyx.ked25519.MathUtils.getQ
import io.pnyx.ked25519.MathUtils.random
import net.i2p.crypto.eddsa.Utils
import net.i2p.crypto.eddsa.math.GroupElement
import org.hamcrest.core.IsEqual
import org.junit.Assert
import org.junit.Test
import net.i2p.crypto.eddsa.Utils.hexToBytes
import net.i2p.crypto.eddsa.math.Field
import net.i2p.crypto.eddsa.math.ed25519.Ed25519ScalarOps
import java.math.BigInteger
import net.i2p.crypto.eddsa.math.ed25519.Ed25519FieldElement
import net.i2p.crypto.eddsa.math.FieldElement
import java.security.SecureRandom
import kotlin.experimental.and
import org.hamcrest.core.IsNot




class BasicAlgebraTest  {
    @Test
    fun mathUtilsWorkAsExpected() {
        val neutral = GroupElement.p3(MathUtils.curve, MathUtils.curve.field.ZERO, MathUtils.curve.field.ONE, MathUtils.curve.field.ONE, MathUtils.curve.field.ZERO)
        for (i in 0..999) {
            val g = MathUtils.getRandomGroupElement()

            // Act:
            val h1 = MathUtils.addGroupElements(g, neutral)
            val h2 = MathUtils.addGroupElements(neutral, g)

            // Assert:
            Assert.assertThat(g, IsEqual.equalTo(h1))
            Assert.assertThat(g, IsEqual.equalTo(h2))
        }

        for (i in 0..999) {
            var g = MathUtils.getRandomGroupElement()

            // P3 -> P2.
            var h = MathUtils.toRepresentation(g, GroupElement.Representation.P2)
            Assert.assertThat(h, IsEqual.equalTo(g))
            // P3 -> P1P1.
            h = MathUtils.toRepresentation(g, GroupElement.Representation.P1P1)
            Assert.assertThat(g, IsEqual.equalTo(h))

            // P3 -> CACHED.
            h = MathUtils.toRepresentation(g, GroupElement.Representation.CACHED)
            Assert.assertThat(h, IsEqual.equalTo(g))

            // P3 -> P2 -> P3.
            g = MathUtils.toRepresentation(g, GroupElement.Representation.P2)
            h = MathUtils.toRepresentation(g, GroupElement.Representation.P3)
            Assert.assertThat(g, IsEqual.equalTo(h))

            // P3 -> P2 -> P1P1.
            g = MathUtils.toRepresentation(g, GroupElement.Representation.P2)
            h = MathUtils.toRepresentation(g, GroupElement.Representation.P1P1)
            Assert.assertThat(g, IsEqual.equalTo(h))
        }

        for (i in 0..9) {
            // Arrange:
            val g = MathUtils.getRandomGroupElement()

            // Act:
            val h = MathUtils.scalarMultiplyGroupElement(g, MathUtils.curve.field.ZERO)

            // Assert:
            Assert.assertThat(MathUtils.curve.getZero(GroupElement.Representation.P3), IsEqual.equalTo(h))
        }
    }
//    @Test
//    fun dotest() {
//        val _29 = fe(bi(29))
//        val _87 = fe(bi(87))
//
//        val sum = _29 + _87
//        println(sum.toBigInteger())
////        println(fe(i(7), i(9)) * fe(i(8), i(9)))
////        println(fe(i(8), i(9)) * fe(i(7), i(9)))
//////        for (i in 0..16)
//////            println(Fe(i(2), i(17)).pow(i))
////
////        println("============")
////        for (i in 0..16)
////            println(Fe(i(i), i(17)).mulInverse())
//    }
}

class Ed25519ScalarOpsTest {

    /**
     * Test method for [net.i2p.crypto.eddsa.math.bigint.BigIntegerScalarOps.reduce].
     */
    @Test
    fun testReduce() {
        // Example from test case 1
        val r = Utils.hexToBytes("b6b19cd8e0426f5983fa112d89a143aa97dab8bc5deb8d5b6253c928b65272f4044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d")
        Assert.assertArrayEquals(scalarOps.reduce(r), Utils.hexToBytes("f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404"))
    }

    @Test
    fun reduceReturnsExpectedResult() {
        for (i in 0..999) {
            // Arrange:
            val bytes = MathUtils.getRandomByteArray(64)

            // Act:
            val reduced1 = scalarOps.reduce(bytes)
            val reduced2 = MathUtils.reduceModGroupOrder(bytes)

            // Assert:
            Assert.assertThat(MathUtils.toBigInteger(reduced1).compareTo(MathUtils.getGroupOrder()), IsEqual.equalTo(-1))
            Assert.assertThat(MathUtils.toBigInteger(reduced1).compareTo(BigInteger("-1")), IsEqual.equalTo(1))
            Assert.assertThat(reduced1, IsEqual.equalTo(reduced2))
        }
    }

    /**
     * Test method for [net.i2p.crypto.eddsa.math.bigint.BigIntegerScalarOps.multiplyAndAdd].
     */
    @Test
    fun testMultiplyAndAdd() {
        // Example from test case 1
        val h = Utils.hexToBytes("86eabc8e4c96193d290504e7c600df6cf8d8256131ec2c138a3e7e162e525404")
        val a = Utils.hexToBytes("307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f")
        val r = Utils.hexToBytes("f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404")
        val S = Utils.hexToBytes("5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        Assert.assertArrayEquals(scalarOps.multiplyAndAdd(h, a, r), S)
    }

    @Test
    fun multiplyAndAddReturnsExpectedResult() {
        for (i in 0..999) {
            // Arrange:
            val bytes1 = MathUtils.getRandomByteArray(32)
            val bytes2 = MathUtils.getRandomByteArray(32)
            val bytes3 = MathUtils.getRandomByteArray(32)

            // Act:
            val result1 = scalarOps.multiplyAndAdd(bytes1, bytes2, bytes3)
            val result2 = MathUtils.multiplyAndAddModGroupOrder(bytes1, bytes2, bytes3)

            // Assert:
            Assert.assertThat(MathUtils.toBigInteger(result1).compareTo(MathUtils.getGroupOrder()), IsEqual.equalTo(-1))
            Assert.assertThat(MathUtils.toBigInteger(result1).compareTo(BigInteger("-1")), IsEqual.equalTo(1))
            Assert.assertThat(result1, IsEqual.equalTo(result2))
        }
    }

    companion object {

        private val scalarOps = Ed25519ScalarOps()
    }



}

class Ed25519LittleEndianEncodingTest {

    @Test
    fun encodeReturnsCorrectByteArrayForSimpleFieldElements() {
        // Arrange:
        val t1 = IntArray(10)
        val t2 = IntArray(10)
        t2[0] = 1
        val fieldElement1 = Ed25519FieldElement(MathUtils.getField(), t1)
        val fieldElement2 = Ed25519FieldElement(MathUtils.getField(), t2)

        // Act:
        val bytes1 = MathUtils.getField().encoding.encode(fieldElement1)
        val bytes2 = MathUtils.getField().encoding.encode(fieldElement2)

        // Assert:
        Assert.assertThat(bytes1, IsEqual.equalTo(MathUtils.toByteArray(BigInteger.ZERO)))
        Assert.assertThat(bytes2, IsEqual.equalTo(MathUtils.toByteArray(BigInteger.ONE)))
    }

    @Test
    fun encodeReturnsCorrectByteArray() {
        for (i in 0..9999) {
            // Arrange:
            val t = IntArray(10)
            for (j in 0..9) {
                t[j] = random.nextInt(1 shl 28) - (1 shl 27)
            }
            val fieldElement1 = Ed25519FieldElement(MathUtils.getField(), t)
            val b = MathUtils.toBigInteger(t)

            // Act:
            val bytes = MathUtils.getField().encoding.encode(fieldElement1)

            // Assert:
            Assert.assertThat(bytes, IsEqual.equalTo(MathUtils.toByteArray(b.mod(MathUtils.getQ()))))
        }
    }

//        @Test
//        fun decodeReturnsCorrectFieldElementForSimpleByteArrays() {
//            // Arrange:
//            val bytes1 = ByteArray(32)
//            val bytes2 = ByteArray(32)
//            bytes2[0] = 1
//
//            // Act:
//            val f1 = MathUtils.getField().encoding.decode(bytes1) as Ed25519FieldElement
//            val f2 = MathUtils.getField().encoding.decode(bytes2) as Ed25519FieldElement
//            val b1 = MathUtils.toBigInteger(f1.t)
//            val b2 = MathUtils.toBigInteger(f2.t)
//
//            // Assert:
//            Assert.assertThat(b1, IsEqual.equalTo(BigInteger.ZERO))
//            Assert.assertThat(b2, IsEqual.equalTo(BigInteger.ONE))
//        }

//        @Test
//        fun decodeReturnsCorrectFieldElement() {
//            for (i in 0..9999) {
//                // Arrange:
//                val bytes = ByteArray(32)
//                random.nextBytes(bytes)
//                bytes[31] = (bytes[31] and 0x7f.toByte()).toByte()//TODO miki
//                val b1 = MathUtils.toBigInteger(bytes)
//
//                // Act:
//                val f = MathUtils.getField().encoding.decode(bytes) as Ed25519FieldElement
//                val b2 = MathUtils.toBigInteger(f.t).mod(MathUtils.q)
//
//                // Assert:
//                Assert.assertThat(b2, IsEqual.equalTo(b1))
//            }
//        }

    @Test
    fun isNegativeReturnsCorrectResult() {
        for (i in 0..9999) {
            // Arrange:
            val t = IntArray(10)
            for (j in 0..9) {
                t[j] = random.nextInt(1 shl 28) - (1 shl 27)
            }
            val isNegative = MathUtils.toBigInteger(t).mod(MathUtils.getQ()).mod(BigInteger("2")) == BigInteger.ONE
            val f = Ed25519FieldElement(MathUtils.getField(), t)

            // Assert:
            Assert.assertThat(MathUtils.getField().encoding.isNegative(f), IsEqual.equalTo(isNegative))
        }
    }
}


class Ed25519FieldElementTest {

    protected val randomFieldElement: FieldElement
        get() = MathUtils.getRandomFieldElement()

    protected val q: BigInteger
        get() = MathUtils.getQ()

    protected val field: Field
        get() = MathUtils.getField()

    // endregion

    // region isNonZero

    protected val zeroFieldElement: FieldElement
        get() = Ed25519FieldElement(MathUtils.getField(), IntArray(10))

    protected val nonZeroFieldElement: FieldElement
        get() {
            val t = IntArray(10)
            t[0] = 5
            return Ed25519FieldElement(MathUtils.getField(), t)
        }

    protected fun toBigInteger(f: FieldElement): BigInteger {
        return MathUtils.toBigInteger(f)
    }

    // region constructor

    @Test
    fun canConstructFieldElementFromArrayWithCorrectLength() {
        // Assert:
        Ed25519FieldElement(MathUtils.getField(), IntArray(10))
    }

    @Test(expected = IllegalArgumentException::class)
    fun cannotConstructFieldElementFromArrayWithIncorrectLength() {
        // Assert:
        Ed25519FieldElement(MathUtils.getField(), IntArray(9))
    }

    @Test(expected = IllegalArgumentException::class)
    fun cannotConstructFieldElementWithoutField() {
        // Assert:
        Ed25519FieldElement(null, IntArray(9))
    }

    // endregion

    // region toString

    @Test
    fun toStringReturnsCorrectRepresentation() {
        // Arrange:
        val bytes = ByteArray(32)
        for (i in 0..31) {
            bytes[i] = (i + 1).toByte()
        }
        val f = MathUtils.getField().encoding.decode(bytes)

        // Act:
        val fAsString = f.toString()
        val builder = StringBuilder()
        builder.append("[Ed25519FieldElement val=")
        for (b in bytes) {
            builder.append(String.format("%02x", b))
        }
        builder.append("]")

        // Assert:
        Assert.assertThat(fAsString, IsEqual.equalTo(builder.toString()))
    }

    @Test
    fun isNonZeroReturnsFalseIfFieldElementIsZero() {
        // Act:
        val f = zeroFieldElement

        // Assert:
        Assert.assertThat(f.isNonZero(), IsEqual.equalTo(false))
    }

    @Test
    fun isNonZeroReturnsTrueIfFieldElementIsNonZero() {
        // Act:
        val f = nonZeroFieldElement

        // Assert:
        Assert.assertThat(f.isNonZero(), IsEqual.equalTo(true))
    }


    @Test
    fun addReturnsCorrectResult() {
        for (i in 0..999) {
            // Arrange:
            val f1 = randomFieldElement
            val f2 = randomFieldElement
            val b1 = toBigInteger(f1)
            val b2 = toBigInteger(f2)

            // Act:
            val f3 = f1.add(f2)
            val b3 = toBigInteger(f3).mod(q)

            // Assert:
            Assert.assertThat(b3, IsEqual.equalTo(b1.add(b2).mod(q)))
        }
    }

    // endregion


    @Test
    fun subtractReturnsCorrectResult() {
        for (i in 0..999) {
            // Arrange:
            val f1 = randomFieldElement
            val f2 = randomFieldElement
            val b1 = toBigInteger(f1)
            val b2 = toBigInteger(f2)

            // Act:
            val f3 = f1.subtract(f2)
            val b3 = toBigInteger(f3).mod(q)

            // Assert:
            Assert.assertThat(b3, IsEqual.equalTo(b1.subtract(b2).mod(q)))
        }
    }

    @Test
    fun negateReturnsCorrectResult() {
        for (i in 0..999) {
            // Arrange:
            val f1 = randomFieldElement
            val b1 = toBigInteger(f1)

            // Act:
            val f2 = f1.negate()
            val b2 = toBigInteger(f2).mod(q)

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.negate().mod(q)))
        }
    }

    @Test
    fun multiplyReturnsCorrectResult() {
        for (i in 0..999) {
            // Arrange:
            val f1 = randomFieldElement
            val f2 = randomFieldElement
            val b1 = toBigInteger(f1)
            val b2 = toBigInteger(f2)

            // Act:
            val f3 = f1.multiply(f2)
            val b3 = toBigInteger(f3).mod(q)

            // Assert:
            Assert.assertThat(b3, IsEqual.equalTo(b1.multiply(b2).mod(q)))
        }
    }

    @Test
    fun squareReturnsCorrectResult() {
        for (i in 0..999) {
            // Arrange:
            val f1 = randomFieldElement
            val b1 = toBigInteger(f1)

            // Act:
            val f2 = f1.square()
            val b2 = toBigInteger(f2).mod(q)

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.multiply(b1).mod(q)))
        }
    }

    @Test
    fun squareAndDoubleReturnsCorrectResult() {
        for (i in 0..999) {
            // Arrange:
            val f1 = randomFieldElement
            val b1 = toBigInteger(f1)

            // Act:
            val f2 = f1.squareAndDouble()
            val b2 = toBigInteger(f2).mod(q)

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.multiply(b1).multiply(BigInteger("2")).mod(q)))
        }
    }

    @Test
    fun invertReturnsCorrectResult() {
        for (i in 0..999) {
            // Arrange:
            val f1 = randomFieldElement
            val b1 = toBigInteger(f1)

            // Act:
            val f2 = f1.invert()
            val b2 = toBigInteger(f2).mod(q)

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.modInverse(q)))
        }
    }

    @Test
    fun pow22523ReturnsCorrectResult() {
        for (i in 0..999) {
            // Arrange:
            val f1 = randomFieldElement
            val b1 = toBigInteger(f1)

            // Act:
            val f2 = f1.pow22523()
            val b2 = toBigInteger(f2).mod(q)

            // Assert:
            Assert.assertThat(b2, IsEqual.equalTo(b1.modPow(BigInteger.ONE.shiftLeft(252).subtract(BigInteger("3")), q)))
        }
    }

    // endregion

    // region cmov

    @Test
    fun cmovReturnsCorrectResult() {
        val zero = zeroFieldElement
        val nz = nonZeroFieldElement
        val f = randomFieldElement

        Assert.assertThat(zero.cmov(nz, 0), IsEqual.equalTo<FieldElement>(zero))
        Assert.assertThat(zero.cmov(nz, 1), IsEqual.equalTo<FieldElement>(nz))

        Assert.assertThat(f.cmov(nz, 0), IsEqual.equalTo<FieldElement>(f))
        Assert.assertThat(f.cmov(nz, 1), IsEqual.equalTo<FieldElement>(nz))
    }

    // endregion

    // region hashCode / equals

    @Test
    fun equalsOnlyReturnsTrueForEquivalentObjects() {
        // Arrange:
        val f1 = randomFieldElement
        val f2 = field.getEncoding().decode(f1.toByteArray())
        val f3 = randomFieldElement
        val f4 = randomFieldElement

        // Assert:
        Assert.assertThat(f1, IsEqual.equalTo<FieldElement>(f2))
        Assert.assertThat(f1, IsNot.not(IsEqual.equalTo<FieldElement>(f3)))
        Assert.assertThat(f1, IsNot.not(IsEqual.equalTo<FieldElement>(f4)))
        Assert.assertThat(f3, IsNot.not(IsEqual.equalTo<FieldElement>(f4)))
    }

    @Test
    fun hashCodesAreEqualForEquivalentObjects() {
        // Arrange:
        val f1 = randomFieldElement
        val f2 = field.getEncoding().decode(f1.toByteArray())
        val f3 = randomFieldElement
        val f4 = randomFieldElement

        // Assert:
        Assert.assertThat(f1.hashCode(), IsEqual.equalTo<Int>(f2.hashCode()))
        Assert.assertThat(f1.hashCode(), IsNot.not(IsEqual.equalTo<Int>(f3.hashCode())))
        Assert.assertThat(f1.hashCode(), IsNot.not(IsEqual.equalTo<Int>(f4.hashCode())))
        Assert.assertThat(f3.hashCode(), IsNot.not(IsEqual.equalTo<Int>(f4.hashCode())))
    }
}