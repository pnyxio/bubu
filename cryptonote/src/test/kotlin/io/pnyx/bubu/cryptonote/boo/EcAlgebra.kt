package io.pnyx.bubu.cryptonote.boo

import org.junit.Assert
import org.junit.Test
import java.math.BigInteger
import java.math.BigInteger.ONE
import java.math.BigInteger.ZERO

class Test  {
    @Test
    fun dotest() {
        val _29 = Fe(i(29), i(99))
        val _87 = Fe(i(87), i(99))

        val sum = _29 + _87
        println(sum.v)
        println(Fe(i(7), i(9)) * Fe(i(8), i(9)))
        println(Fe(i(8), i(9)) * Fe(i(7), i(9)))
//        for (i in 0..16)
//            println(Fe(i(2), i(17)).pow(i))

        println("============")
        for (i in 0..16)
            println(Fe(i(i), i(17)).mulInverse())
    }
}

fun gcd(x: BigInteger, y: BigInteger): BigInteger = when {
    x == ZERO -> y.abs()
    y == ZERO -> x.abs()
    x == y -> x.abs()
    x < y -> gcd(y, x)
    else -> gcd(y, mod(x, y))
}

fun mod(x: BigInteger, n: BigInteger) : BigInteger {
    Assert.assertTrue(n > ZERO)
    val rem = x % n
    val res = if(rem >= ZERO) rem else n + rem
    Assert.assertTrue(res >= ZERO)
    Assert.assertTrue(res < n)
    return res
}

class Fe(xx: BigInteger, val q: BigInteger) {
    val v : BigInteger
    init {
        v = if(xx > q || xx < ZERO) mod(xx, q) else xx
    }
    /////
    operator fun plus(fe: Fe): Fe {
        Assert.assertEquals(q, fe.q)
        val x = q - v//assert >= 0
        return if(x > fe.v) {
            Fe(fe.v + v, q)
        } else {
            Fe(fe.v - x, q)
        }
    }

    operator fun times(fe: Fe): Fe {
        Assert.assertEquals(q, fe.q)
        val a: Fe
        val b: Fe
        if(this < fe) {
            a = this
            b = fe
        } else {
            a = fe
            b = this
        }
        var s = b
        var r = Fe(ZERO, q)
        for(bit in a.v.toString(2).reversed()) {
            if(bit == '1') r = r + s
            s += s
        }
        return r
    }

    fun pow(exp: Int): Fe {
        if(exp == 0) return Fe(ONE, q)
        Assert.assertTrue(exp > 0)
        var m = this
        var r = Fe(ONE, q)
        for(bit in BigInteger.valueOf(exp.toLong()).toString(2).reversed()) {
            if(bit == '1') r = r * m
            m *= m
        }
        return r
    }

    @Throws
    fun mulInverse(): Fe {
//        if(gcd(v, q) > ONE)  throw IllegalStateException()

        if (q.isProbablePrime(1)) {
            return pow(q.longValueExact().toInt() - 2)
        }
        var _r = ZERO
        var _r1 = ONE
        var _q = q
        var _q1 = v
        while (_r1 != ZERO) {
            val quotient = _q / _q1
            val _r1tmp = _r1
            _r1 = _r - quotient * _r1
            _r = _r1tmp

            val _q1tmp = _q1
            _q1 = _q - quotient * _q1
            _q = _q1tmp
        }
        if (_q <= ONE) {
            return if (_r < ZERO) Fe( _r + q, q) else Fe( _r, q)
        } else {
            throw IllegalStateException()
        }
    }

    private operator fun compareTo(fe: Fe): Int {
        Assert.assertEquals(q, fe.q)
        return v.compareTo(fe.v)
    }

    override fun toString(): String {
        return "${v.toString(10)} mod ${q.toString(10)}"
    }
}

class Ge {

}

class Point {

}