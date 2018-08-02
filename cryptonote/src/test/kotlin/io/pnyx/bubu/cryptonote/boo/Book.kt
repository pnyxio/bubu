package io.pnyx.bubu.cryptonote.boo

import org.junit.Assert
import org.junit.Test

fun div1(a: Int, n: Int): Pair<Int,Int> {
    Assert.assertTrue(n > 0)
    if(a >= 0) {
        return Pair(a/n, a%n)
    } else {
        return Pair(a/n -1, n + a%n)
    }
    val y = a / n
}

fun mod(x: Int, n: Int) : Int {
    Assert.assertTrue(n > 0)
    val rem = x%n
    val res = if(rem >= 0) rem else n + rem
    Assert.assertTrue(res >= 0)
    Assert.assertTrue(res < n)
    return res
}

fun gcd_(x: Int, y: Int): Int = when {
    x == y -> Math.abs(x)
    y == 0 -> Math.abs(x)
    x < y -> gcd_(y, x)
    else -> gcd_(y, mod(x, y))
}

class Tt {
    @Test
    fun xxx() {
        println(gcd_(1066,1970))
    }
}