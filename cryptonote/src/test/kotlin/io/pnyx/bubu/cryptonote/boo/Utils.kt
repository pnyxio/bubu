package io.pnyx.bubu.cryptonote.boo

import java.math.BigInteger

fun i(l: Long): BigInteger {
    return BigInteger.valueOf(l)
}

fun i(i: Int): BigInteger {
    return BigInteger.valueOf(i.toLong())
}

fun i(s: String): BigInteger {
    return BigInteger(s)
}
