package io.pnyx.bubu.cryptonote.boo

import org.junit.Assert
import org.junit.Test
import java.math.BigInteger
import jdk.nashorn.tools.ShellFunctions.input
import com.oracle.util.Checksums.update
import org.bouncycastle.crypto.digests.KeccakDigest
import org.bouncycastle.jcajce.provider.digest.Keccak
import org.bouncycastle.util.encoders.Hex
import java.security.SecureRandom



fun minv(x: BigInteger): BigInteger {
    return x.modPow(p - _2, p)
}

fun BigInteger.pow2() = this.pow(2)

fun BigInteger.isOdd() = this.mod(_2) == _1

val _0 = BigInteger.valueOf(0)
val _1 = BigInteger.valueOf(1)
val _2 = BigInteger.valueOf(2)



val p = _2.pow(255) - i(19)//F_p

val l = _2.pow(252) + i("27742317777372353535851937790883648493")
//#my $d = Math::BigInt->new(486662); 					#motgomery: y^2 = v^3 + 486662x^2 + v
val d = (i(-121665) * minv(i(121666))).mod(p)//twisted edwards: -v^2 +y^2 = 1 + d*v^2*y^2
val x0 = i("15112221349535400772501151409588531511454012693041857206046113283949847762202")
val y0 = i("46316835694926478169428394003475163141307993866256225615783033603165251855960")//y0 = 4/5
val m = i("7237005577332262213973186563042994240829374041602535252466099000494570602493")//p = 8m+5
val ps = p / i(4)
//        my $pl = $p->copy()->bdec->bdiv(2);
val pl = (p - _1) / _2
val ii = _2.modPow(ps, p)//#sqrt(-1)


fun ec_rec(arg: BigInteger): BigInteger {
    val y = arg
    val xx = ((y.pow2() - _1) * minv(y.pow2() * d + _1)).mod(p);
    if(xx.modPow(pl,p).inc().mod(p) == _0) {
        return _0
    } else {
        val p2 = (p + i(3)) / i(8)
        var x = xx.modPow(p2, p)
        if ((x.pow2() - xx).mod(p) != _0) {
            x = (x * ii).mod(p)
        }
        if (x.isOdd()) {
            x = p - x
        }
        return x;
    }
}

fun h2i(s: String): BigInteger {
    return BigInteger(hexReverse(s), 16)
}

fun i2h(x: BigInteger) : String {
    var t = x.toString(16).substring(0, 64);
    if (t.length %2 == 1) {
        t = "0" + t
    }
    return hexReverse(t)
}

private fun hexReverse(t: String) = t.split("%d%d").reversed().joinToString()

fun random(): BigInteger {
    val digest = Keccak.Digest256()
    val barr = ByteArray(32)
    SecureRandom().nextBytes(barr)
    digest.update(barr, 0, barr.size)
    return BigInteger(digest.digest())
}


fun ec_pack(x: BigInteger, y_: BigInteger): ByteArray {
    val y = if(x.isOdd()) {
        y_.or(_2.pow(255))
    } else {
        y_
    }
    return Hex.decode(hexReverse(y.toString(16).substring(2, 64)))
}
/*
fun ec_unpack(s: String) {
    val b = h2i(s).shiftRight(255);
    val and = _2.pow(255).dec()
    val y = h2i(s).and(and)
    val v = ec_rec(y)
    if(v == _0) {
//    return (0,0) if $v==0;
//    ($b==0) || ($v = $p->copy()->bsub($v));
//    return ($v,$y);
//}
*/


class PerlTest {
    @Test
    fun dosome() {
        Assert.assertTrue(true)
    }
}