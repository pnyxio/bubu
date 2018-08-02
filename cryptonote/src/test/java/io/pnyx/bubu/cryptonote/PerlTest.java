package io.pnyx.bubu.cryptonote;

import org.junit.Test;

import java.math.BigInteger;

public class PerlTest {
    @Test
    public void doSome() {
        BigInteger p = bint(2).pow(255).subtract(bint(19));//F_p

        BigInteger l = bint(2).pow(252).add(bint("27742317777372353535851937790883648493"));
//#my $d = Math::BigInt->new(486662); 					#motgomery: y^2 = v^3 + 486662x^2 + v
        BigInteger d = bint(-121665).multiply(minv(121666, p)).mod(p);//twisted edwards: -v^2 +y^2 = 1 + d*v^2*y^2
        BigInteger x0 = bint("15112221349535400772501151409588531511454012693041857206046113283949847762202");
        BigInteger y0 = bint("46316835694926478169428394003475163141307993866256225615783033603165251855960");//y0 = 4/5
        BigInteger m = bint("7237005577332262213973186563042994240829374041602535252466099000494570602493");//p = 8m+5
        BigInteger ps = p.divide(bint(4));
//        my $pl = $p->copy()->bdec->bdiv(2);
        BigInteger pl = p.subtract(bint(1)).divide(bint(2));
        BigInteger ii = bint(2).modPow(ps,p);//#sqrt(-1)






    }

    private BigInteger bint(long l) {
        return BigInteger.valueOf(l);
    }

    private BigInteger bint(int i) {
        return BigInteger.valueOf(i);
    }

    private BigInteger bint(String s) {
        return new BigInteger(s);
    }
    private BigInteger minv(int i, BigInteger p) {
        BigInteger x = bint(i);
        return x.modPow(p.subtract(bint(2)),p);
    }

}
