package io.pnyx.ked25519.monero;

public class Assert {
    public static void isFalse(boolean b) {
        if(! b) {
            throw new IllegalArgumentException();
        }
    }
}
