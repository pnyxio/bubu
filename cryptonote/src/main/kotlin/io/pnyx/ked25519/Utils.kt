package io.pnyx.ked25519

object Assert {
    fun isFalse(b: Boolean) {
        if (b) {
            throw IllegalArgumentException()
        }
    }
    fun isTrue(b: Boolean) {
        if (!b) {
            throw IllegalArgumentException()
        }
    }
}
