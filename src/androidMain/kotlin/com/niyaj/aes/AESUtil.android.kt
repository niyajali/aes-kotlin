package com.niyaj.aes


// JVM implementation
actual class SecureRandom {
    private val random = java.security.SecureRandom()

    actual fun nextBytes(bytes: ByteArray) {
        random.nextBytes(bytes)
    }
}