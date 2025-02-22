package com.niyaj.aes

import kotlin.random.Random

// iOS implementation
actual class SecureRandom {
    actual fun nextBytes(bytes: ByteArray) {
        Random.nextBytes(bytes)
    }
}