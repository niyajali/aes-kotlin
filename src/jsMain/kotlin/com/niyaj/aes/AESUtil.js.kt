package com.niyaj.aes

import kotlin.random.Random

// Common code
actual class SecureRandom actual constructor() {
    actual fun nextBytes(bytes: ByteArray) {
        Random.nextBytes(bytes)
    }
}