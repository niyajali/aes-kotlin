package com.niyaj.aes

// Common code
expect class SecureRandom() {
    fun nextBytes(bytes: ByteArray)
}

object AESUtils {
    fun generateRandomIV(): ByteArray {
        return ByteArray(16).apply {
            SecureRandom().nextBytes(this)
        }
    }

    fun generateKey(sizeInBits: Int): ByteArray {
        require(sizeInBits in setOf(128, 192, 256)) { "Key size must be 128, 192, or 256 bits" }
        return ByteArray(sizeInBits / 8).apply {
            SecureRandom().nextBytes(this)
        }
    }

    fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { byte ->
            byte.toUByte().toString(16).padStart(2, '0')
        }
    }

    fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Hex string must have even length" }
        return ByteArray(hex.length / 2) {
            hex.substring(it * 2, it * 2 + 2).toInt(16).toByte()
        }
    }
}