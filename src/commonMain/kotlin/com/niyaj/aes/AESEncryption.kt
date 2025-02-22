package com.niyaj.aes

import kotlin.experimental.xor

import kotlin.experimental.xor

class AESEncryption(key: ByteArray) {
    private val encryptionKeys: Array<LongArray>
    private val decryptionKeys: Array<LongArray>

    init {
        val rounds = numberOfRounds[key.size] ?: throw IllegalArgumentException("Invalid key size (must be 16, 24, or 32 bytes)")
        encryptionKeys = Array(rounds + 1) { LongArray(4) }
        decryptionKeys = Array(rounds + 1) { LongArray(4) }

        val tk = convertToLong32(key)
        val roundKeyCount = (rounds + 1) * 4
        val keyChunkCount = key.size / 4

        for (i in 0 until keyChunkCount) {
            encryptionKeys[i shr 2][i % 4] = tk[i]
            decryptionKeys[rounds - (i shr 2)][i % 4] = tk[i]
        }

        var rconIndex = 0
        var t = keyChunkCount
        while (t < roundKeyCount) {
            var tt = tk[keyChunkCount - 1]
            tk[0] = tk[0] xor (
                    (S[((tt shr 16) and 0xFF).toInt()] shl 24) xor
                            (S[((tt shr 8) and 0xFF).toInt()] shl 16) xor
                            (S[(tt and 0xFF).toInt()] shl 8) xor
                            S[((tt shr 24) and 0xFF).toInt()] xor
                            (rcon[rconIndex] shl 24)
                    )
            rconIndex++

            if (keyChunkCount != 8) {
                for (i in 1 until keyChunkCount) {
                    tk[i] = tk[i] xor tk[i - 1]
                }
            } else {
                for (i in 1 until keyChunkCount / 2) {
                    tk[i] = tk[i] xor tk[i - 1]
                }
                tt = tk[keyChunkCount / 2 - 1]
                tk[keyChunkCount / 2] = tk[keyChunkCount / 2] xor (
                        S[(tt and 0xFF).toInt()] xor
                                (S[((tt shr 8) and 0xFF).toInt()] shl 8) xor
                                (S[((tt shr 16) and 0xFF).toInt()] shl 16) xor
                                (S[((tt shr 24) and 0xFF).toInt()] shl 24)
                        )
                for (i in keyChunkCount / 2 + 1 until keyChunkCount) {
                    tk[i] = tk[i] xor tk[i - 1]
                }
            }

            var i = 0
            while (i < keyChunkCount && t < roundKeyCount) {
                val r = t shr 2
                val c = t % 4
                encryptionKeys[r][c] = tk[i]
                decryptionKeys[rounds - r][c] = tk[i]
                i++
                t++
            }

            for (r in 1 until rounds) {
                for (c in 0 until 4) {
                    tt = decryptionKeys[r][c]
                    decryptionKeys[r][c] = (
                            U1[((tt shr 24) and 0xFF).toInt()] xor
                                    U2[((tt shr 16) and 0xFF).toInt()] xor
                                    U3[((tt shr 8) and 0xFF).toInt()] xor
                                    U4[(tt and 0xFF).toInt()]
                            )
                }
            }
        }
    }

    fun encrypt(plaintext: ByteArray): ByteArray {
        if (plaintext.size != 16) throw IllegalArgumentException("Invalid plaintext size (must be 16 bytes)")

        val rounds = encryptionKeys.size - 1
        val a = LongArray(4)
        val t = convertToLong32(plaintext)

        for (i in 0 until 4) {
            t[i] = t[i] xor encryptionKeys[0][i]
        }

        for (r in 1 until rounds) {
            for (i in 0 until 4) {
                a[i] = (
                        T1[((t[i] shr 24) and 0xFF).toInt()] xor
                                T2[((t[(i + 1) % 4] shr 16) and 0xFF).toInt()] xor
                                T3[((t[(i + 2) % 4] shr 8) and 0xFF).toInt()] xor
                                T4[(t[(i + 3) % 4] and 0xFF).toInt()] xor
                                encryptionKeys[r][i]
                        )
            }
            a.copyInto(t, 0, 0, 4)
        }

        val result = ByteArray(16)
        for (i in 0 until 4) {
            val tt = encryptionKeys[rounds][i]
            result[4 * i] = (S[((t[i] shr 24) and 0xFF).toInt()] xor (tt shr 24)).toByte()
            result[4 * i + 1] = (S[((t[(i + 1) % 4] shr 16) and 0xFF).toInt()] xor (tt shr 16)).toByte()
            result[4 * i + 2] = (S[((t[(i + 2) % 4] shr 8) and 0xFF).toInt()] xor (tt shr 8)).toByte()
            result[4 * i + 3] = (S[(t[(i + 3) % 4] and 0xFF).toInt()] xor tt).toByte()
        }

        return result
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        if (ciphertext.size != 16) throw IllegalArgumentException("Invalid ciphertext size (must be 16 bytes)")

        val rounds = decryptionKeys.size - 1
        val a = LongArray(4)
        val t = convertToLong32(ciphertext)

        for (i in 0 until 4) {
            t[i] = t[i] xor decryptionKeys[0][i]
        }

        for (r in 1 until rounds) {
            for (i in 0 until 4) {
                a[i] = (
                        T5[((t[i] shr 24) and 0xFF).toInt()] xor
                                T6[((t[(i + 3) % 4] shr 16) and 0xFF).toInt()] xor
                                T7[((t[(i + 2) % 4] shr 8) and 0xFF).toInt()] xor
                                T8[(t[(i + 1) % 4] and 0xFF).toInt()] xor
                                decryptionKeys[r][i]
                        )
            }
            a.copyInto(t, 0, 0, 4)
        }

        val result = ByteArray(16)
        for (i in 0 until 4) {
            val tt = decryptionKeys[rounds][i]
            result[4 * i] = (Si[((t[i] shr 24) and 0xFF).toInt()] xor (tt shr 24)).toByte()
            result[4 * i + 1] = (Si[((t[(i + 3) % 4] shr 16) and 0xFF).toInt()] xor (tt shr 16)).toByte()
            result[4 * i + 2] = (Si[((t[(i + 2) % 4] shr 8) and 0xFF).toInt()] xor (tt shr 8)).toByte()
            result[4 * i + 3] = (Si[(t[(i + 1) % 4] and 0xFF).toInt()] xor tt).toByte()
        }

        return result
    }

    private fun convertToLong32(bytes: ByteArray): LongArray {
        val result = LongArray(bytes.size / 4)
        for (i in result.indices) {
            val offset = i * 4
            result[i] = (
                    (bytes[offset].toLong() and 0xFF shl 24) or
                            (bytes[offset + 1].toLong() and 0xFF shl 16) or
                            (bytes[offset + 2].toLong() and 0xFF shl 8) or
                            (bytes[offset + 3].toLong() and 0xFF))
        }
        return result
    }

    companion object {
        private val numberOfRounds = mapOf(16 to 10, 24 to 12, 32 to 14)
        private val rcon: LongArray = rconKey
        private val S: LongArray = sBoxKey
        private val Si: LongArray = inverseSBoxKey

        private val T1: LongArray = transformationKeyOne
        private val T2: LongArray = transformationKeyTwo
        private val T3: LongArray = transformationKeyThree
        private val T4: LongArray = transformationKeyFour

        private val T5: LongArray = transformationKeyFive
        private val T6: LongArray = transformationKeySix
        private val T7: LongArray = transformationKeySeven
        private val T8: LongArray = transformationKeyEight

        private val U1: LongArray = expansionKeyOne
        private val U2: LongArray = expansionKeyTwo
        private val U3: LongArray = expansionKeyThree
        private val U4: LongArray = expansionKeyFour
    }
}

class ModeOfOperationECB(key: ByteArray) {
    private val aes = AESEncryption(key)

    fun encrypt(plaintext: ByteArray): ByteArray {
        if (plaintext.size % 16 != 0) throw IllegalArgumentException("Invalid plaintext size (must be multiple of 16 bytes)")
        val ciphertext = ByteArray(plaintext.size)
        val block = ByteArray(16)

        for (i in plaintext.indices step 16) {
            plaintext.copyInto(block, 0, i, i + 16)
            val encryptedBlock = aes.encrypt(block)
            encryptedBlock.copyInto(ciphertext, i, 0, 16)
        }

        return ciphertext
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        if (ciphertext.size % 16 != 0) throw IllegalArgumentException("Invalid ciphertext size (must be multiple of 16 bytes)")
        val plaintext = ByteArray(ciphertext.size)
        val block = ByteArray(16)

        for (i in ciphertext.indices step 16) {
            ciphertext.copyInto(block, 0, i, i + 16)
            val decryptedBlock = aes.decrypt(block)
            decryptedBlock.copyInto(plaintext, i, 0, 16)
        }

        return plaintext
    }
}

class ModeOfOperationCBC(private val key: ByteArray, private val iv: ByteArray) {
    private val aes = AESEncryption(key)
    private var lastCipherBlock = iv.copyOf()

    fun encrypt(plaintext: ByteArray): ByteArray {
        if (plaintext.size % 16 != 0) throw IllegalArgumentException("Invalid plaintext size (must be multiple of 16 bytes)")
        val ciphertext = ByteArray(plaintext.size)
        val block = ByteArray(16)

        for (i in plaintext.indices step 16) {
            plaintext.copyInto(block, 0, i, i + 16)
            for (j in 0 until 16) {
                block[j] = (block[j] xor lastCipherBlock[j]).toByte()
            }
            lastCipherBlock = aes.encrypt(block)
            lastCipherBlock.copyInto(ciphertext, i, 0, 16)
        }

        return ciphertext
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        if (ciphertext.size % 16 != 0) throw IllegalArgumentException("Invalid ciphertext size (must be multiple of 16 bytes)")
        val plaintext = ByteArray(ciphertext.size)
        val block = ByteArray(16)

        for (i in ciphertext.indices step 16) {
            ciphertext.copyInto(block, 0, i, i + 16)
            val decryptedBlock = aes.decrypt(block)
            for (j in 0 until 16) {
                plaintext[i + j] = (decryptedBlock[j] xor lastCipherBlock[j]).toByte()
            }
            ciphertext.copyInto(lastCipherBlock, 0, i, i + 16)
        }

        return plaintext
    }
}

class ModeOfOperationCFB(
    private val key: ByteArray,
    private val iv: ByteArray,
    private val segmentSize: Int = 1,
) {
    private val aes = AESEncryption(key)
    private var shiftRegister = iv.copyOf()

    fun encrypt(plaintext: ByteArray): ByteArray {
        if (plaintext.size % segmentSize != 0) throw IllegalArgumentException("Invalid plaintext size (must be multiple of segmentSize bytes)")
        val encrypted = plaintext.copyOf()

        for (i in encrypted.indices step segmentSize) {
            val xorSegment = aes.encrypt(shiftRegister)
            for (j in 0 until segmentSize) {
                encrypted[i + j] = (encrypted[i + j] xor xorSegment[j]).toByte()
            }

            shiftRegister.copyInto(shiftRegister, 0, segmentSize, shiftRegister.size)
            encrypted.copyInto(shiftRegister, shiftRegister.size - segmentSize, i, i + segmentSize)
        }

        return encrypted
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        if (ciphertext.size % segmentSize != 0) throw IllegalArgumentException("Invalid ciphertext size (must be multiple of segmentSize bytes)")
        val plaintext = ciphertext.copyOf()

        for (i in plaintext.indices step segmentSize) {
            val xorSegment = aes.encrypt(shiftRegister)
            for (j in 0 until segmentSize) {
                plaintext[i + j] = (plaintext[i + j] xor xorSegment[j]).toByte()
            }

            shiftRegister.copyInto(shiftRegister, 0, segmentSize, shiftRegister.size)
            ciphertext.copyInto(shiftRegister, shiftRegister.size - segmentSize, i, i + segmentSize)
        }

        return plaintext
    }
}

class ModeOfOperationOFB(private val key: ByteArray, private val iv: ByteArray) {
    private val aes = AESEncryption(key)
    private var lastPrecipher = iv.copyOf()
    private var lastPrecipherIndex = 16

    fun encrypt(plaintext: ByteArray): ByteArray {
        val encrypted = plaintext.copyOf()

        for (i in encrypted.indices) {
            if (lastPrecipherIndex == 16) {
                lastPrecipher = aes.encrypt(lastPrecipher)
                lastPrecipherIndex = 0
            }
            encrypted[i] = (encrypted[i] xor lastPrecipher[lastPrecipherIndex++]).toByte()
        }

        return encrypted
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        return encrypt(ciphertext)
    }
}

class Counter(private var counter: ByteArray) {
    init {
        if (counter.size != 16) throw IllegalArgumentException("Invalid counter size (must be 16 bytes)")
    }

    fun increment() {
        for (i in counter.indices.reversed()) {
            if (counter[i].toInt() == 255) {
                counter[i] = 0
            } else {
                counter[i] = (counter[i] + 1).toByte()
                break
            }
        }
    }

    fun getBytes(): ByteArray {
        return counter.copyOf()
    }
}

class ModeOfOperationCTR(private val key: ByteArray, private val counter: Counter) {
    private val aes = AESEncryption(key)
    private var remainingCounter: ByteArray? = null
    private var remainingCounterIndex = 16

    fun encrypt(plaintext: ByteArray): ByteArray {
        val encrypted = plaintext.copyOf()

        for (i in encrypted.indices) {
            if (remainingCounterIndex == 16) {
                remainingCounter = aes.encrypt(counter.getBytes())
                remainingCounterIndex = 0
                counter.increment()
            }
            encrypted[i] = (encrypted[i] xor remainingCounter!![remainingCounterIndex++]).toByte()
        }

        return encrypted
    }

    fun decrypt(ciphertext: ByteArray): ByteArray {
        return encrypt(ciphertext)
    }
}

fun pkcs7Pad(data: ByteArray, blockSize: Int): ByteArray {
    val padLength = blockSize - (data.size % blockSize)
    val paddedData = ByteArray(data.size + padLength)
    data.copyInto(paddedData, 0, 0, data.size)
    for (i in data.size until paddedData.size) {
        paddedData[i] = padLength.toByte()
    }
    return paddedData
}

fun pkcs7Strip(data: ByteArray): ByteArray {
    if (data.size < 16) throw IllegalArgumentException("PKCS#7 invalid length")
    val padder = data[data.size - 1].toInt()
    if (padder > 16) throw IllegalArgumentException("PKCS#7 padding byte out of range")
    val length = data.size - padder
    for (i in 0 until padder) {
        if (data[length + i] != padder.toByte()) throw IllegalArgumentException("PKCS#7 invalid padding byte")
    }
    val result = ByteArray(length)
    data.copyInto(result, 0, 0, length)
    return result
}

fun bytesToHex(bytes: ByteArray): String {
    return bytes.joinToString("") { byte ->
        byte.toUByte().toString(16).padStart(2, '0')
    }
}

fun encryptAesEcb(input: String): String {
    val key = "qwertyuioplkjhgf".encodeToByteArray()
    val inputBytes = input.encodeToByteArray()
    val paddedInput = pkcs7Pad(inputBytes, 16)
    val encryptedBytes = ModeOfOperationECB(key).encrypt(paddedInput)
    return bytesToHex(encryptedBytes)
}