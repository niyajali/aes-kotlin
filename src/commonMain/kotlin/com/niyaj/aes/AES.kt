package com.niyaj.aes

import kotlin.experimental.xor

// Enhanced AESEncryption implementation
class AES(key: ByteArray) {
    private val encryptionKeys: Array<LongArray>
    private val decryptionKeys: Array<LongArray>
    private val rounds: Int =
        numberOfRounds[key.size] ?: throw IllegalArgumentException("Invalid key size")

    init {
        encryptionKeys = Array(rounds + 1) { LongArray(4) }
        decryptionKeys = Array(rounds + 1) { LongArray(4) }
        expandKey(key)
    }

    private fun expandKey(key: ByteArray) {
        val keyWords = key.size / 4
        val totalWords = (rounds + 1) * 4
        val temp = LongArray(totalWords)

        // Copy initial key
        for (i in 0 until keyWords) {
            temp[i] = bytesToLong(key, i * 4)
        }

        // Generate additional round keys
        for (i in keyWords until totalWords) {
            var t = temp[i - 1]
            if (i % keyWords == 0) {
                t = subWord(rotWord(t)) xor (AESConstants.rcon[i / keyWords].toLong() shl 24)
            } else if (keyWords > 6 && i % keyWords == 4) {
                t = subWord(t)
            }
            temp[i] = temp[i - keyWords] xor t
        }

        // Copy to encryption and decryption keys
        for (i in 0..rounds) {
            for (j in 0..3) {
                encryptionKeys[i][j] = temp[i * 4 + j]
                decryptionKeys[rounds - i][j] = temp[i * 4 + j]
            }
        }

        // Apply inverse mix columns to decryption keys
        for (i in 1 until rounds) {
            for (j in 0..3) {
                decryptionKeys[i][j] = invMixColumn(decryptionKeys[i][j])
            }
        }
    }

    private fun subWord(word: Long): Long {
        return ((AESConstants.S[((word shr 24) and 0xFF).toInt()].toLong() shl 24) or
                (AESConstants.S[((word shr 16) and 0xFF).toInt()].toLong() shl 16) or
                (AESConstants.S[((word shr 8) and 0xFF).toInt()].toLong() shl 8) or
                AESConstants.S[(word and 0xFF).toInt()].toLong())
    }

    private fun rotWord(word: Long): Long {
        return ((word shl 8) or (word shr 24)) and 0xFFFFFFFFL
    }

    private fun invMixColumn(word: Long): Long {
        return (AESConstants.T0i[((word shr 24) and 0xFF).toInt()] xor
                AESConstants.T1i[((word shr 16) and 0xFF).toInt()] xor
                AESConstants.T2i[((word shr 8) and 0xFF).toInt()] xor
                AESConstants.T3i[(word and 0xFF).toInt()])
    }

    fun encrypt(input: ByteArray): ByteArray {
        require(input.size == 16) { "Input must be 16 bytes" }

        val state = Array(4) { LongArray(4) }
        for (i in 0..3) {
            for (j in 0..3) {
                state[j][i] = input[4 * i + j].toLong() and 0xFF
            }
        }

        addRoundKey(state, 0)

        for (round in 1 until rounds) {
            subBytes(state)
            shiftRows(state)
            mixColumns(state)
            addRoundKey(state, round)
        }

        subBytes(state)
        shiftRows(state)
        addRoundKey(state, rounds)

        val result = ByteArray(16)
        for (i in 0..3) {
            for (j in 0..3) {
                result[4 * i + j] = (state[j][i] and 0xFF).toByte()
            }
        }

        return result
    }

    fun decrypt(input: ByteArray): ByteArray {
        require(input.size == 16) { "Input must be 16 bytes" }

        val state = Array(4) { LongArray(4) }
        for (i in 0..3) {
            for (j in 0..3) {
                state[j][i] = input[4 * i + j].toLong() and 0xFF
            }
        }

        addRoundKey(state, rounds)
        invShiftRows(state)
        invSubBytes(state)

        for (round in rounds - 1 downTo 1) {
            addRoundKey(state, round)
            invMixColumns(state)
            invShiftRows(state)
            invSubBytes(state)
        }

        addRoundKey(state, 0)

        val result = ByteArray(16)
        for (i in 0..3) {
            for (j in 0..3) {
                result[4 * i + j] = (state[j][i] and 0xFF).toByte()
            }
        }

        return result
    }

    private fun addRoundKey(state: Array<LongArray>, round: Int) {
        for (i in 0..3) {
            for (j in 0..3) {
                state[i][j] = state[i][j] xor ((encryptionKeys[round][i] shr (24 - 8 * j)) and 0xFF)
            }
        }
    }

    private fun subBytes(state: Array<LongArray>) {
        for (i in 0..3) {
            for (j in 0..3) {
                state[i][j] = AESConstants.S[(state[i][j] and 0xFF).toInt()].toLong()
            }
        }
    }

    private fun shiftRows(state: Array<LongArray>) {
        for (i in 1..3) {
            val temp = state[i].copyOf()
            for (j in 0..3) {
                state[i][j] = temp[(j + i) % 4]
            }
        }
    }

    private fun mixColumns(state: Array<LongArray>) {
        for (i in 0..3) {
            val s0 = state[0][i]
            val s1 = state[1][i]
            val s2 = state[2][i]
            val s3 = state[3][i]

            state[0][i] = AESConstants.T0[(s0 and 0xFF).toInt()] xor
                    AESConstants.T1[(s1 and 0xFF).toInt()] xor
                    AESConstants.T2[(s2 and 0xFF).toInt()] xor
                    AESConstants.T3[(s3 and 0xFF).toInt()]

            state[1][i] = AESConstants.T0[(s1 and 0xFF).toInt()] xor
                    AESConstants.T1[(s2 and 0xFF).toInt()] xor
                    AESConstants.T2[(s3 and 0xFF).toInt()] xor
                    AESConstants.T3[(s0 and 0xFF).toInt()]

            state[2][i] = AESConstants.T0[(s2 and 0xFF).toInt()] xor
                    AESConstants.T1[(s3 and 0xFF).toInt()] xor
                    AESConstants.T2[(s0 and 0xFF).toInt()] xor
                    AESConstants.T3[(s1 and 0xFF).toInt()]

            state[3][i] = AESConstants.T0[(s3 and 0xFF).toInt()] xor
                    AESConstants.T1[(s0 and 0xFF).toInt()] xor
                    AESConstants.T2[(s1 and 0xFF).toInt()] xor
                    AESConstants.T3[(s2 and 0xFF).toInt()]
        }
    }

    private fun invSubBytes(state: Array<LongArray>) {
        for (i in 0..3) {
            for (j in 0..3) {
                state[i][j] = AESConstants.Si[(state[i][j] and 0xFF).toInt()].toLong()
            }
        }
    }

    private fun invShiftRows(state: Array<LongArray>) {
        for (i in 1..3) {
            val temp = state[i].copyOf()
            for (j in 0..3) {
                state[i][(j + i) % 4] = temp[j]
            }
        }
    }

    private fun invMixColumns(state: Array<LongArray>) {
        for (i in 0..3) {
            val s0 = state[0][i]
            val s1 = state[1][i]
            val s2 = state[2][i]
            val s3 = state[3][i]

            state[0][i] = AESConstants.T0i[(s0 and 0xFF).toInt()] xor
                    AESConstants.T1i[(s1 and 0xFF).toInt()] xor
                    AESConstants.T2i[(s2 and 0xFF).toInt()] xor
                    AESConstants.T3i[(s3 and 0xFF).toInt()]

            state[1][i] = AESConstants.T0i[(s1 and 0xFF).toInt()] xor
                    AESConstants.T1i[(s2 and 0xFF).toInt()] xor
                    AESConstants.T2i[(s3 and 0xFF).toInt()] xor
                    AESConstants.T3i[(s0 and 0xFF).toInt()]

            state[2][i] = AESConstants.T0i[(s2 and 0xFF).toInt()] xor
                    AESConstants.T1i[(s3 and 0xFF).toInt()] xor
                    AESConstants.T2i[(s0 and 0xFF).toInt()] xor
                    AESConstants.T3i[(s1 and 0xFF).toInt()]

            state[3][i] = AESConstants.T0i[(s3 and 0xFF).toInt()] xor
                    AESConstants.T1i[(s0 and 0xFF).toInt()] xor
                    AESConstants.T2i[(s1 and 0xFF).toInt()] xor
                    AESConstants.T3i[(s2 and 0xFF).toInt()]
        }
    }

    private fun bytesToLong(bytes: ByteArray, offset: Int): Long {
        return ((bytes[offset].toLong() and 0xFF) shl 24) or
                ((bytes[offset + 1].toLong() and 0xFF) shl 16) or
                ((bytes[offset + 2].toLong() and 0xFF) shl 8) or
                (bytes[offset + 3].toLong() and 0xFF)
    }

    companion object {
        private val numberOfRounds = mapOf(
            16 to 10, // AES-128
            24 to 12, // AES-192
            32 to 14  // AES-256
        )
    }
}

// Improved block cipher mode implementations
sealed class BlockCipherMode {
    abstract fun encrypt(data: ByteArray): ByteArray
    abstract fun decrypt(data: ByteArray): ByteArray

    protected fun validateBlockSize(data: ByteArray) {
        require(data.size % 16 == 0) { "Data length must be multiple of 16 bytes" }
    }
}

class ECBMode(private val aes: AES) : BlockCipherMode() {
    override fun encrypt(data: ByteArray): ByteArray {
        validateBlockSize(data)
        return data.chunked(16)
            .map { aes.encrypt(it) }
            .flatten()
    }

    override fun decrypt(data: ByteArray): ByteArray {
        validateBlockSize(data)
        return data.chunked(16)
            .map { aes.decrypt(it) }
            .flatten()
    }
}

class CBCMode(private val aes: AES, private val iv: ByteArray) : BlockCipherMode() {
    init {
        require(iv.size == 16) { "IV must be 16 bytes" }
    }

    override fun encrypt(data: ByteArray): ByteArray {
        validateBlockSize(data)
        var previousBlock = iv
        return data.chunked(16)
            .map { block ->
                val xoredBlock =
                    block.zip(previousBlock) { a, b -> (a xor b).toByte() }.toByteArray()
                val encryptedBlock = aes.encrypt(xoredBlock)
                previousBlock = encryptedBlock
                encryptedBlock
            }
            .flatten()
    }

    override fun decrypt(data: ByteArray): ByteArray {
        validateBlockSize(data)
        var previousBlock = iv
        return data.chunked(16)
            .map { block ->
                val decryptedBlock = aes.decrypt(block)
                val plaintext = decryptedBlock.zip(previousBlock) { a, b ->
                    (a xor b)
                }.toByteArray()
                previousBlock = block
                plaintext
            }
            .flatten()
    }
}

class CTRMode(private val aes: AES, private val nonce: ByteArray) : BlockCipherMode() {
    private var counter = 0L

    init {
        require(nonce.size == 8) { "Nonce must be 8 bytes" }
    }

    private fun generateCounterBlock(): ByteArray {
        return ByteArray(16).apply {
            nonce.copyInto(this)
            val counterBytes = counter.toBigEndian()
            counterBytes.copyInto(this, 8)
            counter++
        }
    }

    override fun encrypt(data: ByteArray): ByteArray {
        return processBlocks(data)
    }

    override fun decrypt(data: ByteArray): ByteArray {
        return processBlocks(data)
    }

    private fun processBlocks(data: ByteArray): ByteArray {
        return ByteArray(data.size).also { result ->
            var offset = 0
            while (offset < data.size) {
                val counterBlock = generateCounterBlock()
                val keystream = aes.encrypt(counterBlock)

                val length = minOf(16, data.size - offset)
                for (i in 0 until length) {
                    result[offset + i] = (data[offset + i] xor keystream[i]).toByte()
                }
                offset += length
            }
        }
    }
}

class CFBMode(
    private val aes: AES,
    private val iv: ByteArray,
    private val segmentSize: Int = 8
) : BlockCipherMode() {

    init {
        require(iv.size == 16) { "IV must be 16 bytes" }
        require(segmentSize in setOf(1, 8, 16, 32, 64, 128)) { "Invalid segment size" }
    }

    override fun encrypt(data: ByteArray): ByteArray {
        val register = iv.copyOf()
        return ByteArray(data.size).also { result ->
            var offset = 0
            while (offset < data.size) {
                val keystream = aes.encrypt(register)
                val segmentBytes = minOf(segmentSize, data.size - offset)

                for (i in 0 until segmentBytes) {
                    result[offset + i] = (data[offset + i] xor keystream[i]).toByte()
                }

                // Shift register
                register.copyInto(register, 0, segmentBytes)
                result.copyInto(register, 16 - segmentBytes, offset, offset + segmentBytes)

                offset += segmentBytes
            }
        }
    }

    override fun decrypt(data: ByteArray): ByteArray {
        val register = iv.copyOf()
        return ByteArray(data.size).also { result ->
            var offset = 0
            while (offset < data.size) {
                val keystream = aes.encrypt(register)
                val segmentBytes = minOf(segmentSize, data.size - offset)

                for (i in 0 until segmentBytes) {
                    result[offset + i] = (data[offset + i] xor keystream[i]).toByte()
                }

                // Shift register
                register.copyInto(register, 0, segmentBytes)
                data.copyInto(register, 16 - segmentBytes, offset, offset + segmentBytes)

                offset += segmentBytes
            }
        }
    }
}

class OFBMode(private val aes: AES, private val iv: ByteArray) : BlockCipherMode() {
    init {
        require(iv.size == 16) { "IV must be 16 bytes" }
    }

    override fun encrypt(data: ByteArray): ByteArray {
        return processBlocks(data)
    }

    override fun decrypt(data: ByteArray): ByteArray {
        return processBlocks(data)
    }

    private fun processBlocks(data: ByteArray): ByteArray {
        var register = iv.copyOf()
        return ByteArray(data.size).also { result ->
            var offset = 0
            while (offset < data.size) {
                register = aes.encrypt(register)
                val length = minOf(16, data.size - offset)

                for (i in 0 until length) {
                    result[offset + i] = (data[offset + i] xor register[i]).toByte()
                }
                offset += length
            }
        }
    }
}

// Extension functions for ByteArray
private fun Long.toBigEndian(): ByteArray {
    return ByteArray(8) { i ->
        ((this shr ((7 - i) * 8)) and 0xFF).toByte()
    }
}

// High-level encryption wrapper
class AESCipher(private val mode: BlockCipherMode) {
    fun encrypt(data: ByteArray, padding: Boolean = true): ByteArray {
        val paddedData = if (padding) PKCS7.pad(data) else data
        return mode.encrypt(paddedData)
    }

    fun decrypt(data: ByteArray, padding: Boolean = true): ByteArray {
        val decrypted = mode.decrypt(data)
        return if (padding) PKCS7.unpad(decrypted) else decrypted
    }
}

// Improved PKCS7 padding with constant-time implementation
object PKCS7 {
    fun pad(data: ByteArray, blockSize: Int = 16): ByteArray {
        val padding = blockSize - (data.size % blockSize)
        return data + ByteArray(padding) { padding.toByte() }
    }

    fun unpad(data: ByteArray): ByteArray {
        require(data.isNotEmpty()) { "Empty data cannot be unpadded" }

        // Get the padding value (last byte)
        val paddingValue = data.last().toInt() and 0xFF

        // Validate the padding value
        if (paddingValue < 1 || paddingValue > 16) {
            throw IllegalArgumentException("Invalid padding value: $paddingValue")
        }

        // Verify that all padding bytes have the same value
        for (i in data.size - paddingValue until data.size) {
            if (data[i].toInt() and 0xFF != paddingValue) {
                throw IllegalArgumentException("Invalid padding bytes")
            }
        }

        // Remove the padding
        return data.copyOfRange(0, data.size - paddingValue)
    }
}

// Constants and lookup tables
private object AESConstants {
    val S = generateSBox()
    val Si = generateInverseSBox()
    val rcon = generateRcon()

    // T-tables for faster operations
    val T0 = generateTTable(0)
    val T1 = generateTTable(1)
    val T2 = generateTTable(2)
    val T3 = generateTTable(3)

    // Inverse T-tables for decryption
    val T0i = generateInverseTTable(0)
    val T1i = generateInverseTTable(1)
    val T2i = generateInverseTTable(2)
    val T3i = generateInverseTTable(3)

    private fun generateInverseSBox(): ByteArray {
        val inverse = ByteArray(256)
        for (i in 0..255) {
            inverse[S[i].toInt() and 0xFF] = i.toByte()
        }
        return inverse
    }

    private fun generateRcon(): ByteArray {
        val rcon = ByteArray(256)
        var r = 1
        for (i in 0..255) {
            rcon[i] = r.toByte()
            r = (r shl 1) xor (if (r and 0x80 != 0) 0x1B else 0)
        }
        return rcon
    }

    private fun generateTTable(shift: Int): LongArray {
        return LongArray(256) { i ->
            val s = S[i].toInt() and 0xFF
            val t = ((gmul(s, 2) shl 24)
                    or (s shl 16)
                    or (s shl 8)
                    or s)
            (t ushr (8 * shift) or (t shl (32 - 8 * shift))).toLong()
        }
    }

    private fun generateInverseTTable(shift: Int): LongArray {
        return LongArray(256) { i ->
            val s = Si[i].toInt() and 0xFF
            val t = ((gmul(s, 0x0E) shl 24)
                    or (gmul(s, 0x09) shl 16)
                    or (gmul(s, 0x0D) shl 8)
                    or gmul(s, 0x0B))
            (t ushr (8 * shift) or (t shl (32 - 8 * shift))).toLong()
        }
    }

    private fun generateSBox(): ByteArray {
        val sBox = ByteArray(256)

        // Initialize the S-box with values from 0x00 to 0xFF
        for (i in 0..255) {
            sBox[i] = i.toByte()
        }

        // Apply multiplicative inverse in GF(2^8)
        for (i in 0..255) {
            if (sBox[i].toInt() != 0) {
                sBox[i] = gmulInverse(sBox[i].toInt()).toByte()
            }
        }

        // Apply affine transformation
        for (i in 0..255) {
            var b = sBox[i].toInt() and 0xFF
            b = b xor ((b shl 1) or (b shr 7)) xor ((b shl 2) or (b shr 6)) xor
                    ((b shl 3) or (b shr 5)) xor ((b shl 4) or (b shr 4)) xor 0x63
            sBox[i] = b.toByte()
        }

        return sBox
    }

    private fun gmulInverse(a: Int): Int {
        if (a == 0) return 0
        var b = 1
        for (i in 0..253) {
            b = gmul(b, a)
        }
        return b
    }

    private fun gmul(a: Int, b: Int): Int {
        var p = 0
        var aa = a
        var bb = b
        for (i in 0..7) {
            if ((bb and 1) != 0) {
                p = p xor aa
            }
            val hiBitSet = aa and 0x80
            aa = (aa shl 1) and 0xFF
            if (hiBitSet != 0) {
                aa = aa xor 0x1B
            }
            bb = bb shr 1
        }
        return p
    }
}

// Extension function to combine list of ByteArrays
fun List<ByteArray>.flatten(): ByteArray {
    val totalSize = this.sumOf { it.size }
    val result = ByteArray(totalSize)
    var position = 0

    this.forEach { array ->
        array.copyInto(result, position)
        position += array.size
    }

    return result
}

// Extension function for ByteArray chunking
fun ByteArray.chunked(size: Int): List<ByteArray> {
    require(size > 0) { "Chunk size must be positive" }
    val chunks = mutableListOf<ByteArray>()
    var position = 0

    while (position < this.size) {
        val chunkSize = minOf(size, this.size - position)
        val chunk = ByteArray(chunkSize)
        this.copyInto(chunk, 0, position, position + chunkSize)
        chunks.add(chunk)
        position += chunkSize
    }

    return chunks
}

fun encryptAes(input: String): String {
    // Convert the key and input to bytes
    val key = "qwertyuioplkjhgf".encodeToByteArray()
    val inputBytes = input.encodeToByteArray()

    // Apply PKCS#7 padding
    val paddedInput = PKCS7.pad(inputBytes, 16)

    val encryptedBytes = ModeOfOperationECB(key).encrypt(paddedInput)

    // Convert the encrypted bytes to a hex string
    return bytesToHex(encryptedBytes)
}