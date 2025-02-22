<div align="center">

# AES Encryption in Kotlin
Enjoy secure encryption with AES in Kotlin! 🚀

![Kotlin](https://img.shields.io/badge/Kotlin-7f52ff?style=flat-square&logo=kotlin&logoColor=white)
![Kotlin Multiplatform](https://img.shields.io/badge/Kotlin%20Multiplatform-4c8d3f?style=flat-square&logo=kotlin&logoColor=white)

![badge-android](http://img.shields.io/badge/platform-android-6EDB8D.svg?style=flat)
![badge-ios](http://img.shields.io/badge/platform-ios-CDCDCD.svg?style=flat)
![badge-desktop](http://img.shields.io/badge/platform-jvm-7f52ff.svg?style=flat)
![badge-js](http://img.shields.io/badge/platform-web-FDD835.svg?style=flat)

This repository provides a Kotlin implementation of the **Advanced Encryption Standard (AES)**, ported from the original [aes-js](https://github.com/ricmoo/aes-js) library. It supports AES encryption and decryption with various modes of operation, including **ECB**, **CBC**, **CFB**, **OFB**, and **CTR**.

</div>

---

## Features

- **AES Encryption and Decryption**: Supports 128-bit, 192-bit, and 256-bit keys.
- **Modes of Operation**:
    - **ECB (Electronic Codebook)**
    - **CBC (Cipher Block Chaining)**
    - **CFB (Cipher Feedback)**
    - **OFB (Output Feedback)**
    - **CTR (Counter)**
- **PKCS#7 Padding**: Automatically pads and strips data for block alignment.
- **Easy-to-Use API**: Simple and intuitive methods for encryption and decryption.

## Installation

Add the following dependency to your `build.gradle.kts` file:

```kotlin
implementation("io.github.niyajali:aes-kotlin:1.0.0")
```

## Usage

### 1. AES Encryption Basics

#### Initialize AES with a Key
```kotlin
val key = "2b7e151628aed2a6abf7158809cf4f3c".hexToBytes() // 128-bit key
val aes = AESEncryption(key)
```

#### Encrypt and Decrypt Data
```kotlin
val plaintext = "Hello, AES!".toByteArray()
val ciphertext = aes.encrypt(plaintext)
val decryptedText = aes.decrypt(ciphertext)

println("Ciphertext: ${ciphertext.toHexString()}")
println("Decrypted Text: ${String(decryptedText)}")
```

### 2. Modes of Operation

#### ECB (Electronic Codebook)
```kotlin
val ecb = ModeOfOperationECB(key)
val encrypted = ecb.encrypt(plaintext)
val decrypted = ecb.decrypt(encrypted)
```

#### CBC (Cipher Block Chaining)
```kotlin
val iv = "000102030405060708090a0b0c0d0e0f".hexToBytes() // Initialization Vector
val cbc = ModeOfOperationCBC(key, iv)
val encrypted = cbc.encrypt(plaintext)
val decrypted = cbc.decrypt(encrypted)
```

#### CFB (Cipher Feedback)
```kotlin
val cfb = ModeOfOperationCFB(key, iv, segmentSize = 8) // 8-bit segment size
val encrypted = cfb.encrypt(plaintext)
val decrypted = cfb.decrypt(encrypted)
```

#### OFB (Output Feedback)
```kotlin
val ofb = ModeOfOperationOFB(key, iv)
val encrypted = ofb.encrypt(plaintext)
val decrypted = ofb.decrypt(encrypted)
```

#### CTR (Counter)
```kotlin
val counter = Counter("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".hexToBytes())
val ctr = ModeOfOperationCTR(key, counter)
val encrypted = ctr.encrypt(plaintext)
val decrypted = ctr.decrypt(encrypted)
```

### 3. PKCS#7 Padding

#### Pad Data
```kotlin
val paddedData = pkcs7Pad(plaintext, 16) // Pad to 16-byte blocks
```

#### Strip Padding
```kotlin
val strippedData = pkcs7Strip(paddedData)
```

### 4. Utility Functions

#### Convert Bytes to Hex String
```kotlin
val hexString = bytesToHex(ciphertext)
println("Hex: $hexString")
```

#### Convert Hex String to Bytes
```kotlin
val bytes = "2b7e151628aed2a6abf7158809cf4f3c".hexToBytes()
```

## Example

Here’s a complete example of encrypting and decrypting data using AES in CBC mode:

```kotlin
fun main() {
    val key = "2b7e151628aed2a6abf7158809cf4f3c".hexToBytes()
    val iv = "000102030405060708090a0b0c0d0e0f".hexToBytes()
    val plaintext = "Hello, AES!".toByteArray()

    // Encrypt
    val cbc = ModeOfOperationCBC(key, iv)
    val ciphertext = cbc.encrypt(plaintext)
    println("Encrypted: ${bytesToHex(ciphertext)}")

    // Decrypt
    val decrypted = cbc.decrypt(ciphertext)
    println("Decrypted: ${String(decrypted)}")
}
```

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- This library is a Kotlin port of the original [aes-js](https://github.com/ricmoo/aes-js) library by [ricmoo](https://github.com/ricmoo).
- Special thanks to the contributors and maintainers of the original library.
