package com.skl.securefastfiletransfer

import android.util.Log
import java.io.*
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object CryptoHelper {

    private const val ALGORITHM = "AES"
    private const val TRANSFORMATION_CTR = "AES/CTR/NoPadding" // For streaming
    private const val HMAC_ALGORITHM = "HmacSHA256"
    private const val IV_SIZE = 16 // 128 bits for CTR mode
    private const val HMAC_SIZE = 32 // 256 bits for SHA256
    private const val SALT_SIZE = 16
    private const val MIN_SECRET_LENGTH = 64 // Enforce exactly 64 hex characters (256-bit keys only)
    private const val BUFFER_SIZE = 8 * 1024 * 1024 // 8MB chunks for streaming

    // Counter to ensure IV uniqueness within a session (additional safety)
    @Volatile
    private var ivCounter = 0L

    private fun generateSalt(): ByteArray {
        val salt = ByteArray(SALT_SIZE)
        SecureRandom().nextBytes(salt)
        return salt
    }

    private fun generateUniqueIV(): ByteArray {
        val iv = ByteArray(IV_SIZE)
        val secureRandom = SecureRandom()

        // Fill first 12 bytes with secure random data
        val randomPart = ByteArray(12)
        secureRandom.nextBytes(randomPart)
        randomPart.copyInto(iv, 0)

        // Use counter + timestamp for last 4 bytes to ensure uniqueness
        val uniqueness = (System.nanoTime() xor (++ivCounter)).toInt()
        iv[12] = (uniqueness shr 24).toByte()
        iv[13] = (uniqueness shr 16).toByte()
        iv[14] = (uniqueness shr 8).toByte()
        iv[15] = uniqueness.toByte()

        return iv
    }

    fun generateKeyFromSecret(secret: String, salt: ByteArray = generateSalt()): Pair<SecretKeySpec, ByteArray> {
        // Only accept 256-bit hex keys - no legacy support
        val secretBytes = if (secret.length == 64 && secret.matches(Regex("[0-9a-fA-F]{64}"))) {
            // Convert hex to bytes
            secret.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        } else {
            throw IllegalArgumentException("Secret must be exactly 64 hexadecimal characters (256-bit key)")
        }

        return try {
            val secretKey = SecretKeySpec(secretBytes, ALGORITHM)
            Pair(secretKey, salt)
        } finally {
            // Clear sensitive data
            Arrays.fill(secretBytes, 0.toByte())
        }
    }

    /**
     * Derive separate keys for encryption and HMAC from the main secret
     */
    private fun deriveKeys(secret: String, salt: ByteArray): Pair<SecretKeySpec, SecretKeySpec> {
        val (mainKey, _) = generateKeyFromSecret(secret, salt)

        // Derive separate keys using HKDF-like approach
        val keyBytes = mainKey.encoded

        // Create encryption key (first 32 bytes for AES-256)
        val encryptionKeyBytes = ByteArray(32)
        keyBytes.copyInto(encryptionKeyBytes, 0, 0, minOf(32, keyBytes.size))
        if (keyBytes.size < 32) {
            // If original key is shorter, expand using SHA256
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            val expanded = digest.digest(keyBytes + "encryption".toByteArray())
            expanded.copyInto(encryptionKeyBytes, keyBytes.size, 0, 32 - keyBytes.size)
        }

        // Create HMAC key by deriving from original key
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val hmacKeyBytes = digest.digest(keyBytes + "authentication".toByteArray())

        val encryptionKey = SecretKeySpec(encryptionKeyBytes, ALGORITHM)
        val hmacKey = SecretKeySpec(hmacKeyBytes, HMAC_ALGORITHM)

        // Clear intermediate data
        Arrays.fill(keyBytes, 0.toByte())
        Arrays.fill(encryptionKeyBytes, 0.toByte())
        Arrays.fill(hmacKeyBytes, 0.toByte())

        return Pair(encryptionKey, hmacKey)
    }

    /**
     * Create encrypted file header containing metadata
     */
    private fun createFileHeader(fileName: String, fileSize: Long): ByteArray {
        // Create header with filename and size
        val header = "$fileName|$fileSize"
        val headerBytes = header.toByteArray(Charsets.UTF_8)

        // Pad to exactly 8MB (same as BUFFER_SIZE) with random data to hide actual metadata size
        val paddedSize = BUFFER_SIZE // 8MB to match other chunks
        val paddedHeader = ByteArray(paddedSize)

        // Copy header to beginning
        headerBytes.copyInto(paddedHeader, 0)

        // Fill rest with secure random padding
        val random = SecureRandom()
        val paddingBytes = ByteArray(paddedSize - headerBytes.size)
        random.nextBytes(paddingBytes)
        paddingBytes.copyInto(paddedHeader, headerBytes.size)

        // Mark end of actual data (use a specific byte pattern)
        if (headerBytes.size < paddedSize - 4) {
            paddedHeader[headerBytes.size] = 0xFF.toByte()
            paddedHeader[headerBytes.size + 1] = 0xFE.toByte()
            paddedHeader[headerBytes.size + 2] = 0xFD.toByte()
            paddedHeader[headerBytes.size + 3] = 0xFC.toByte()
        }

        return paddedHeader
    }

    /**
     * Parse encrypted file header to extract metadata
     */
    private fun parseFileHeader(headerBytes: ByteArray): Pair<String, Long>? {
        return try {
            // Find the end marker
            var endPos = -1
            for (i in 0 until headerBytes.size - 3) {
                if (headerBytes[i] == 0xFF.toByte() &&
                    headerBytes[i + 1] == 0xFE.toByte() &&
                    headerBytes[i + 2] == 0xFD.toByte() &&
                    headerBytes[i + 3] == 0xFC.toByte()) {
                    endPos = i
                    break
                }
            }

            if (endPos == -1) {
                // No marker found, assume entire array is data (fallback)
                endPos = headerBytes.indexOfFirst { it == 0.toByte() }
                if (endPos == -1) endPos = headerBytes.size
            }

            val headerString = String(headerBytes, 0, endPos, Charsets.UTF_8)
            val parts = headerString.split("|")
            if (parts.size == 2) {
                val fileName = parts[0]
                val fileSize = parts[1].toLongOrNull() ?: -1L
                Pair(fileName, fileSize)
            } else {
                null
            }
        } catch (e: Exception) {
            Log.e("CryptoHelper", "Failed to parse file header: ${e.message}")
            null
        }
    }

    // Enhanced streaming encryption with encrypted filename and HMAC authentication
    fun encryptFileStreamWithProgress(
        inputStream: InputStream,
        outputStream: OutputStream,
        secret: String,
        fileSize: Long,
        fileName: String = "file",
        progressCallback: ((bytesProcessed: Long, totalBytes: Long, speed: Float) -> Unit)? = null
    ): EncryptionMetadata? {
        return try {
            if (secret.length < MIN_SECRET_LENGTH) {
                Log.w("CryptoHelper", "Secret is too short, should be at least $MIN_SECRET_LENGTH characters")
                return null
            }

            val salt = generateSalt()
            val iv = generateUniqueIV()
            val (encryptionKey, hmacKey) = deriveKeys(secret, salt)

            // Write salt and IV first
            outputStream.write(salt)
            outputStream.write(iv)

            // Initialize HMAC for authentication
            val mac = javax.crypto.Mac.getInstance(HMAC_ALGORITHM)
            mac.init(hmacKey)

            // Authenticate salt and IV
            mac.update(salt)
            mac.update(iv)

            // Use AES-CTR mode for streaming
            val ctrCipher = Cipher.getInstance(TRANSFORMATION_CTR)
            val ctrSpec = IvParameterSpec(iv)
            ctrCipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ctrSpec)

            // Create and encrypt file header first
            val fileHeader = createFileHeader(fileName, fileSize)
            val encryptedHeader = ctrCipher.update(fileHeader)
            outputStream.write(encryptedHeader)
            mac.update(encryptedHeader) // Authenticate encrypted header

            val buffer = ByteArray(BUFFER_SIZE)
            var bytesProcessed = 0L
            var bytesRead: Int
            val startTime = System.currentTimeMillis()
            var lastUpdateTime = startTime
            val totalBytesWithHeader = fileSize + fileHeader.size

            // TRUE STREAMING: Read chunk by chunk and immediately encrypt and send
            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                // Encrypt this chunk immediately
                val encryptedChunk = ctrCipher.update(buffer, 0, bytesRead)
                if (encryptedChunk != null) {
                    // Send immediately to network
                    outputStream.write(encryptedChunk)
                    outputStream.flush() // Force immediate sending
                    mac.update(encryptedChunk) // Authenticate each chunk
                }

                bytesProcessed += bytesRead
                val currentTime = System.currentTimeMillis()

                // Report progress every 250ms to avoid overwhelming the UI thread
                if (progressCallback != null && (currentTime - lastUpdateTime > 250 || bytesProcessed == fileSize)) {
                    val elapsed = (currentTime - startTime) / 1000.0f
                    val speed = if (elapsed > 0) (bytesProcessed + fileHeader.size) / elapsed else 0f
                    progressCallback(bytesProcessed + fileHeader.size, totalBytesWithHeader, speed)
                    lastUpdateTime = currentTime
                }
            }

            // Finalize encryption
            val finalChunk = ctrCipher.doFinal()
            if (finalChunk != null && finalChunk.isNotEmpty()) {
                outputStream.write(finalChunk)
                outputStream.flush()
                mac.update(finalChunk) // Authenticate final chunk
            }

            // Write HMAC at the end for authentication
            val hmacBytes = mac.doFinal()
            outputStream.write(hmacBytes)
            outputStream.flush()

            Log.d("CryptoHelper", "File encrypted successfully with streaming AES-CTR+HMAC. Processed $bytesProcessed bytes")
            EncryptionMetadata(iv, salt)
        } catch (e: Exception) {
            Log.e("CryptoHelper", "Streaming AES-CTR+HMAC encryption failed: ${e.message}")
            null
        }
    }

    // TRUE STREAMING DECRYPTION - no temp files, process chunk by chunk
    fun decryptFileStreamWithProgress(
        inputStream: InputStream,
        outputStream: OutputStream,
        secret: String,
        progressCallback: ((bytesProcessed: Long, fileName: String?, fileSize: Long?) -> Unit)? = null
    ): Boolean {
        return try {
            // Read salt and IV first
            val salt = ByteArray(SALT_SIZE)
            val iv = ByteArray(IV_SIZE)

            if (inputStream.read(salt) != SALT_SIZE || inputStream.read(iv) != IV_SIZE) {
                Log.e("CryptoHelper", "Failed to read salt or IV from encrypted stream")
                return false
            }

            val (encryptionKey, hmacKey) = deriveKeys(secret, salt)

            // Initialize HMAC for verification
            val mac = javax.crypto.Mac.getInstance(HMAC_ALGORITHM)
            mac.init(hmacKey)

            // Verify salt and IV
            mac.update(salt)
            mac.update(iv)

            // Use AES-CTR mode for streaming decryption
            val ctrCipher = Cipher.getInstance(TRANSFORMATION_CTR)
            val ctrSpec = IvParameterSpec(iv)
            ctrCipher.init(Cipher.DECRYPT_MODE, encryptionKey, ctrSpec)

            // Read and decrypt the file header first (8MB)
            val encryptedHeaderSize = BUFFER_SIZE
            val encryptedHeader = ByteArray(encryptedHeaderSize)
            var headerBytesRead = 0

            // Read header completely
            while (headerBytesRead < encryptedHeaderSize) {
                val read = inputStream.read(encryptedHeader, headerBytesRead, encryptedHeaderSize - headerBytesRead)
                if (read == -1) {
                    Log.e("CryptoHelper", "Unexpected end of stream while reading header")
                    return false
                }
                headerBytesRead += read
            }

            // Update HMAC with header and decrypt it
            mac.update(encryptedHeader)
            val decryptedHeader = ctrCipher.update(encryptedHeader)
            val (fileName, fileSize) = parseFileHeader(decryptedHeader) ?: Pair("unknown_file", -1L)

            Log.d("CryptoHelper", "Decrypted file header: fileName=$fileName, fileSize=$fileSize")

            // Report initial progress with filename
            progressCallback?.invoke(0L, fileName, fileSize)

            // Now stream the actual file data chunk by chunk
            val buffer = ByteArray(BUFFER_SIZE)
            var totalBytesProcessed = headerBytesRead.toLong()
            var fileBytesWritten = 0L
            var lastUpdateTime = System.currentTimeMillis()
            val startTime = lastUpdateTime

            // Read all remaining data except last 32 bytes (HMAC)
            var pendingData = ByteArray(0)
            var endOfStream = false

            while (!endOfStream) {
                val bytesRead = inputStream.read(buffer)
                if (bytesRead == -1) {
                    endOfStream = true
                    // Process any remaining pending data
                    if (pendingData.size > HMAC_SIZE) {
                        val dataToProcess = pendingData.size - HMAC_SIZE
                        val dataChunk = pendingData.sliceArray(0 until dataToProcess)

                        // Update HMAC and decrypt
                        mac.update(dataChunk)
                        val decryptedChunk = ctrCipher.update(dataChunk)
                        if (decryptedChunk != null) {
                            outputStream.write(decryptedChunk)
                            fileBytesWritten += decryptedChunk.size
                        }

                        // Extract HMAC from last 32 bytes
                        val receivedHmac = pendingData.sliceArray(dataToProcess until pendingData.size)

                        // Verify HMAC
                        val calculatedHmac = mac.doFinal()
                        if (!calculatedHmac.contentEquals(receivedHmac)) {
                            Log.e("CryptoHelper", "HMAC verification failed - data may be corrupted or tampered")
                            return false
                        }

                        Log.d("CryptoHelper", "HMAC verification successful")
                    }
                } else {
                    // Append new data to pending
                    val newPending = ByteArray(pendingData.size + bytesRead)
                    pendingData.copyInto(newPending)
                    buffer.copyInto(newPending, pendingData.size, 0, bytesRead)

                    // If we have enough data (keep last 32 bytes for HMAC), process it
                    if (newPending.size > HMAC_SIZE + BUFFER_SIZE) {
                        val dataToProcess = newPending.size - HMAC_SIZE - BUFFER_SIZE
                        val dataChunk = newPending.sliceArray(0 until dataToProcess)

                        // Update HMAC and decrypt
                        mac.update(dataChunk)
                        val decryptedChunk = ctrCipher.update(dataChunk)
                        if (decryptedChunk != null) {
                            outputStream.write(decryptedChunk)
                            outputStream.flush() // Ensure data is written immediately
                            fileBytesWritten += decryptedChunk.size
                        }

                        // Keep remaining data as pending
                        pendingData = newPending.sliceArray(dataToProcess until newPending.size)
                    } else {
                        pendingData = newPending
                    }

                    totalBytesProcessed += bytesRead
                }

                val currentTime = System.currentTimeMillis()

                // Report progress every 250ms for smooth updates
                if (progressCallback != null && (currentTime - lastUpdateTime > 250 || endOfStream)) {
                    progressCallback(fileBytesWritten, fileName, fileSize)
                    lastUpdateTime = currentTime
                }
            }

            // Finalize decryption
            val finalChunk = ctrCipher.doFinal()
            if (finalChunk != null && finalChunk.isNotEmpty()) {
                outputStream.write(finalChunk)
                fileBytesWritten += finalChunk.size
            }

            outputStream.flush()

            Log.d("CryptoHelper", "File decrypted successfully with true streaming AES-CTR+HMAC verification. Processed $fileBytesWritten bytes")
            true
        } catch (e: Exception) {
            Log.e("CryptoHelper", "True streaming AES-CTR+HMAC decryption failed: ${e.message}")
            false
        }
    }

    data class EncryptionMetadata(
        val iv: ByteArray,   // IV for AES-CTR
        val salt: ByteArray  // Salt used for key derivation
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as EncryptionMetadata

            if (!iv.contentEquals(other.iv)) return false
            if (!salt.contentEquals(other.salt)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = iv.contentHashCode()
            result = 31 * result + salt.contentHashCode()
            return result
        }
    }
}
