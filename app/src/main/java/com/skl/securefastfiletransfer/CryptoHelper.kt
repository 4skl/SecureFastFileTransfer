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
    private const val BUFFER_SIZE = 1 * 1024 * 1024 // 1MB chunks for streaming

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

    // TRUE STREAMING DECRYPTION - process chunks with adaptive buffer sizing
    fun decryptFileStreamWithProgress(
        inputStream: InputStream,
        outputStream: OutputStream,
        secret: String,
        progressCallback: ((bytesProcessed: Long, fileName: String?, fileSize: Long?) -> Unit)? = null,
        integrityCheckCallback: (() -> Unit)? = null
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

            // Read and decrypt the file header first (fixed 8MB block for compatibility)
            val encryptedHeader = ByteArray(BUFFER_SIZE)
            var headerBytesRead = 0

            // Read header completely
            while (headerBytesRead < BUFFER_SIZE) {
                val read = inputStream.read(encryptedHeader, headerBytesRead, BUFFER_SIZE - headerBytesRead)
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

            // Stream the actual file data using fixed 1MB buffer
            val buffer = ByteArray(BUFFER_SIZE)
            var fileBytesWritten = 0L
            var lastUpdateTime = System.currentTimeMillis()
            var hmacBuffer = ByteArray(0) // Buffer to collect data for HMAC verification

            // Read file data chunks until we reach the HMAC at the end
            while (true) {
                val bytesRead = inputStream.read(buffer)
                if (bytesRead == -1) break

                // Add to HMAC buffer for final verification
                val newHmacBuffer = ByteArray(hmacBuffer.size + bytesRead)
                hmacBuffer.copyInto(newHmacBuffer)
                buffer.copyInto(newHmacBuffer, hmacBuffer.size, 0, bytesRead)

                // If we have more than HMAC_SIZE bytes, we can process some data
                if (newHmacBuffer.size > HMAC_SIZE) {
                    val dataToProcess = newHmacBuffer.size - HMAC_SIZE
                    val dataChunk = newHmacBuffer.sliceArray(0 until dataToProcess)

                    // Decrypt and write this chunk immediately
                    mac.update(dataChunk)
                    val decryptedChunk = ctrCipher.update(dataChunk)
                    if (decryptedChunk != null && decryptedChunk.isNotEmpty()) {
                        outputStream.write(decryptedChunk)
                        outputStream.flush() // Force immediate write to disk
                        fileBytesWritten += decryptedChunk.size
                    }

                    // Keep only the last HMAC_SIZE bytes for final verification
                    hmacBuffer = newHmacBuffer.sliceArray(dataToProcess until newHmacBuffer.size)
                } else {
                    hmacBuffer = newHmacBuffer
                }

                val currentTime = System.currentTimeMillis()
                // Report progress every 100ms for smooth updates
                if (progressCallback != null && (currentTime - lastUpdateTime > 100)) {
                    progressCallback(fileBytesWritten, fileName, fileSize)
                    lastUpdateTime = currentTime
                }

                // Clear buffer to free memory immediately
                buffer.fill(0)
            }

            // Notify that we're starting integrity verification
            Log.d("CryptoHelper", "Starting file integrity verification...")
            integrityCheckCallback?.invoke()

            // Verify HMAC from the last HMAC_SIZE bytes
            if (hmacBuffer.size == HMAC_SIZE) {
                val calculatedHmac = mac.doFinal()
                if (!calculatedHmac.contentEquals(hmacBuffer)) {
                    Log.e("CryptoHelper", "HMAC verification failed - data may be corrupted or tampered")
                    return false
                }
                Log.d("CryptoHelper", "HMAC verification successful")
            } else {
                Log.e("CryptoHelper", "Invalid HMAC size: ${hmacBuffer.size}, expected: $HMAC_SIZE")
                return false
            }

            // Finalize decryption
            val finalChunk = ctrCipher.doFinal()
            if (finalChunk != null && finalChunk.isNotEmpty()) {
                outputStream.write(finalChunk)
                outputStream.flush()
                fileBytesWritten += finalChunk.size
            }

            // Final progress update
            progressCallback?.invoke(fileBytesWritten, fileName, fileSize)

            Log.d("CryptoHelper", "File decrypted successfully with adaptive streaming. Processed $fileBytesWritten bytes using ${BUFFER_SIZE/1024/1024}MB buffer")
            true
        } catch (e: Exception) {
            Log.e("CryptoHelper", "Adaptive streaming decryption failed: ${e.message}")
            false
        }
    }

    /**
     * TRUE STREAMING ENCRYPTION - encrypts and sends chunks with adaptive buffer sizing
     */
    fun encryptFileStreamWithProgress(
        inputStream: InputStream,
        outputStream: OutputStream,
        secret: String,
        fileSize: Long,
        fileName: String,
        progressCallback: ((bytesProcessed: Long, totalBytes: Long, speed: Float) -> Unit)? = null
    ): Boolean {
        return try {
            // Generate salt and IV
            val salt = generateSalt()
            val iv = generateUniqueIV()

            // Derive encryption and HMAC keys
            val (encryptionKey, hmacKey) = deriveKeys(secret, salt)

            // Initialize HMAC for authentication
            val mac = javax.crypto.Mac.getInstance(HMAC_ALGORITHM)
            mac.init(hmacKey)

            // Write salt and IV first
            outputStream.write(salt)
            outputStream.write(iv)

            // Update HMAC with salt and IV
            mac.update(salt)
            mac.update(iv)

            // Use AES-CTR mode for streaming encryption
            val ctrCipher = Cipher.getInstance(TRANSFORMATION_CTR)
            val ctrSpec = IvParameterSpec(iv)
            ctrCipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ctrSpec)

            // Create and encrypt file header (still using fixed BUFFER_SIZE for compatibility)
            val fileHeader = createFileHeader(fileName, fileSize)
            val encryptedHeader = ctrCipher.update(fileHeader)
            mac.update(encryptedHeader)
            outputStream.write(encryptedHeader)
            outputStream.flush()

            Log.d("CryptoHelper", "Encrypted file header written: fileName=$fileName, fileSize=$fileSize, bufferSize=${BUFFER_SIZE/1024/1024}MB")

            // Stream the actual file data using fixed 1MB buffer
            val buffer = ByteArray(BUFFER_SIZE)
            var bytesProcessed = 0L
            var startTime = System.currentTimeMillis()
            var lastUpdateTime = startTime

            while (true) {
                val bytesRead = inputStream.read(buffer)
                if (bytesRead == -1) break

                // Create chunk with actual data size
                val dataChunk = if (bytesRead == BUFFER_SIZE) {
                    buffer
                } else {
                    buffer.copyOf(bytesRead)
                }

                // Encrypt and write this chunk immediately
                val encryptedChunk = ctrCipher.update(dataChunk)
                if (encryptedChunk != null && encryptedChunk.isNotEmpty()) {
                    mac.update(encryptedChunk)
                    outputStream.write(encryptedChunk)
                    outputStream.flush() // Force immediate write to network
                }

                bytesProcessed += bytesRead

                val currentTime = System.currentTimeMillis()
                // Report progress every 100ms for smooth updates
                if (progressCallback != null && (currentTime - lastUpdateTime > 100)) {
                    val elapsedSeconds = (currentTime - startTime) / 1000f
                    val speed = if (elapsedSeconds > 0.1f) bytesProcessed / elapsedSeconds else 0f
                    progressCallback(bytesProcessed, fileSize, speed)
                    lastUpdateTime = currentTime
                }

                // Clear buffer to free memory immediately
                buffer.fill(0)
            }

            // Finalize encryption
            val finalChunk = ctrCipher.doFinal()
            if (finalChunk != null && finalChunk.isNotEmpty()) {
                mac.update(finalChunk)
                outputStream.write(finalChunk)
            }

            // Write HMAC for authentication
            val hmac = mac.doFinal()
            outputStream.write(hmac)
            outputStream.flush()

            // Final progress update
            val finalTime = System.currentTimeMillis()
            val totalElapsedSeconds = (finalTime - startTime) / 1000f
            val finalSpeed = if (totalElapsedSeconds > 0) bytesProcessed / totalElapsedSeconds else 0f
            progressCallback?.invoke(bytesProcessed, fileSize, finalSpeed)

            Log.d("CryptoHelper", "File encrypted successfully with adaptive streaming. Processed $bytesProcessed bytes using ${BUFFER_SIZE/1024/1024}MB buffer")
            true
        } catch (e: Exception) {
            Log.e("CryptoHelper", "Adaptive streaming encryption failed: ${e.message}")
            false
        }
    }

    /**
     * Generate a cryptographically secure 256-bit hex key for use as handshake secret
     */
    fun generateSecureSecret(): String {
        return try {
            // Use SecureRandom for cryptographically strong random key
            val secureRandom = SecureRandom()
            val keyBytes = ByteArray(32) // 256 bits = 32 bytes
            secureRandom.nextBytes(keyBytes)

            // Convert to hex string
            val hexKey = keyBytes.joinToString("") { byte ->
                "%02x".format(byte)
            }

            Log.d("CryptoHelper", "Generated secure 256-bit hex key with strong entropy")
            hexKey
        } catch (e: Exception) {
            Log.e("CryptoHelper", "Failed to generate secure secret", e)
            // Fallback - should never happen but better safe than sorry
            val fallbackRandom = SecureRandom()
            val fallbackBytes = ByteArray(32)
            fallbackRandom.nextBytes(fallbackBytes)
            fallbackBytes.joinToString("") { "%02x".format(it) }
        }
    }

    /**
     * Enhanced validation for secrets with multiple security checks for 256-bit hex keys
     */
    fun isValidSecret(secret: String?): Boolean {
        if (secret.isNullOrBlank()) {
            Log.w("CryptoHelper", "Empty or null secret provided")
            return false
        }

        return try {
            // First sanitize the input
            val sanitized = sanitizeSecret(secret) ?: return false

            // Check if it's a valid 256-bit hex key format (64 hex characters)
            val isValidLength = sanitized.length == MIN_SECRET_LENGTH
            val hasValidFormat = sanitized.matches(Regex("[0-9a-fA-F]{64}"))
            val isNotAllZeros = sanitized != "0".repeat(64) // Reject all-zero key
            val isNotAllOnes = sanitized.uppercase() != "F".repeat(64) // Reject all-ones key

            val isValid = isValidLength && hasValidFormat && isNotAllZeros && isNotAllOnes

            if (!isValid) {
                Log.w("CryptoHelper", "Secret validation failed: length=$isValidLength, format=$hasValidFormat, notAllZeros=$isNotAllZeros, notAllOnes=$isNotAllOnes")
            } else {
                Log.d("CryptoHelper", "Secret validation successful")
            }

            isValid
        } catch (e: Exception) {
            Log.e("CryptoHelper", "Unexpected error during secret validation", e)
            false
        }
    }

    /**
     * Sanitize secret text to remove any potential malicious content
     */
    fun sanitizeSecret(secret: String?): String? {
        if (secret.isNullOrBlank()) return null

        return try {
            // Remove any whitespace and control characters
            val cleaned = secret.trim().replace(Regex("[\\p{Cntrl}]"), "")

            // Limit length to prevent DoS attacks
            val maxLength = 100 // Reasonable limit for hex key + some margin
            val truncated = if (cleaned.length > maxLength) {
                Log.w("CryptoHelper", "Input text too long, truncating from ${cleaned.length} to $maxLength characters")
                cleaned.take(maxLength)
            } else {
                cleaned
            }

            // Only allow hex characters (0-9, a-f, A-F)
            val sanitized = truncated.replace(Regex("[^a-fA-F0-9]"), "")

            if (sanitized != truncated) {
                Log.w("CryptoHelper", "Removed non-hex characters from input")
            }

            // Return null if the sanitized string is too short to be a valid hex key
            if (sanitized.length < MIN_SECRET_LENGTH) {
                Log.w("CryptoHelper", "Sanitized text too short to be a valid hex key: ${sanitized.length}")
                return null
            }

            Log.d("CryptoHelper", "Successfully sanitized secret")
            sanitized
        } catch (e: Exception) {
            Log.e("CryptoHelper", "Error sanitizing secret", e)
            null
        }
    }

    /**
     * Check if the secret contains repeating patterns
     */
    private fun isRepeatingPattern(secret: String): Boolean {
        val cleaned = secret.lowercase()

        // Check for repeating characters (more than 4 in a row)
        for (i in 0 until cleaned.length - 4) {
            val char = cleaned[i]
            if (cleaned.substring(i, i + 5).all { it == char }) {
                return true
            }
        }

        // Check for repeating short patterns
        for (patternLength in 2..8) {
            for (i in 0 until cleaned.length - (patternLength * 2)) {
                val pattern = cleaned.substring(i, i + patternLength)
                val nextPart = cleaned.substring(i + patternLength, i + patternLength * 2)
                if (pattern == nextPart) {
                    return true
                }
            }
        }

        return false
    }
}
