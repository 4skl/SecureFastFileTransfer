package com.skl.securefastfiletransfer

import android.util.Base64
import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object CryptoHelper {

    private const val ALGORITHM = "AES"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_SIZE = 12 // 96 bits for GCM
    private const val TAG_SIZE = 16 // 128 bits authentication tag
    private const val PBKDF2_ITERATIONS = 310000 // OWASP 2023 recommendation for PBKDF2-SHA256
    private const val SALT_SIZE = 16
    private const val MIN_SECRET_LENGTH = 8
    private const val BUFFER_SIZE = 8192 // 8KB chunks for streaming

    private fun generateSalt(): ByteArray {
        val salt = ByteArray(SALT_SIZE)
        SecureRandom().nextBytes(salt)
        return salt
    }

    private fun generateIV(): ByteArray {
        val iv = ByteArray(IV_SIZE)
        SecureRandom().nextBytes(iv)
        return iv
    }

    fun generateKeyFromSecret(secret: String, salt: ByteArray = generateSalt()): Pair<SecretKeySpec, ByteArray> {
        // Use PBKDF2 instead of plain SHA-256 for better security
        val secretChars = secret.toCharArray()
        return try {
            val spec = PBEKeySpec(secretChars, salt, PBKDF2_ITERATIONS, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val keyBytes = factory.generateSecret(spec).encoded
            
            // Clear sensitive data
            spec.clearPassword()
            
            val secretKey = SecretKeySpec(keyBytes, ALGORITHM)
            // Clear key bytes from memory
            Arrays.fill(keyBytes, 0.toByte())
            
            Pair(secretKey, salt)
        } finally {
            // Ensure cleanup even if exception occurs
            Arrays.fill(secretChars, ' ')
        }
    }

    fun encryptFile(fileBytes: ByteArray, secret: String): EncryptedData? {
        return try {
            // Add input validation
            if (secret.length < MIN_SECRET_LENGTH) {
                Log.w("CryptoHelper", "Secret is too short, should be at least $MIN_SECRET_LENGTH characters")
                return null
            }
            if (fileBytes.isEmpty()) {
                Log.w("CryptoHelper", "Cannot encrypt empty file")
                return null
            }

            val (key, salt) = generateKeyFromSecret(secret)
            val cipher = Cipher.getInstance(TRANSFORMATION)

            // Generate random IV (nonce) for GCM
            val iv = generateIV()
            val gcmSpec = GCMParameterSpec(TAG_SIZE * 8, iv) // Tag size in bits

            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)
            val encryptedBytes = cipher.doFinal(fileBytes)

            Log.d("CryptoHelper", "File encrypted successfully with AES-GCM. Size: ${encryptedBytes.size} bytes")
            EncryptedData(encryptedBytes, iv, salt)
        } catch (e: Exception) {
            Log.e("CryptoHelper", "AES-GCM encryption failed: ${e.message}")
            null
        }
    }

    fun decryptFile(encryptedData: EncryptedData, secret: String): ByteArray? {
        return try {
            val (key, _) = generateKeyFromSecret(secret, encryptedData.salt)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            val gcmSpec = GCMParameterSpec(TAG_SIZE * 8, encryptedData.iv)

            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)
            val decryptedBytes = cipher.doFinal(encryptedData.data)

            Log.d("CryptoHelper", "File decrypted successfully with AES-GCM. Size: ${decryptedBytes.size} bytes")
            decryptedBytes
        } catch (e: Exception) {
            Log.e("CryptoHelper", "AES-GCM decryption failed: ${e.message}")
            null
        }
    }

    // New streaming encryption method using manual chunking
    fun encryptFileStream(inputStream: InputStream, outputStream: OutputStream, secret: String): EncryptionMetadata? {
        return try {
            if (secret.length < MIN_SECRET_LENGTH) {
                Log.w("CryptoHelper", "Secret is too short, should be at least $MIN_SECRET_LENGTH characters")
                return null
            }

            val (key, salt) = generateKeyFromSecret(secret)
            val iv = generateIV()

            // Write salt and IV first
            outputStream.write(salt)
            outputStream.write(iv)

            // For very large files, we'll use AES/CTR mode for streaming
            // CTR mode is a stream cipher and doesn't have the buffer issues of GCM
            val ctrCipher = Cipher.getInstance("AES/CTR/NoPadding")
            val ctrSpec = IvParameterSpec(iv)
            ctrCipher.init(Cipher.ENCRYPT_MODE, key, ctrSpec)

            val buffer = ByteArray(BUFFER_SIZE)
            var bytesRead: Int

            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                val encryptedChunk = ctrCipher.update(buffer, 0, bytesRead)
                if (encryptedChunk != null) {
                    outputStream.write(encryptedChunk)
                }
            }

            // Finalize encryption
            val finalChunk = ctrCipher.doFinal()
            if (finalChunk != null && finalChunk.isNotEmpty()) {
                outputStream.write(finalChunk)
            }

            outputStream.flush()

            Log.d("CryptoHelper", "File encrypted successfully with streaming AES-CTR")
            EncryptionMetadata(iv, salt)
        } catch (e: Exception) {
            Log.e("CryptoHelper", "Streaming AES-CTR encryption failed: ${e.message}")
            null
        }
    }

    // New streaming decryption method using manual chunking
    fun decryptFileStream(inputStream: InputStream, outputStream: OutputStream, secret: String): Boolean {
        return try {
            // Read salt and IV first
            val salt = ByteArray(SALT_SIZE)
            val iv = ByteArray(IV_SIZE)

            if (inputStream.read(salt) != SALT_SIZE || inputStream.read(iv) != IV_SIZE) {
                Log.e("CryptoHelper", "Failed to read salt or IV from encrypted stream")
                return false
            }

            val (key, _) = generateKeyFromSecret(secret, salt)

            // Use AES/CTR mode for streaming decryption
            val ctrCipher = Cipher.getInstance("AES/CTR/NoPadding")
            val ctrSpec = IvParameterSpec(iv)
            ctrCipher.init(Cipher.DECRYPT_MODE, key, ctrSpec)

            val buffer = ByteArray(BUFFER_SIZE)
            var bytesRead: Int

            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                val decryptedChunk = ctrCipher.update(buffer, 0, bytesRead)
                if (decryptedChunk != null) {
                    outputStream.write(decryptedChunk)
                }
            }

            // Finalize decryption
            val finalChunk = ctrCipher.doFinal()
            if (finalChunk != null && finalChunk.isNotEmpty()) {
                outputStream.write(finalChunk)
            }

            outputStream.flush()

            Log.d("CryptoHelper", "File decrypted successfully with streaming AES-CTR")
            true
        } catch (e: Exception) {
            Log.e("CryptoHelper", "Streaming AES-CTR decryption failed: ${e.message}")
            false
        }
    }

    data class EncryptedData(
        val data: ByteArray, // Contains encrypted data + authentication tag
        val iv: ByteArray,   // 96-bit nonce for GCM
        val salt: ByteArray  // Salt used for key derivation
    ) {
        fun toBase64(): String {
            // Combine salt + IV + encrypted data (with tag) for transmission
            val combined = salt + iv + data
            return Base64.encodeToString(combined, Base64.DEFAULT)
        }

        companion object {
            fun fromBase64(base64String: String): EncryptedData? {
                return try {
                    val combined = Base64.decode(base64String, Base64.DEFAULT)
                    if (combined.size <= SALT_SIZE + IV_SIZE) return null

                    val salt = combined.sliceArray(0 until SALT_SIZE)
                    val iv = combined.sliceArray(SALT_SIZE until SALT_SIZE + IV_SIZE)
                    val data = combined.sliceArray(SALT_SIZE + IV_SIZE until combined.size)
                    EncryptedData(data, iv, salt)
                } catch (e: Exception) {
                    Log.e("CryptoHelper", "Failed to decode base64 encrypted data: ${e.message}")
                    null
                }
            }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as EncryptedData

            if (!data.contentEquals(other.data)) return false
            if (!iv.contentEquals(other.iv)) return false
            if (!salt.contentEquals(other.salt)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = data.contentHashCode()
            result = 31 * result + iv.contentHashCode()
            result = 31 * result + salt.contentHashCode()
            return result
        }
    }

    data class EncryptionMetadata(
        val iv: ByteArray,   // 96-bit nonce for GCM
        val salt: ByteArray  // Salt used for key derivation
    )
}
