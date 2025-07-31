package com.skl.securefastfiletransfer

import android.util.Base64
import android.util.Log
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object CryptoHelper {

    private const val ALGORITHM = "AES"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_SIZE = 12 // 96 bits for GCM
    private const val TAG_SIZE = 16 // 128 bits authentication tag

    fun generateKeyFromSecret(secret: String): SecretKeySpec {
        // Use SHA-256 to derive a 256-bit key from the secret
        val digest = MessageDigest.getInstance("SHA-256")
        val keyBytes = digest.digest(secret.toByteArray(Charsets.UTF_8))
        return SecretKeySpec(keyBytes, ALGORITHM)
    }

    fun encryptFile(fileBytes: ByteArray, secret: String): EncryptedData? {
        return try {
            val key = generateKeyFromSecret(secret)
            val cipher = Cipher.getInstance(TRANSFORMATION)

            // Generate random IV (nonce) for GCM
            val iv = ByteArray(IV_SIZE)
            SecureRandom().nextBytes(iv)
            val gcmSpec = GCMParameterSpec(TAG_SIZE * 8, iv) // Tag size in bits

            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)
            val encryptedBytes = cipher.doFinal(fileBytes)

            Log.d("CryptoHelper", "File encrypted successfully with AES-GCM. Size: ${encryptedBytes.size} bytes")
            EncryptedData(encryptedBytes, iv)
        } catch (e: Exception) {
            Log.e("CryptoHelper", "AES-GCM encryption failed: ${e.message}")
            null
        }
    }

    fun decryptFile(encryptedData: EncryptedData, secret: String): ByteArray? {
        return try {
            val key = generateKeyFromSecret(secret)
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

    data class EncryptedData(
        val data: ByteArray, // Contains encrypted data + authentication tag
        val iv: ByteArray    // 96-bit nonce for GCM
    ) {
        fun toBase64(): String {
            // Combine IV + encrypted data (with tag) for transmission
            val combined = iv + data
            return Base64.encodeToString(combined, Base64.DEFAULT)
        }

        companion object {
            fun fromBase64(base64String: String): EncryptedData? {
                return try {
                    val combined = Base64.decode(base64String, Base64.DEFAULT)
                    if (combined.size <= IV_SIZE) return null

                    val iv = combined.sliceArray(0 until IV_SIZE)
                    val data = combined.sliceArray(IV_SIZE until combined.size)
                    EncryptedData(data, iv)
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

            return true
        }

        override fun hashCode(): Int {
            var result = data.contentHashCode()
            result = 31 * result + iv.contentHashCode()
            return result
        }
    }
}
