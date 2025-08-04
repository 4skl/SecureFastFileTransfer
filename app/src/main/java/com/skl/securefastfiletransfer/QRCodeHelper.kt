package com.skl.securefastfiletransfer

import android.graphics.Bitmap
import android.graphics.Color
import android.util.Log
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.security.SecureRandom
import java.util.*
import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

object QRCodeHelper {

    private const val TAG = "QRCodeHelper"
    private const val HEX_KEY_LENGTH = 64 // 256 bits = 32 bytes = 64 hex characters
    private const val MIN_SECRET_LENGTH = 64 // Enforce exactly 64 hex characters

    /**
     * Generate a QR code bitmap with enhanced security settings
     */
    fun generateQRCode(secret: String, size: Int = 512): Bitmap? {
        return try {
            // Validate secret before generating QR code
            if (!isValidSecret(secret)) {
                Log.e(TAG, "Invalid secret provided for QR code generation")
                return null
            }

            val writer = QRCodeWriter()
            val hints = EnumMap<EncodeHintType, Any>(EncodeHintType::class.java).apply {
                // Use highest error correction for better scanning reliability
                put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.H)
                // Add margin for better scanning
                put(EncodeHintType.MARGIN, 2)
                // Use UTF-8 encoding for international compatibility
                put(EncodeHintType.CHARACTER_SET, "UTF-8")
            }

            val bitMatrix = writer.encode(secret, BarcodeFormat.QR_CODE, size, size, hints)
            val width = bitMatrix.width
            val height = bitMatrix.height

            // Use ARGB_8888 for better quality instead of RGB_565
            val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)

            // Generate QR code with high contrast colors
            for (x in 0 until width) {
                for (y in 0 until height) {
                    bitmap.setPixel(x, y, if (bitMatrix[x, y]) Color.BLACK else Color.WHITE)
                }
            }

            Log.d(TAG, "QR code generated successfully with size ${width}x${height}")
            bitmap
        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate QR code", e)
            null
        }
    }

    /**
     * Generate a cryptographically secure 256-bit key in hex format
     */
    fun generateSecureSecret(): String {
        return try {
            // Generate 32 random bytes (256 bits)
            val secureRandom = SecureRandom()
            val keyBytes = ByteArray(32)
            secureRandom.nextBytes(keyBytes)

            // Convert to hex string
            val hexKey = keyBytes.joinToString("") { "%02x".format(it) }
            Log.d(TAG, "Generated secure 256-bit hex key with strong entropy")
            hexKey
        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate secure secret, falling back to standard generation", e)
            // Fallback: generate another way
            val secureRandom = SecureRandom()
            val keyBytes = ByteArray(32)
            secureRandom.nextBytes(keyBytes)
            keyBytes.joinToString("") { "%02x".format(it) }
        }
    }

    /**
     * Validate if the secret is in the correct format (256-bit hex only)
     */
    fun isValidSecret(secret: String): Boolean {
        return try {
            val sanitized = sanitizeSecretInput(secret) ?: return false

            // Only accept 256-bit hex key format
            if (sanitized.length == HEX_KEY_LENGTH && sanitized.matches(Regex("[0-9a-fA-F]{64}"))) {
                Log.d(TAG, "Valid 256-bit hex key format detected")
                return true
            }

            Log.w(TAG, "Secret must be exactly 64 hex characters (256-bit key): length=${sanitized.length}")
            false
        } catch (e: Exception) {
            Log.e(TAG, "Error validating secret format", e)
            false
        }
    }

    /**
     * Validate the strength of a secret for cryptographic use
     */
    fun validateSecretStrength(secret: String): Boolean {
        // Only accept exactly 64 hex characters (256-bit keys)
        if (secret.length != HEX_KEY_LENGTH) {
            Log.w(TAG, "Secret must be exactly $HEX_KEY_LENGTH characters: actual length=${secret.length}")
            return false
        }

        if (!secret.matches(Regex("[0-9a-fA-F]{64}"))) {
            Log.w(TAG, "Secret must contain only hexadecimal characters (0-9, A-F)")
            return false
        }

        return true
    }

    /**
     * Clean and sanitize secret input from user or QR code
     */
    fun sanitizeScannedText(input: String?): String? {
        return sanitizeSecretInput(input)
    }

    /**
     * Clean and sanitize secret input from user or QR code
     */
    private fun sanitizeSecretInput(input: String?): String? {
        if (input.isNullOrBlank()) {
            Log.w(TAG, "Empty secret input")
            return null
        }

        return try {
            // Remove whitespace and convert to lowercase for hex keys
            var sanitized = input.trim().lowercase()

            // Limit length to prevent abuse
            val maxLength = 100 // Reasonable limit for hex key + some margin
            if (sanitized.length > maxLength) {
                Log.w(TAG, "Secret input too long, truncating: ${sanitized.length}")
                sanitized = sanitized.substring(0, maxLength)
            }

            // Only allow hex characters
            sanitized = sanitized.filter { it.isDigit() || it in 'a'..'f' }
            if (sanitized.length != input.trim().length) {
                Log.w(TAG, "Removed non-hex characters from input")
            }

            // Return null if not exactly 64 characters
            if (sanitized.length != HEX_KEY_LENGTH) {
                Log.w(TAG, "Secret must be exactly $HEX_KEY_LENGTH hex characters: actual length=${sanitized.length}")
                return null
            }

            sanitized
        } catch (e: Exception) {
            Log.e(TAG, "Error sanitizing secret input", e)
            null
        }
    }
}
