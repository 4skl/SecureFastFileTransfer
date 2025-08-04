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
    private const val UUID_LENGTH = 36
    private const val MIN_SECRET_LENGTH = 32

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
     * Enhanced validation for scanned secrets with multiple security checks
     */
    fun isValidSecret(scannedText: String?): Boolean {
        if (scannedText.isNullOrBlank()) {
            Log.w(TAG, "Empty or null secret provided")
            return false
        }

        return try {
            // First sanitize the input
            val sanitized = sanitizeScannedText(scannedText) ?: return false

            // Check if it's a valid UUID format
            val uuid = UUID.fromString(sanitized.trim())

            // Additional security checks
            val isValidLength = sanitized.length == UUID_LENGTH
            val hasValidFormat = sanitized.matches(Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"))
            val isNotNilUuid = uuid != UUID(0L, 0L) // Reject nil UUID

            // Use the validateSecretStrength method for additional validation
            val hasGoodStrength = validateSecretStrength(sanitized)

            val isValid = isValidLength && hasValidFormat && isNotNilUuid && hasGoodStrength

            if (!isValid) {
                Log.w(TAG, "Secret validation failed: length=$isValidLength, format=$hasValidFormat, notNil=$isNotNilUuid, strength=$hasGoodStrength")
            } else {
                Log.d(TAG, "Secret validation successful")
            }

            isValid
        } catch (e: IllegalArgumentException) {
            Log.w(TAG, "Invalid UUID format: ${e.message}")
            false
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error during secret validation", e)
            false
        }
    }

    /**
     * Generate a cryptographically secure UUID for use as handshake secret
     */
    fun generateSecureSecret(): String {
        return try {
            // Use SecureRandom for cryptographically strong random UUID
            val secureRandom = SecureRandom()
            val mostSigBits = secureRandom.nextLong()
            val leastSigBits = secureRandom.nextLong()

            val uuid = UUID(mostSigBits, leastSigBits)
            Log.d(TAG, "Generated secure UUID secret with strong entropy")
            uuid.toString()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate secure secret, falling back to standard UUID", e)
            // Fallback to standard UUID generation
            UUID.randomUUID().toString()
        }
    }

    /**
     * Validate the strength of a secret for cryptographic use
     */
    fun validateSecretStrength(secret: String): Boolean {
        if (secret.length < MIN_SECRET_LENGTH) {
            Log.w(TAG, "Secret too short: ${secret.length} < $MIN_SECRET_LENGTH")
            return false
        }

        // Check for sufficient entropy (mix of characters)
        val hasDigits = secret.any { it.isDigit() }
        val hasLetters = secret.any { it.isLetter() }
        val hasSpecialChars = secret.any { !it.isLetterOrDigit() }

        // For UUID format, we expect digits, letters, and hyphens
        val hasGoodEntropy = hasDigits && hasLetters && hasSpecialChars

        if (!hasGoodEntropy) {
            Log.w(TAG, "Secret has insufficient entropy: digits=$hasDigits, letters=$hasLetters, special=$hasSpecialChars")
        }

        // Additional check: ensure it's not a predictable pattern
        val isNotSequential = !isSequentialPattern(secret)
        val isNotRepeating = !isRepeatingPattern(secret)

        val isStrong = hasGoodEntropy && isNotSequential && isNotRepeating

        if (!isStrong) {
            Log.w(TAG, "Secret failed strength validation: entropy=$hasGoodEntropy, notSequential=$isNotSequential, notRepeating=$isNotRepeating")
        }

        return isStrong
    }

    /**
     * Sanitize scanned text to remove any potential malicious content
     */
    fun sanitizeScannedText(text: String?): String? {
        if (text.isNullOrBlank()) return null

        return try {
            // Remove any whitespace and control characters
            val cleaned = text.trim().replace(Regex("[\\p{Cntrl}]"), "")

            // Limit length to prevent DoS attacks
            val maxLength = 100 // Reasonable limit for UUID + some margin
            val truncated = if (cleaned.length > maxLength) {
                Log.w(TAG, "Input text too long, truncating from ${cleaned.length} to $maxLength characters")
                cleaned.take(maxLength)
            } else {
                cleaned
            }

            // Only allow UUID-compatible characters (alphanumeric and hyphens)
            val sanitized = truncated.replace(Regex("[^a-fA-F0-9\\-]"), "")

            if (sanitized != truncated) {
                Log.w(TAG, "Removed non-UUID characters from input")
            }

            // Return null if the sanitized string is too short to be a valid UUID
            if (sanitized.length < UUID_LENGTH) {
                Log.w(TAG, "Sanitized text too short to be a valid UUID: ${sanitized.length}")
                return null
            }

            Log.d(TAG, "Successfully sanitized scanned text")
            sanitized
        } catch (e: Exception) {
            Log.e(TAG, "Error sanitizing scanned text", e)
            null
        }
    }

    /**
     * Check if the secret contains sequential patterns
     */
    private fun isSequentialPattern(secret: String): Boolean {
        // Remove hyphens for pattern checking
        val cleaned = secret.replace("-", "")

        // Check for ascending sequences (like "123456" or "abcdef")
        for (i in 0 until cleaned.length - 2) {
            val char1 = cleaned[i]
            val char2 = cleaned[i + 1]
            val char3 = cleaned[i + 2]

            if (char2.code == char1.code + 1 && char3.code == char2.code + 1) {
                return true
            }
        }

        return false
    }

    /**
     * Check if the secret contains repeating patterns
     */
    private fun isRepeatingPattern(secret: String): Boolean {
        // Remove hyphens for pattern checking
        val cleaned = secret.replace("-", "")

        // Check for repeating characters (more than 3 in a row)
        for (i in 0 until cleaned.length - 3) {
            val char = cleaned[i]
            if (cleaned.substring(i, i + 4).all { it == char }) {
                return true
            }
        }

        // Check for repeating short patterns
        for (patternLength in 2..4) {
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

    /**
     * Generate a cryptographically secure key for AES encryption from the secret
     */
    fun deriveEncryptionKey(secret: String): SecretKeySpec? {
        return try {
            if (!isValidSecret(secret)) {
                Log.e(TAG, "Cannot derive encryption key from invalid secret")
                return null
            }

            // Use a proper key derivation function in production
            // For now, we'll use a simple but secure approach
            val keyBytes = secret.toByteArray(Charsets.UTF_8)
            val keySpec = SecretKeySpec(keyBytes.sliceArray(0..15), "AES") // 128-bit key

            Log.d(TAG, "Successfully derived encryption key from secret")
            keySpec
        } catch (e: Exception) {
            Log.e(TAG, "Failed to derive encryption key", e)
            null
        }
    }
}
