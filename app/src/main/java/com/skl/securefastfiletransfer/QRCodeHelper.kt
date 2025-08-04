package com.skl.securefastfiletransfer

import android.graphics.Bitmap
import android.graphics.Color
import android.util.Log
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

object QRCodeHelper {

    private const val TAG = "QRCodeHelper"
    private const val HEX_KEY_LENGTH = 64 // 256 bits = 64 hex characters
    private const val MIN_SECRET_LENGTH = 64 // Exactly 64 hex characters for 256-bit keys

    /**
     * Generate a QR code bitmap with enhanced security settings
     */
    fun generateQRCode(secret: String, size: Int = 512): Bitmap? {
        return try {
            // For generated secrets, use simple validation (they should already be clean)
            // Only use complex validation for scanned/user-input secrets
            if (!secret.matches(Regex("[0-9a-fA-F]{64}"))) {
                Log.e(TAG, "Invalid secret provided for QR code generation: length=${secret.length}, expected=$HEX_KEY_LENGTH")
                return null
            }

            val writer = QRCodeWriter()
            val hints = mapOf<EncodeHintType, Any>(
                // Use highest error correction for better scanning reliability
                EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.H,
                // Add margin for better scanning
                EncodeHintType.MARGIN to 2,
                // Use UTF-8 encoding for international compatibility
                EncodeHintType.CHARACTER_SET to "UTF-8"
            )

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
     * Enhanced validation for scanned secrets with multiple security checks for 256-bit hex keys
     */
    fun isValidSecret(scannedText: String?): Boolean {
        if (scannedText.isNullOrBlank()) {
            Log.w(TAG, "Empty or null secret provided")
            return false
        }

        return try {
            // First sanitize the input
            val sanitized = sanitizeScannedText(scannedText) ?: return false

            // Check if it's a valid 256-bit hex key format (64 hex characters)
            val isValidLength = sanitized.length == HEX_KEY_LENGTH
            val hasValidFormat = sanitized.matches(Regex("[0-9a-fA-F]{64}"))
            val isNotAllZeros = sanitized != "0".repeat(64) // Reject all-zero key
            val isNotAllOnes = sanitized.uppercase() != "F".repeat(64) // Reject all-ones key

            // Use the validateSecretStrength method for additional validation
            val hasGoodStrength = validateSecretStrength(sanitized)

            val isValid = isValidLength && hasValidFormat && isNotAllZeros && isNotAllOnes && hasGoodStrength

            if (!isValid) {
                Log.w(TAG, "Secret validation failed: length=$isValidLength, format=$hasValidFormat, notAllZeros=$isNotAllZeros, notAllOnes=$isNotAllOnes, strength=$hasGoodStrength")
            } else {
                Log.d(TAG, "Secret validation successful")
            }

            isValid
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error during secret validation", e)
            false
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

        // For hex keys, check for sufficient entropy (mix of different hex digits)
        val hexDigits = secret.lowercase().toCharArray().distinct()
        val hasGoodEntropy = hexDigits.size >= 8 // At least 8 different hex digits

        if (!hasGoodEntropy) {
            Log.w(TAG, "Secret has insufficient entropy: only ${hexDigits.size} different hex digits")
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
            val maxLength = 100 // Reasonable limit for hex key + some margin
            val truncated = if (cleaned.length > maxLength) {
                Log.w(TAG, "Input text too long, truncating from ${cleaned.length} to $maxLength characters")
                cleaned.take(maxLength)
            } else {
                cleaned
            }

            // Only allow hex characters (0-9, a-f, A-F)
            val sanitized = truncated.replace(Regex("[^a-fA-F0-9]"), "")

            if (sanitized != truncated) {
                Log.w(TAG, "Removed non-hex characters from input")
            }

            // Return null if the sanitized string is too short to be a valid hex key
            if (sanitized.length < HEX_KEY_LENGTH) {
                Log.w(TAG, "Sanitized text too short to be a valid hex key: ${sanitized.length}")
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
        val cleaned = secret.lowercase()

        // Check for ascending sequences (like "123456" or "abcdef")
        for (i in 0 until cleaned.length - 2) {
            val char1 = cleaned[i]
            val char2 = cleaned[i + 1]
            val char3 = cleaned[i + 2]

            // Check if it's a sequence in hex digits (0-9, a-f)
            val isHexSequence = when {
                char1.isDigit() && char2.isDigit() && char3.isDigit() -> {
                    char2.code == char1.code + 1 && char3.code == char2.code + 1
                }
                char1.isLetter() && char2.isLetter() && char3.isLetter() -> {
                    char2.code == char1.code + 1 && char3.code == char2.code + 1
                }
                else -> false
            }

            if (isHexSequence) {
                return true
            }
        }

        return false
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
