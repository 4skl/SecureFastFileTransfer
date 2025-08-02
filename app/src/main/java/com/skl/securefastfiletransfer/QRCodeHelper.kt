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
            // Check if it's a valid UUID format
            val uuid = UUID.fromString(scannedText.trim())

            // Additional security checks
            val isValidLength = scannedText.length == UUID_LENGTH
            val hasValidFormat = scannedText.matches(Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"))
            val isNotNilUuid = uuid != UUID(0L, 0L) // Reject nil UUID

            val isValid = isValidLength && hasValidFormat && isNotNilUuid

            if (!isValid) {
                Log.w(TAG, "Secret validation failed: length=$isValidLength, format=$hasValidFormat, notNil=$isNotNilUuid")
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
            Log.d(TAG, "Generated secure UUID secret")
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

        val hasGoodEntropy = hasDigits && hasLetters

        if (!hasGoodEntropy) {
            Log.w(TAG, "Secret has insufficient entropy")
        }

        return hasGoodEntropy
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
            if (cleaned.length > 100) {
                Log.w(TAG, "Scanned text too long, truncating")
                cleaned.substring(0, 100)
            } else {
                cleaned
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error sanitizing scanned text", e)
            null
        }
    }
}
