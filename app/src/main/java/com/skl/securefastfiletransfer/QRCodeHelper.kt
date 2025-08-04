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
}
