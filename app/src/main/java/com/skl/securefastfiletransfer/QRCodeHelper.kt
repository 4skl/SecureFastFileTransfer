package com.skl.securefastfiletransfer

import android.graphics.Bitmap
import android.graphics.Color
import android.util.Log
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.util.*

object QRCodeHelper {

    fun generateQRCode(secret: String, size: Int = 512): Bitmap? {
        return try {
            val writer = QRCodeWriter()
            val hints = EnumMap<EncodeHintType, Any>(EncodeHintType::class.java)
            hints[EncodeHintType.ERROR_CORRECTION] = ErrorCorrectionLevel.H
            hints[EncodeHintType.MARGIN] = 2

            val bitMatrix = writer.encode(secret, BarcodeFormat.QR_CODE, size, size, hints)
            val width = bitMatrix.width
            val height = bitMatrix.height
            val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)

            for (x in 0 until width) {
                for (y in 0 until height) {
                    bitmap.setPixel(x, y, if (bitMatrix[x, y]) Color.BLACK else Color.WHITE)
                }
            }

            Log.d("QRCodeHelper", "QR code generated successfully for secret: ${secret.take(8)}...")
            bitmap
        } catch (e: Exception) {
            Log.e("QRCodeHelper", "Failed to generate QR code: ${e.message}")
            null
        }
    }

    fun isValidSecret(scannedText: String): Boolean {
        // Validate that scanned text looks like a UUID
        return try {
            UUID.fromString(scannedText)
            scannedText.length == 36 // Standard UUID length
        } catch (e: IllegalArgumentException) {
            false
        }
    }
}
