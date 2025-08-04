package com.skl.securefastfiletransfer

import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.IBinder
import android.util.Log
import androidx.core.net.toUri
import androidx.documentfile.provider.DocumentFile
import kotlinx.coroutines.*
import java.io.*
import java.net.ServerSocket
import java.net.Socket

class FileTransferService : Service() {

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var serverSocket: ServerSocket? = null

    companion object {
        const val ACTION_SEND_FILE = "com.skl.securefastfiletransfer.SEND_FILE"
        const val ACTION_RECEIVE_FILE = "com.skl.securefastfiletransfer.RECEIVE_FILE"
        const val ACTION_STOP_SERVICE = "com.skl.securefastfiletransfer.STOP_SERVICE"
        const val EXTRA_FILE_PATH = "file_path"
        const val EXTRA_FILE_URI = "file_uri"
        const val EXTRA_FILE_NAME = "file_name"
        const val EXTRA_HOST = "host_address"
        const val EXTRA_SECRET = "shared_secret"
        const val EXTRA_SAVE_DIRECTORY_URI = "save_directory_uri"
        private const val FILE_TRANSFER_PORT = 8989
        private const val STATUS_NOTIFICATION_PORT = 8990 // New port for receiver->sender status updates

        // Progress broadcast actions
        const val ACTION_TRANSFER_PROGRESS = "com.skl.securefastfiletransfer.TRANSFER_PROGRESS"
        const val ACTION_TRANSFER_COMPLETE = "com.skl.securefastfiletransfer.FILE_TRANSFER_COMPLETE"
        const val ACTION_SENDER_STATUS_UPDATE = "com.skl.securefastfiletransfer.SENDER_STATUS_UPDATE" // New action for sender-specific updates
        const val EXTRA_PROGRESS_BYTES = "progress_bytes"
        const val EXTRA_TOTAL_BYTES = "total_bytes"
        const val EXTRA_TRANSFER_SPEED = "transfer_speed"
        const val EXTRA_IS_SENDING = "is_sending"
        const val EXTRA_OPERATION_TYPE = "operation_type" // "encrypting", "transferring", "decrypting", "verifying_integrity"
        const val EXTRA_VERIFICATION_PROGRESS = "verification_progress" // New field for verification percentage

        fun startService(
            context: Context,
            action: String,
            filePath: String? = null,
            fileUri: Uri? = null,
            fileName: String? = null,
            hostAddress: String? = null,
            secret: String,
            saveDirectoryUri: Uri? = null
        ) {
            val intent = Intent(context, FileTransferService::class.java).apply {
                this.action = action
                putExtra(EXTRA_SECRET, secret)
                filePath?.let { putExtra(EXTRA_FILE_PATH, it) }
                fileUri?.let { putExtra(EXTRA_FILE_URI, it.toString()) }
                fileName?.let { putExtra(EXTRA_FILE_NAME, it) }
                hostAddress?.let { putExtra(EXTRA_HOST, it) }
                saveDirectoryUri?.let { putExtra(EXTRA_SAVE_DIRECTORY_URI, it.toString()) }
            }
            context.startService(intent)
        }

        fun stopService(context: Context) {
            val intent = Intent(context, FileTransferService::class.java).apply {
                action = ACTION_STOP_SERVICE
            }
            context.startService(intent)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        intent ?: return START_NOT_STICKY

        when (intent.action) {
            ACTION_SEND_FILE -> {
                val filePath = intent.getStringExtra(EXTRA_FILE_PATH)
                val fileUriString = intent.getStringExtra(EXTRA_FILE_URI)
                val fileName = intent.getStringExtra(EXTRA_FILE_NAME)
                val hostAddress = intent.getStringExtra(EXTRA_HOST)
                val secret = intent.getStringExtra(EXTRA_SECRET)

                if (hostAddress != null && secret != null) {
                    serviceScope.launch {
                        // Use URI-based streaming if available, otherwise fall back to file path
                        if (fileUriString != null && fileName != null) {
                            sendFileFromUri(fileUriString.toUri(), fileName, hostAddress, secret)
                        } else if (filePath != null) {
                            sendFile(filePath, hostAddress, secret)
                        } else {
                            Log.e("FileTransferService", "No file source provided")
                        }
                        stopSelf(startId)
                    }
                } else {
                    stopSelf(startId)
                }
            }
            ACTION_RECEIVE_FILE -> {
                val secret = intent.getStringExtra(EXTRA_SECRET)
                val saveDirectoryUriString = intent.getStringExtra(EXTRA_SAVE_DIRECTORY_URI)
                val saveDirectoryUri = saveDirectoryUriString?.toUri()
                if (secret != null) {
                    serviceScope.launch {
                        receiveFile(secret, saveDirectoryUri)
                        stopSelf(startId)
                    }
                } else {
                    stopSelf(startId)
                }
            }
            ACTION_STOP_SERVICE -> {
                stopSelf()
            }
        }

        return START_NOT_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        serverSocket?.close()
        serviceScope.cancel()
    }

    private suspend fun sendFile(filePath: String, hostAddress: String, secret: String) = withContext(Dispatchers.IO) {
        try {
            val file = File(filePath)
            if (!file.exists()) {
                throw Exception("File not found: $filePath")
            }

            // Get the actual filename from the file path
            val actualFileName = file.name
            Log.d("FileTransferService", "Starting encryption and streaming of file: $actualFileName")

            // Create connection (this should be fast)
            val socket = Socket()
            socket.connect(java.net.InetSocketAddress(hostAddress, FILE_TRANSFER_PORT))
            socket.soTimeout = 0 // No timeout during data operations

            val outputStream = socket.getOutputStream()
            val dataOutputStream = DataOutputStream(outputStream)

            // Simple progress reporting callback without artificial phase detection
            val progressCallback: (Long, Long, Float) -> Unit = { bytesProcessed, totalBytes, speed ->
                // Broadcast progress on main thread to avoid blocking transfer
                launch(Dispatchers.Main) {
                    val progressIntent = Intent(ACTION_TRANSFER_PROGRESS)
                    progressIntent.setPackage(packageName)
                    progressIntent.putExtra(EXTRA_PROGRESS_BYTES, bytesProcessed)
                    progressIntent.putExtra(EXTRA_TOTAL_BYTES, totalBytes)
                    progressIntent.putExtra(EXTRA_TRANSFER_SPEED, speed)
                    progressIntent.putExtra(EXTRA_IS_SENDING, true)
                    progressIntent.putExtra(EXTRA_OPERATION_TYPE, "encrypting_and_sending")
                    sendBroadcast(progressIntent)
                }
            }

            // Stream encryption directly from file to network - NO TEMP FILE NEEDED
            file.inputStream().use { fileInputStream ->
                val success = CryptoHelper.encryptFileStreamWithProgress(
                    fileInputStream,
                    dataOutputStream,
                    secret,
                    file.length(),
                    actualFileName, // Use the actual filename
                    progressCallback
                )
                if (!success) {
                    throw Exception("Failed to encrypt and stream file")
                }
            }

            dataOutputStream.close()
            socket.close()

            Log.d("FileTransferService", "File encrypted and streamed successfully: $actualFileName")

            // Broadcast final success immediately after transfer completes
            val broadcastIntent = Intent(ACTION_TRANSFER_COMPLETE)
            broadcastIntent.setPackage(packageName)
            broadcastIntent.putExtra("success", true)
            broadcastIntent.putExtra("message", "File sent successfully")
            sendBroadcast(broadcastIntent)

        } catch (e: Exception) {
            Log.e("FileTransferService", "Error sending file: ${e.message}")
            val broadcastIntent = Intent(ACTION_TRANSFER_COMPLETE)
            broadcastIntent.setPackage(packageName)
            broadcastIntent.putExtra("success", false)
            broadcastIntent.putExtra("message", "Failed to send file: ${e.message}")
            sendBroadcast(broadcastIntent)
        }
    }

    private suspend fun sendFileFromUri(fileUri: Uri, fileName: String, hostAddress: String, secret: String) = withContext(Dispatchers.IO) {
        try {
            // Get file size from URI first for proper progress reporting
            val fileSize = try {
                contentResolver.openFileDescriptor(fileUri, "r")?.use { pfd ->
                    pfd.statSize
                } ?: run {
                    // Fallback method if file descriptor not available
                    contentResolver.openInputStream(fileUri)?.use { inputStream ->
                        inputStream.available().toLong()
                    } ?: -1L
                }
            } catch (e: Exception) {
                Log.e("FileTransferService", "Failed to get file size from URI: ${e.message}")
                -1L
            }

            Log.d("FileTransferService", "Starting encryption and streaming of file: $fileName (size: $fileSize bytes)")

            // ContentResolver to open input stream for the URI
            contentResolver.openInputStream(fileUri)?.use { inputStream ->
                // Create a socket connection
                val socket = Socket()
                socket.connect(java.net.InetSocketAddress(hostAddress, FILE_TRANSFER_PORT))
                socket.soTimeout = 0 // No timeout during data operations

                val outputStream = socket.getOutputStream()
                val dataOutputStream = DataOutputStream(outputStream)

                // Simple progress reporting callback
                val progressCallback: (Long, Long, Float) -> Unit = { bytesProcessed, totalBytes, speed ->
                    // Broadcast progress on main thread to avoid blocking transfer
                    launch(Dispatchers.Main) {
                        val progressIntent = Intent(ACTION_TRANSFER_PROGRESS)
                        progressIntent.setPackage(packageName)
                        progressIntent.putExtra(EXTRA_PROGRESS_BYTES, bytesProcessed)
                        progressIntent.putExtra(EXTRA_TOTAL_BYTES, totalBytes)
                        progressIntent.putExtra(EXTRA_TRANSFER_SPEED, speed)
                        progressIntent.putExtra(EXTRA_IS_SENDING, true)
                        progressIntent.putExtra(EXTRA_OPERATION_TYPE, "encrypting_and_sending")
                        sendBroadcast(progressIntent)
                    }
                }

                // Stream encryption directly from URI to network
                val success = CryptoHelper.encryptFileStreamWithProgress(
                    inputStream,
                    dataOutputStream,
                    secret,
                    fileSize, // Use the actual file size we retrieved
                    fileName, // Use the provided file name
                    progressCallback
                )
                if (!success) {
                    throw Exception("Failed to encrypt and stream file from URI")
                }

                dataOutputStream.close()
                socket.close()

                Log.d("FileTransferService", "File encrypted and streamed successfully from URI: $fileName")

                // Broadcast final success immediately after transfer completes
                val broadcastIntent = Intent(ACTION_TRANSFER_COMPLETE)
                broadcastIntent.setPackage(packageName)
                broadcastIntent.putExtra("success", true)
                broadcastIntent.putExtra("message", "File sent successfully")
                sendBroadcast(broadcastIntent)

            } ?: run {
                throw Exception("Failed to open input stream for URI: $fileUri")
            }
        } catch (e: Exception) {
            Log.e("FileTransferService", "Error sending file from URI: ${e.message}")
            val broadcastIntent = Intent(ACTION_TRANSFER_COMPLETE)
            broadcastIntent.setPackage(packageName)
            broadcastIntent.putExtra("success", false)
            broadcastIntent.putExtra("message", "Failed to send file from URI: ${e.message}")
            sendBroadcast(broadcastIntent)
        }
    }

    private suspend fun receiveFile(secret: String, saveDirectoryUri: Uri?) = withContext(Dispatchers.IO) {
        try {
            serverSocket = ServerSocket(FILE_TRANSFER_PORT)
            serverSocket?.soTimeout = 0 // No timeout - wait indefinitely for connection
            Log.d("FileTransferService", "Waiting for encrypted file transfer...")

            // Broadcast that we're waiting for connection
            val waitingIntent = Intent(ACTION_TRANSFER_PROGRESS)
            waitingIntent.setPackage(packageName)
            waitingIntent.putExtra(EXTRA_PROGRESS_BYTES, 0L)
            waitingIntent.putExtra(EXTRA_TOTAL_BYTES, 0L)
            waitingIntent.putExtra(EXTRA_TRANSFER_SPEED, 0f)
            waitingIntent.putExtra(EXTRA_IS_SENDING, false)
            waitingIntent.putExtra(EXTRA_OPERATION_TYPE, "waiting_for_connection")
            sendBroadcast(waitingIntent)

            val socket = serverSocket?.accept()
            socket?.soTimeout = 0 // No timeout during data operations
            val inputStream = socket?.getInputStream()
            val dataInputStream = DataInputStream(inputStream)

            Log.d("FileTransferService", "Receiving encrypted file")

            // Broadcast that decryption is starting
            val decryptionStartIntent = Intent(ACTION_TRANSFER_PROGRESS)
            decryptionStartIntent.setPackage(packageName)
            decryptionStartIntent.putExtra(EXTRA_PROGRESS_BYTES, 0L)
            decryptionStartIntent.putExtra(EXTRA_TOTAL_BYTES, 0L) // We don't know total size yet
            decryptionStartIntent.putExtra(EXTRA_TRANSFER_SPEED, 0f)
            decryptionStartIntent.putExtra(EXTRA_IS_SENDING, false)
            decryptionStartIntent.putExtra(EXTRA_OPERATION_TYPE, "receiving_and_decrypting")
            sendBroadcast(decryptionStartIntent)

            // Track for real-time progress updates
            var lastProgressUpdate = System.currentTimeMillis()
            var receivedFileName: String? = null
            var totalFileSize: Long = 0L
            var startTime = System.currentTimeMillis()
            var lastBytesProcessed = 0L

            // Enhanced progress reporting callback with real-time updates
            val progressCallback: (Long, String?, Long?) -> Unit = { bytesProcessed, fileName, fileSize ->
                val currentTime = System.currentTimeMillis()

                // Update filename and file size when first available
                if (fileName != null && receivedFileName == null) {
                    receivedFileName = fileName
                    Log.d("FileTransferService", "Receiving file: $fileName")
                }
                if (fileSize != null && fileSize > 0 && totalFileSize == 0L) {
                    totalFileSize = fileSize
                    startTime = currentTime // Reset start time when we know the file size
                    Log.d("FileTransferService", "File size: $fileSize bytes")
                }

                // Broadcast progress updates more frequently for real-time feedback
                if (currentTime - lastProgressUpdate > 100) { // Update every 100ms for smoother progress
                    launch(Dispatchers.Main) {
                        val progressIntent = Intent(ACTION_TRANSFER_PROGRESS)
                        progressIntent.setPackage(packageName)
                        progressIntent.putExtra(EXTRA_PROGRESS_BYTES, bytesProcessed)
                        if (totalFileSize > 0) {
                            progressIntent.putExtra(EXTRA_TOTAL_BYTES, totalFileSize)
                        }

                        // Calculate speed based on overall transfer performance
                        val elapsedSeconds = (currentTime - startTime) / 1000f
                        val speed = if (elapsedSeconds > 0.1f) { // Avoid division by very small numbers
                            // Use total bytes processed from start for more stable speed calculation
                            bytesProcessed / elapsedSeconds
                        } else {
                            0f
                        }

                        progressIntent.putExtra(EXTRA_TRANSFER_SPEED, speed)
                        progressIntent.putExtra(EXTRA_IS_SENDING, false)
                        progressIntent.putExtra(EXTRA_OPERATION_TYPE, "receiving_and_decrypting")
                        sendBroadcast(progressIntent)
                    }
                    lastProgressUpdate = currentTime
                    lastBytesProcessed = bytesProcessed
                }
            }

            // Integrity check callback - only for receiver's own verification display
            val integrityCheckCallback: () -> Unit = {
                launch(Dispatchers.Main) {
                    val integrityIntent = Intent(ACTION_TRANSFER_PROGRESS)
                    integrityIntent.setPackage(packageName)
                    integrityIntent.putExtra(EXTRA_PROGRESS_BYTES, totalFileSize)
                    integrityIntent.putExtra(EXTRA_TOTAL_BYTES, totalFileSize)
                    integrityIntent.putExtra(EXTRA_TRANSFER_SPEED, 0f)
                    integrityIntent.putExtra(EXTRA_IS_SENDING, false)
                    integrityIntent.putExtra(EXTRA_OPERATION_TYPE, "verifying_integrity")
                    sendBroadcast(integrityIntent)
                }
                Log.d("FileTransferService", "Starting integrity verification")
            }

            // Create output stream for the decrypted file - handle both selected directory and fallback
            val savedFilePath = if (saveDirectoryUri != null) {
                try {
                    // Try to save to user-selected directory using DocumentFile
                    val directory = DocumentFile.fromTreeUri(this@FileTransferService, saveDirectoryUri)
                    if (directory != null && directory.exists()) {
                        Log.d("FileTransferService", "Using user-selected directory via DocumentFile")
                        // We'll determine the filename during decryption, so use a temporary name for now
                        val newFile = directory.createFile("*/*", "received_file_temp")
                        if (newFile != null) {
                            // Use ContentResolver to get OutputStream for DocumentFile
                            contentResolver.openOutputStream(newFile.uri)?.use { fileOutputStream ->
                                val success = CryptoHelper.decryptFileStreamWithProgress(
                                    dataInputStream,
                                    fileOutputStream,
                                    secret,
                                    progressCallback,
                                    integrityCheckCallback
                                )
                                if (!success) {
                                    throw Exception("Failed to decrypt file - incorrect secret or corrupted data")
                                }
                            }

                            // Try to rename the file to the actual filename if we got it
                            if (receivedFileName != null && receivedFileName != "received_file_temp") {
                                try {
                                    val finalFile = directory.createFile("*/*", receivedFileName!!)
                                    if (finalFile != null) {
                                        // Copy content from temp file to final file
                                        contentResolver.openInputStream(newFile.uri)?.use { tempInput ->
                                            contentResolver.openOutputStream(finalFile.uri)?.use { finalOutput ->
                                                tempInput.copyTo(finalOutput)
                                            }
                                        }
                                        // Delete temp file
                                        newFile.delete()
                                        finalFile.uri.toString()
                                    } else {
                                        newFile.uri.toString()
                                    }
                                } catch (e: Exception) {
                                    Log.w("FileTransferService", "Could not rename to actual filename: ${e.message}")
                                    newFile.uri.toString()
                                }
                            } else {
                                newFile.uri.toString()
                            }
                        } else {
                            throw Exception("Failed to create file in selected directory")
                        }
                    } else {
                        throw Exception("Selected directory is not accessible")
                    }
                } catch (e: Exception) {
                    Log.w("FileTransferService", "Could not save to selected directory: ${e.message}, using fallback")
                    // Fallback to app directory with proper filename
                    val fileName = receivedFileName ?: "received_file"
                    val fallbackPath = createFileForSaving(fileName, null)
                    File(fallbackPath).outputStream().use { fileOutputStream ->
                        val success = CryptoHelper.decryptFileStreamWithProgress(
                            dataInputStream,
                            fileOutputStream,
                            secret,
                            progressCallback,
                            integrityCheckCallback
                        )
                        if (!success) {
                            throw Exception("Failed to decrypt file - incorrect secret or corrupted data")
                        }
                    }
                    fallbackPath
                }
            } else {
                // No directory selected, use app directory with proper filename
                val fileName = receivedFileName ?: "received_file"
                val appPath = createFileForSaving(fileName, null)
                File(appPath).outputStream().use { fileOutputStream ->
                    val success = CryptoHelper.decryptFileStreamWithProgress(
                        dataInputStream,
                        fileOutputStream,
                        secret,
                        progressCallback,
                        integrityCheckCallback
                    )
                    if (!success) {
                        throw Exception("Failed to decrypt file - incorrect secret or corrupted data")
                    }
                }
                appPath
            }

            dataInputStream.close()
            serverSocket?.close()
            serverSocket = null

            Log.d("FileTransferService", "File decrypted and saved successfully")
            Log.d("FileTransferService", "File saved to: $savedFilePath")
            Log.d("FileTransferService", "Original filename: ${receivedFileName ?: "unknown"}")

            // Broadcast success with file path and filename
            val broadcastIntent = Intent(ACTION_TRANSFER_COMPLETE)
            broadcastIntent.setPackage(packageName)
            broadcastIntent.putExtra("success", true)
            broadcastIntent.putExtra("message", "File received and decrypted successfully")
            broadcastIntent.putExtra("file_path", savedFilePath)
            broadcastIntent.putExtra("file_name", receivedFileName ?: "received_file")
            sendBroadcast(broadcastIntent)

        } catch (e: Exception) {
            Log.e("FileTransferService", "Error receiving file: ${e.message}")

            val broadcastIntent = Intent(ACTION_TRANSFER_COMPLETE)
            broadcastIntent.setPackage(packageName)
            broadcastIntent.putExtra("success", false)
            broadcastIntent.putExtra("message", "Failed to receive file: ${e.message}")
            sendBroadcast(broadcastIntent)
        } finally {
            serverSocket?.close()
            serverSocket = null
        }
    }

    /**
     * Listen for status updates from receiver (for sender)
     */
    private suspend fun listenForReceiverStatusUpdates(receiverIp: String) = withContext(Dispatchers.IO) {
        try {
            val statusServerSocket = ServerSocket(STATUS_NOTIFICATION_PORT)
            statusServerSocket.soTimeout = 120000 // 2 minutes timeout

            Log.d("FileTransferService", "Listening for receiver status updates on port $STATUS_NOTIFICATION_PORT")

            val clientSocket = statusServerSocket.accept()
            clientSocket.soTimeout = 30000 // 30 seconds timeout for individual messages

            val reader = BufferedReader(InputStreamReader(clientSocket.getInputStream()))

            var shouldContinue = true
            while (shouldContinue) {
                val statusMessage = reader.readLine() ?: break
                Log.d("FileTransferService", "Received status from receiver: $statusMessage")

                // Parse status message format: "STATUS_TYPE:progress:message"
                val parts = statusMessage.split(":", limit = 3)
                if (parts.size >= 2) {
                    val statusType = parts[0]
                    val progress = parts[1].toIntOrNull() ?: 0
                    val message = if (parts.size == 3) parts[2] else ""

                    // Broadcast status update to UI
                    launch(Dispatchers.Main) {
                        when (statusType) {
                            "VERIFICATION_START" -> {
                                val statusIntent = Intent(ACTION_SENDER_STATUS_UPDATE)
                                statusIntent.setPackage(packageName)
                                statusIntent.putExtra(EXTRA_OPERATION_TYPE, "receiver_verifying")
                                statusIntent.putExtra(EXTRA_VERIFICATION_PROGRESS, 0)
                                statusIntent.putExtra("message", "Receiver is verifying file integrity...")
                                sendBroadcast(statusIntent)
                            }
                            "VERIFICATION_PROGRESS" -> {
                                val statusIntent = Intent(ACTION_SENDER_STATUS_UPDATE)
                                statusIntent.setPackage(packageName)
                                statusIntent.putExtra(EXTRA_OPERATION_TYPE, "receiver_verifying")
                                statusIntent.putExtra(EXTRA_VERIFICATION_PROGRESS, progress)
                                statusIntent.putExtra("message", "Receiver verifying: $progress%")
                                sendBroadcast(statusIntent)
                            }
                            "VERIFICATION_COMPLETE" -> {
                                val statusIntent = Intent(ACTION_TRANSFER_COMPLETE)
                                statusIntent.setPackage(packageName)
                                statusIntent.putExtra("success", true)
                                statusIntent.putExtra("message", "File sent and verified successfully!")
                                sendBroadcast(statusIntent)
                                shouldContinue = false // Exit the loop
                            }
                            "VERIFICATION_FAILED" -> {
                                val statusIntent = Intent(ACTION_TRANSFER_COMPLETE)
                                statusIntent.setPackage(packageName)
                                statusIntent.putExtra("success", false)
                                statusIntent.putExtra("message", "File verification failed: $message")
                                sendBroadcast(statusIntent)
                                shouldContinue = false // Exit the loop
                            }
                        }
                    }
                }
            }

            clientSocket.close()
            statusServerSocket.close()

        } catch (e: Exception) {
            Log.e("FileTransferService", "Error listening for receiver status updates: ${e.message}")
        }
    }

    /**
     * Send status updates to sender (for receiver)
     */
    private suspend fun sendStatusToSender(senderIp: String, statusType: String, progress: Int = 0, message: String = "") {
        try {
            val socket = Socket(senderIp, STATUS_NOTIFICATION_PORT)
            socket.soTimeout = 10000 // 10 seconds timeout

            val writer = PrintWriter(socket.getOutputStream(), true)
            val statusMessage = "$statusType:$progress:$message"
            writer.println(statusMessage)

            Log.d("FileTransferService", "Sent status to sender: $statusMessage")

            socket.close()
        } catch (e: Exception) {
            Log.w("FileTransferService", "Failed to send status to sender: ${e.message}")
        }
    }

    /**
     * Create a file path for saving received files
     */
    private fun createFileForSaving(fileName: String, saveDirectory: File?): String {
        return try {
            val targetDir = saveDirectory ?: filesDir
            val receivedFile = File(targetDir, fileName)

            // If file exists, add a number suffix
            var counter = 1
            var finalFile = receivedFile
            while (finalFile.exists()) {
                val nameWithoutExt = fileName.substringBeforeLast(".")
                val extension = if (fileName.contains(".")) ".${fileName.substringAfterLast(".")}" else ""
                finalFile = File(targetDir, "${nameWithoutExt}_$counter$extension")
                counter++
            }

            Log.d("FileTransferService", "Created file path: ${finalFile.absolutePath}")
            finalFile.absolutePath
        } catch (e: Exception) {
            Log.e("FileTransferService", "Error creating file path: ${e.message}")
            // Emergency fallback: Use cache directory
            val cacheFile = File(cacheDir, fileName)
            Log.d("FileTransferService", "Using emergency cache location: ${cacheFile.absolutePath}")
            cacheFile.absolutePath
        }
    }
}
