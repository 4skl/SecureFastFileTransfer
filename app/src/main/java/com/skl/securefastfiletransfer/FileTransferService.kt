package com.skl.securefastfiletransfer

import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.IBinder
import android.util.Log
import androidx.documentfile.provider.DocumentFile
import kotlinx.coroutines.*
import java.io.*
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException

class FileTransferService : Service() {

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var serverSocket: ServerSocket? = null

    companion object {
        const val ACTION_SEND_FILE = "com.skl.securefastfiletransfer.SEND_FILE"
        const val ACTION_RECEIVE_FILE = "com.skl.securefastfiletransfer.RECEIVE_FILE"
        const val ACTION_STOP_SERVICE = "com.skl.securefastfiletransfer.STOP_SERVICE"
        const val EXTRA_FILE_PATH = "file_path"
        const val EXTRA_HOST = "host_address"
        const val EXTRA_SECRET = "shared_secret"
        const val EXTRA_SAVE_DIRECTORY_URI = "save_directory_uri"
        private const val FILE_TRANSFER_PORT = 8989
        // Remove all timeouts to allow unlimited time for large files
        private const val CONNECTION_TIMEOUT = 0 // No timeout for connection
        private const val SERVER_ACCEPT_TIMEOUT = 0 // No timeout for server accept

        // Progress broadcast actions
        const val ACTION_TRANSFER_PROGRESS = "com.skl.securefastfiletransfer.TRANSFER_PROGRESS"
        const val ACTION_TRANSFER_COMPLETE = "com.skl.securefastfiletransfer.FILE_TRANSFER_COMPLETE"
        const val EXTRA_PROGRESS_BYTES = "progress_bytes"
        const val EXTRA_TOTAL_BYTES = "total_bytes"
        const val EXTRA_TRANSFER_SPEED = "transfer_speed"
        const val EXTRA_IS_SENDING = "is_sending"
        const val EXTRA_OPERATION_TYPE = "operation_type" // "encrypting", "transferring", "decrypting"

        fun startService(
            context: Context,
            action: String,
            filePath: String? = null,
            hostAddress: String? = null,
            secret: String,
            saveDirectoryUri: Uri? = null
        ) {
            val intent = Intent(context, FileTransferService::class.java).apply {
                this.action = action
                putExtra(EXTRA_SECRET, secret)
                filePath?.let { putExtra(EXTRA_FILE_PATH, it) }
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
                val hostAddress = intent.getStringExtra(EXTRA_HOST)
                val secret = intent.getStringExtra(EXTRA_SECRET)
                if (filePath != null && hostAddress != null && secret != null) {
                    serviceScope.launch {
                        sendFile(filePath, hostAddress, secret)
                        stopSelf(startId)
                    }
                } else {
                    stopSelf(startId)
                }
            }
            ACTION_RECEIVE_FILE -> {
                val secret = intent.getStringExtra(EXTRA_SECRET)
                val saveDirectoryUriString = intent.getStringExtra(EXTRA_SAVE_DIRECTORY_URI)
                val saveDirectoryUri = saveDirectoryUriString?.let { Uri.parse(it) }
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

            Log.d("FileTransferService", "Starting encryption of file: ${file.name}")

            // Broadcast that encryption is starting
            val encryptionStartIntent = Intent(ACTION_TRANSFER_PROGRESS)
            encryptionStartIntent.setPackage(packageName)
            encryptionStartIntent.putExtra(EXTRA_PROGRESS_BYTES, 0L)
            encryptionStartIntent.putExtra(EXTRA_TOTAL_BYTES, file.length())
            encryptionStartIntent.putExtra(EXTRA_TRANSFER_SPEED, 0f)
            encryptionStartIntent.putExtra(EXTRA_IS_SENDING, true)
            encryptionStartIntent.putExtra(EXTRA_OPERATION_TYPE, "encrypting")
            sendBroadcast(encryptionStartIntent)

            // Create connection (this should be fast)
            val socket = Socket()
            socket.connect(java.net.InetSocketAddress(hostAddress, FILE_TRANSFER_PORT))
            socket.soTimeout = 0 // No timeout during data operations

            val outputStream = socket.getOutputStream()
            val dataOutputStream = DataOutputStream(outputStream)

            // Send file name first
            dataOutputStream.writeUTF(file.name)

            // Enhanced progress reporting callback with encryption phase tracking
            var encryptionStarted = false
            val progressCallback: (Long, Long, Float) -> Unit = { bytesProcessed, totalBytes, speed ->
                // Broadcast progress on main thread to avoid blocking transfer
                launch(Dispatchers.Main) {
                    val progressIntent = Intent(ACTION_TRANSFER_PROGRESS)
                    progressIntent.setPackage(packageName)
                    progressIntent.putExtra(EXTRA_PROGRESS_BYTES, bytesProcessed)
                    progressIntent.putExtra(EXTRA_TOTAL_BYTES, totalBytes)
                    progressIntent.putExtra(EXTRA_TRANSFER_SPEED, speed)
                    progressIntent.putExtra(EXTRA_IS_SENDING, true)

                    // Show encryption progress for the first part, then encryption+sending
                    val operationType = if (!encryptionStarted && bytesProcessed < totalBytes * 0.1) {
                        "encrypting"
                    } else {
                        encryptionStarted = true
                        "encrypting_and_sending"
                    }
                    progressIntent.putExtra(EXTRA_OPERATION_TYPE, operationType)
                    sendBroadcast(progressIntent)
                }
            }

            // Encrypt and send the file using streaming with progress
            file.inputStream().use { fileInputStream ->
                val encryptionMetadata = CryptoHelper.encryptFileStreamWithProgress(
                    fileInputStream,
                    dataOutputStream,
                    secret,
                    file.length(),
                    progressCallback
                )
                if (encryptionMetadata == null) {
                    throw Exception("Failed to encrypt file")
                }
            }

            dataOutputStream.close()
            socket.close()

            Log.d("FileTransferService", "Encrypted file sent successfully: ${file.name}")

            // Broadcast success with consistent action
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

            // Receive file name
            val fileName = dataInputStream.readUTF()

            Log.d("FileTransferService", "Receiving encrypted file: $fileName")

            // Broadcast that decryption is starting
            val decryptionStartIntent = Intent(ACTION_TRANSFER_PROGRESS)
            decryptionStartIntent.setPackage(packageName)
            decryptionStartIntent.putExtra(EXTRA_PROGRESS_BYTES, 0L)
            decryptionStartIntent.putExtra(EXTRA_TOTAL_BYTES, 0L) // We don't know total size yet
            decryptionStartIntent.putExtra(EXTRA_TRANSFER_SPEED, 0f)
            decryptionStartIntent.putExtra(EXTRA_IS_SENDING, false)
            decryptionStartIntent.putExtra(EXTRA_OPERATION_TYPE, "receiving_and_decrypting")
            sendBroadcast(decryptionStartIntent)

            // Progress reporting callback
            val progressCallback: (Long) -> Unit = { bytesProcessed ->
                // Broadcast progress on main thread to avoid blocking transfer
                launch(Dispatchers.Main) {
                    val progressIntent = Intent(ACTION_TRANSFER_PROGRESS)
                    progressIntent.setPackage(packageName)
                    progressIntent.putExtra(EXTRA_PROGRESS_BYTES, bytesProcessed)
                    progressIntent.putExtra(EXTRA_IS_SENDING, false)
                    progressIntent.putExtra(EXTRA_OPERATION_TYPE, "receiving_and_decrypting")
                    sendBroadcast(progressIntent)
                }
            }

            // Create output stream for the decrypted file - handle both selected directory and fallback
            val savedFilePath = if (saveDirectoryUri != null) {
                try {
                    // Try to save to user-selected directory using DocumentFile
                    val directory = DocumentFile.fromTreeUri(this@FileTransferService, saveDirectoryUri)
                    if (directory != null && directory.exists()) {
                        Log.d("FileTransferService", "Using user-selected directory via DocumentFile")
                        val newFile = directory.createFile("*/*", fileName)
                        if (newFile != null) {
                            // Use ContentResolver to get OutputStream for DocumentFile
                            contentResolver.openOutputStream(newFile.uri)?.use { fileOutputStream ->
                                val success = CryptoHelper.decryptFileStreamWithProgress(
                                    dataInputStream,
                                    fileOutputStream,
                                    secret,
                                    progressCallback
                                )
                                if (!success) {
                                    throw Exception("Failed to decrypt file - incorrect secret or corrupted data")
                                }
                            }
                            newFile.uri.toString()
                        } else {
                            throw Exception("Failed to create file in selected directory")
                        }
                    } else {
                        throw Exception("Selected directory is not accessible")
                    }
                } catch (e: Exception) {
                    Log.w("FileTransferService", "Could not save to selected directory: ${e.message}, using fallback")
                    // Fallback to app directory
                    val fallbackPath = createFileForSaving(fileName, null)
                    FileOutputStream(fallbackPath).use { fileOutputStream ->
                        val success = CryptoHelper.decryptFileStreamWithProgress(
                            dataInputStream,
                            fileOutputStream,
                            secret,
                            progressCallback
                        )
                        if (!success) {
                            throw Exception("Failed to decrypt file - incorrect secret or corrupted data")
                        }
                    }
                    fallbackPath
                }
            } else {
                // No directory selected, use app directory
                val appPath = createFileForSaving(fileName, null)
                FileOutputStream(appPath).use { fileOutputStream ->
                    val success = CryptoHelper.decryptFileStreamWithProgress(
                        dataInputStream,
                        fileOutputStream,
                        secret,
                        progressCallback
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

            Log.d("FileTransferService", "File decrypted and saved successfully: $fileName")
            Log.d("FileTransferService", "File saved to: $savedFilePath")

            // Broadcast success with file path
            val broadcastIntent = Intent(ACTION_TRANSFER_COMPLETE)
            broadcastIntent.setPackage(packageName)
            broadcastIntent.putExtra("success", true)
            broadcastIntent.putExtra("message", "File received and decrypted successfully: $fileName")
            broadcastIntent.putExtra("file_path", savedFilePath)
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

    private fun createFileForSaving(fileName: String, saveDirectoryUri: Uri?): String {
        Log.d("FileTransferService", "Creating file for saving: $fileName")
        Log.d("FileTransferService", "Save directory URI: $saveDirectoryUri")

        return try {
            if (saveDirectoryUri != null) {
                Log.d("FileTransferService", "Using user-selected directory")
                // For streaming, we need to get the actual file path, not URI
                // This is a simplified approach - in production you might want to use ContentResolver
                val directory = DocumentFile.fromTreeUri(this, saveDirectoryUri)
                if (directory != null && directory.exists()) {
                    // Fallback to app directory since we need direct file access for streaming
                    Log.w("FileTransferService", "Using fallback for streaming - DocumentFile doesn't support direct streaming")
                }
            }

            // Use app's external files directory for direct file access
            val downloadsDir = File(getExternalFilesDir(null), "Downloads")
            if (!downloadsDir.exists()) {
                downloadsDir.mkdirs()
            }
            val receivedFile = File(downloadsDir, fileName)
            Log.d("FileTransferService", "File will be saved to: ${receivedFile.absolutePath}")
            receivedFile.absolutePath

        } catch (e: Exception) {
            Log.e("FileTransferService", "Error creating file path: ${e.message}")
            // Emergency fallback: Use cache directory
            val cacheFile = File(cacheDir, fileName)
            Log.d("FileTransferService", "Using emergency cache location: ${cacheFile.absolutePath}")
            cacheFile.absolutePath
        }
    }
}
