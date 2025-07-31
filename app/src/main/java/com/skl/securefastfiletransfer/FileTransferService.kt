package com.skl.securefastfiletransfer

import android.app.IntentService
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import androidx.documentfile.provider.DocumentFile
import java.io.*
import java.net.ServerSocket
import java.net.Socket

class FileTransferService : IntentService("FileTransferService") {

    companion object {
        const val ACTION_SEND_FILE = "com.skl.securefastfiletransfer.SEND_FILE"
        const val ACTION_RECEIVE_FILE = "com.skl.securefastfiletransfer.RECEIVE_FILE"
        const val EXTRA_FILE_PATH = "file_path"
        const val EXTRA_HOST = "host_address"
        const val EXTRA_SECRET = "shared_secret"
        const val EXTRA_SAVE_DIRECTORY_URI = "save_directory_uri"
        private const val FILE_TRANSFER_PORT = 8989

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
    }

    override fun onHandleIntent(intent: Intent?) {
        intent ?: return

        when (intent.action) {
            ACTION_SEND_FILE -> {
                val filePath = intent.getStringExtra(EXTRA_FILE_PATH)
                val hostAddress = intent.getStringExtra(EXTRA_HOST)
                val secret = intent.getStringExtra(EXTRA_SECRET)
                if (filePath != null && hostAddress != null && secret != null) {
                    sendFile(filePath, hostAddress, secret)
                }
            }
            ACTION_RECEIVE_FILE -> {
                val secret = intent.getStringExtra(EXTRA_SECRET)
                val saveDirectoryUriString = intent.getStringExtra(EXTRA_SAVE_DIRECTORY_URI)
                val saveDirectoryUri = saveDirectoryUriString?.let { Uri.parse(it) }
                if (secret != null) {
                    receiveFile(secret, saveDirectoryUri)
                }
            }
        }
    }

    private fun sendFile(filePath: String, hostAddress: String, secret: String) {
        try {
            val file = File(filePath)
            val fileBytes = file.readBytes()

            // Encrypt the file using the shared secret
            val encryptedData = CryptoHelper.encryptFile(fileBytes, secret)
            if (encryptedData == null) {
                throw Exception("Failed to encrypt file")
            }

            val socket = Socket(hostAddress, FILE_TRANSFER_PORT)
            val outputStream = socket.getOutputStream()
            val dataOutputStream = DataOutputStream(outputStream)

            // Send file name first
            dataOutputStream.writeUTF(file.name)
            // Send encrypted data size
            dataOutputStream.writeLong(encryptedData.data.size.toLong())
            // Send IV size and IV
            dataOutputStream.writeInt(encryptedData.iv.size)
            dataOutputStream.write(encryptedData.iv)

            // Send encrypted file data
            dataOutputStream.write(encryptedData.data)

            dataOutputStream.close()
            socket.close()

            Log.d("FileTransferService", "Encrypted file sent successfully: ${file.name}")

            // Broadcast success with consistent action
            val broadcastIntent = Intent("com.skl.securefastfiletransfer.FILE_TRANSFER_COMPLETE")
            broadcastIntent.putExtra("success", true)
            broadcastIntent.putExtra("message", "File sent successfully")
            sendBroadcast(broadcastIntent)

        } catch (e: Exception) {
            Log.e("FileTransferService", "Error sending file: ${e.message}")
            val broadcastIntent = Intent("com.skl.securefastfiletransfer.FILE_TRANSFER_COMPLETE")
            broadcastIntent.putExtra("success", false)
            broadcastIntent.putExtra("message", "Failed to send file: ${e.message}")
            sendBroadcast(broadcastIntent)
        }
    }

    private fun receiveFile(secret: String, saveDirectoryUri: Uri?) {
        try {
            val serverSocket = ServerSocket(FILE_TRANSFER_PORT)
            Log.d("FileTransferService", "Waiting for encrypted file transfer...")

            val socket = serverSocket.accept()
            val inputStream = socket.getInputStream()
            val dataInputStream = DataInputStream(inputStream)

            // Receive file name
            val fileName = dataInputStream.readUTF()
            // Receive encrypted data size
            val encryptedSize = dataInputStream.readLong()
            // Receive IV
            val ivSize = dataInputStream.readInt()
            val iv = ByteArray(ivSize)
            dataInputStream.readFully(iv)

            Log.d("FileTransferService", "Receiving encrypted file: $fileName, size: $encryptedSize bytes")

            // Receive encrypted data
            val encryptedData = ByteArray(encryptedSize.toInt())
            dataInputStream.readFully(encryptedData)

            dataInputStream.close()
            serverSocket.close()

            // Decrypt the file
            val encryptedFileData = CryptoHelper.EncryptedData(encryptedData, iv)
            val decryptedBytes = CryptoHelper.decryptFile(encryptedFileData, secret)

            if (decryptedBytes == null) {
                throw Exception("Failed to decrypt file - incorrect secret or corrupted data")
            }

            // Save file to user-selected directory or fallback to app directory
            val savedFilePath = saveFileToSelectedDirectory(fileName, decryptedBytes, saveDirectoryUri)

            Log.d("FileTransferService", "File decrypted and saved successfully: $fileName")
            Log.d("FileTransferService", "File saved to: $savedFilePath")

            // Broadcast success with file path and consistent action
            val broadcastIntent = Intent("com.skl.securefastfiletransfer.FILE_TRANSFER_COMPLETE")
            broadcastIntent.putExtra("success", true)
            broadcastIntent.putExtra("message", "File received and decrypted successfully: $fileName")
            broadcastIntent.putExtra("file_path", savedFilePath)
            sendBroadcast(broadcastIntent)

        } catch (e: Exception) {
            Log.e("FileTransferService", "Error receiving file: ${e.message}")
            val broadcastIntent = Intent("com.skl.securefastfiletransfer.FILE_TRANSFER_COMPLETE")
            broadcastIntent.putExtra("success", false)
            broadcastIntent.putExtra("message", "Failed to receive file: ${e.message}")
            sendBroadcast(broadcastIntent)
        }
    }

    private fun saveFileToSelectedDirectory(fileName: String, fileBytes: ByteArray, saveDirectoryUri: Uri?): String {
        Log.d("FileTransferService", "Attempting to save file: $fileName")
        Log.d("FileTransferService", "Save directory URI: $saveDirectoryUri")

        return try {
            if (saveDirectoryUri != null) {
                Log.d("FileTransferService", "Using user-selected directory")
                // Save to user-selected directory using DocumentFile
                val directory = DocumentFile.fromTreeUri(this, saveDirectoryUri)
                if (directory != null && directory.exists()) {
                    Log.d("FileTransferService", "Directory is valid and exists")
                    val newFile = directory.createFile("*/*", fileName)
                    if (newFile != null) {
                        Log.d("FileTransferService", "Created new file in selected directory")
                        contentResolver.openOutputStream(newFile.uri)?.use { outputStream ->
                            outputStream.write(fileBytes)
                        }
                        Log.d("FileTransferService", "File saved successfully to: ${newFile.uri}")
                        return newFile.uri.toString()
                    } else {
                        Log.w("FileTransferService", "Failed to create file in selected directory")
                    }
                } else {
                    Log.w("FileTransferService", "Selected directory is null or doesn't exist")
                }
            } else {
                Log.d("FileTransferService", "No save directory provided, using fallback")
            }

            // Fallback: Save to app's external files directory
            Log.d("FileTransferService", "Using fallback directory")
            val downloadsDir = File(getExternalFilesDir(null), "Downloads")
            if (!downloadsDir.exists()) {
                downloadsDir.mkdirs()
            }
            val receivedFile = File(downloadsDir, fileName)
            receivedFile.writeBytes(fileBytes)
            Log.d("FileTransferService", "File saved to fallback location: ${receivedFile.absolutePath}")
            receivedFile.absolutePath

        } catch (e: Exception) {
            Log.e("FileTransferService", "Error saving file: ${e.message}")
            // Emergency fallback: Save to cache directory
            val cacheFile = File(cacheDir, fileName)
            cacheFile.writeBytes(fileBytes)
            Log.d("FileTransferService", "File saved to emergency cache: ${cacheFile.absolutePath}")
            cacheFile.absolutePath
        }
    }
}