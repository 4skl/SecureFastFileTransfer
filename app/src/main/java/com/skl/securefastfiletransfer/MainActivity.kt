package com.skl.securefastfiletransfer

import android.Manifest
import android.annotation.SuppressLint
import android.net.Uri
import android.os.Bundle
import android.content.Context
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import java.util.UUID
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.ui.Alignment
import androidx.compose.ui.text.style.TextAlign
import java.io.File
import android.content.BroadcastReceiver
import android.content.IntentFilter
import android.content.Intent
import android.os.Build
import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.ui.graphics.asImageBitmap
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import android.content.pm.PackageManager
import android.os.Environment
import androidx.compose.runtime.LaunchedEffect
import androidx.documentfile.provider.DocumentFile

class MainActivity : ComponentActivity(), WiFiTransferHelper.TransferListener {
    private lateinit var wifiTransferHelper: WiFiTransferHelper
    private var handshakeSecret: String? = null
    private var isSender = false
    private var showConfirmDialog by mutableStateOf(false)
    private var status by mutableStateOf("Ready to start secure file transfer")
    private var selectedFileUri: Uri? = null
    private var selectedSaveDirectory: Uri? = null
    private var peerIpAddress: String? = null
    private var waitingForSecret by mutableStateOf(false)
    private var displayedSecret by mutableStateOf("")
    private var showQRCode by mutableStateOf(false)
    private var qrCodeBitmap by mutableStateOf<Bitmap?>(null)
    private var showManualSecretDialog by mutableStateOf(false)
    private var manualSecretInput by mutableStateOf("")
    private var showFileReceivedDialog by mutableStateOf(false)
    private var receivedFilePath by mutableStateOf("")
    private var showPermissionDialog by mutableStateOf(false)

    // Permission request launcher
    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val allGranted = permissions.values.all { it }
        if (!allGranted) {
            Toast.makeText(this, "Permissions are required for file transfer", Toast.LENGTH_LONG).show()
        }
    }

    // Directory picker launcher for receiver
    private val directoryPickerLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri: Uri? ->
        if (uri != null) {
            selectedSaveDirectory = uri
            // Grant persistent permission
            contentResolver.takePersistableUriPermission(
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
            status = "Save directory selected. Ready to scan QR code or enter secret."
            waitingForSecret = true
        } else {
            Toast.makeText(this, "Please select a directory to save received files", Toast.LENGTH_LONG).show()
        }
    }

    // QR Code scanner launcher
    private val qrScannerLauncher = registerForActivityResult(ScanContract()) { result ->
        if (result.contents != null) {
            val scannedSecret = result.contents
            if (QRCodeHelper.isValidSecret(scannedSecret)) {
                handshakeSecret = scannedSecret
                displayedSecret = scannedSecret.take(12) + "..."
                status = "Secret scanned! Connecting to sender..."
                waitingForSecret = false
                startWifiTransfer()
            } else {
                Toast.makeText(this, "Invalid QR code. Please scan a valid secret code.", Toast.LENGTH_LONG).show()
            }
        } else {
            Toast.makeText(this, "QR code scan cancelled", Toast.LENGTH_SHORT).show()
        }
    }

    private val fileTransferReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.skl.securefastfiletransfer.FILE_TRANSFER_COMPLETE") {
                val success = intent.getBooleanExtra("success", false)
                val message = intent.getStringExtra("message") ?: "Unknown result"
                val filePath = intent.getStringExtra("file_path")

                runOnUiThread {
                    status = message
                    if (success) {
                        if (!isSender && filePath != null) {
                            // Show file received dialog for receiver
                            receivedFilePath = filePath
                            showFileReceivedDialog = true
                        }
                        Toast.makeText(this@MainActivity, "Transfer completed successfully!", Toast.LENGTH_LONG).show()
                        resetToIdle()
                    } else {
                        Toast.makeText(this@MainActivity, "Transfer failed: $message", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    private val pickFileLauncher = registerForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        if (uri != null) {
            selectedFileUri = uri
            val fileName = getFileNameFromUri(this, uri)
            // Generate secret immediately when file is selected
            val generatedSecret = UUID.randomUUID().toString()
            handshakeSecret = generatedSecret
            displayedSecret = generatedSecret.take(12) + "..."
            status = "File selected: $fileName. Share the QR code or secret with receiver."

            // Generate QR code
            qrCodeBitmap = QRCodeHelper.generateQRCode(generatedSecret, 400)
            showQRCode = true
        }
    }

    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        wifiTransferHelper = WiFiTransferHelper(this)

        // Register broadcast receiver for file transfer updates
        val filter = IntentFilter("com.skl.securefastfiletransfer.FILE_TRANSFER_COMPLETE")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(fileTransferReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(fileTransferReceiver, filter)
        }

        enableEdgeToEdge()
        setContent {
            Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                Column(
                    modifier = Modifier
                        .padding(innerPadding)
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = "Secure File Transfer",
                        style = MaterialTheme.typography.headlineMedium,
                        fontWeight = FontWeight.Bold,
                        textAlign = TextAlign.Center
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                    ) {
                        Text(
                            text = status,
                            modifier = Modifier.padding(16.dp),
                            style = MaterialTheme.typography.bodyLarge,
                            textAlign = TextAlign.Center
                        )
                    }

                    Button(
                        onClick = {
                            isSender = true
                            resetState()
                            status = "Select a file to send"
                            pickFileLauncher.launch("*/*")
                        },
                        enabled = !waitingForSecret
                    ) {
                        Text("Send File")
                    }

                    Button(
                        onClick = {
                            isSender = false
                            resetState()
                            status = "Select a directory to save received files"
                            // Open directory picker for receiver
                            directoryPickerLauncher.launch(null)
                        },
                        enabled = !waitingForSecret
                    ) {
                        Text("Receive File")
                    }

                    if (displayedSecret.isNotEmpty()) {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
                        ) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Text(
                                    text = "Secret Code:",
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = displayedSecret,
                                    style = MaterialTheme.typography.headlineSmall,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.primary
                                )
                                Text(
                                    text = "Show this QR code to the receiver or verify codes match!",
                                    style = MaterialTheme.typography.bodySmall,
                                    textAlign = TextAlign.Center
                                )

                                if (isSender && qrCodeBitmap != null) {
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Button(
                                        onClick = {
                                            showQRCode = true
                                        }
                                    ) {
                                        Text("Show QR Code")
                                    }
                                }
                            }
                        }
                    }

                    // Scan QR Code button for receivers
                    if (waitingForSecret) {
                        Button(
                            onClick = {
                                val options = ScanOptions().apply {
                                    setPrompt("Scan the sender's QR code")
                                    setBeepEnabled(true)
                                    setOrientationLocked(false) // Allow rotation for better scanning
                                    setBarcodeImageEnabled(true)
                                    setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                    setCameraId(0) // Use back camera
                                    setTimeout(30000) // 30 second timeout
                                }
                                qrScannerLauncher.launch(options)
                            }
                        ) {
                            Text("Scan QR Code")
                        }
                    }

                    if (waitingForSecret) {
                        Button(
                            onClick = {
                                // Manual secret input
                                showManualSecretDialog = true
                            }
                        ) {
                            Text("Enter Secret Manually")
                        }
                    }

                    if (showConfirmDialog) {
                        AlertDialog(
                            onDismissRequest = {},
                            title = {
                                if (isSender) {
                                    Text("Ready to Send File")
                                } else {
                                    Text("Ready to Receive File")
                                }
                            },
                            text = {
                                Column {
                                    Text(
                                        text = if (isSender) {
                                            "Connected to receiver device! Do the secret codes match on both screens?"
                                        } else {
                                            "Connected to sender device! Do the secret codes match on both screens?"
                                        },
                                        style = MaterialTheme.typography.bodyMedium
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    if (!isSender) {
                                        Text(
                                            text = "⚠️ RECEIVER: Please confirm first to prepare for file reception",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.primary,
                                            fontWeight = FontWeight.Bold
                                        )
                                    } else {
                                        Text(
                                            text = "📤 SENDER: Wait for receiver to confirm first, then confirm to start sending",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.secondary,
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                }
                            },
                            confirmButton = {
                                TextButton(onClick = {
                                    showConfirmDialog = false
                                    startFileTransfer()
                                }) {
                                    Text(if (isSender) "Start Sending" else "Ready to Receive")
                                }
                            },
                            dismissButton = {
                                TextButton(onClick = {
                                    showConfirmDialog = false
                                    resetToIdle()
                                }) { Text("Cancel") }
                            }
                        )
                    }

                    if (showQRCode) {
                        AlertDialog(
                            onDismissRequest = {
                                showQRCode = false
                            },
                            title = { Text("Share QR Code") },
                            text = {
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    Text(
                                        text = "Show this QR code to the receiver to share the secret.",
                                        style = MaterialTheme.typography.bodyMedium,
                                        textAlign = TextAlign.Center
                                    )
                                    Spacer(modifier = Modifier.height(16.dp))
                                    // QR code image
                                    qrCodeBitmap?.let { bitmap ->
                                        Image(
                                            bitmap = bitmap.asImageBitmap(),
                                            contentDescription = "QR Code",
                                            modifier = Modifier.size(250.dp)
                                        )
                                    }
                                }
                            },
                            confirmButton = {
                                TextButton(onClick = {
                                    showQRCode = false
                                    // Start WiFi transfer after showing QR code
                                    startWifiTransfer()
                                }) { Text("Continue") }
                            },
                            dismissButton = {
                                TextButton(onClick = {
                                    showQRCode = false
                                    resetToIdle()
                                }) { Text("Cancel") }
                            }
                        )
                    }

                    if (showManualSecretDialog) {
                        AlertDialog(
                            onDismissRequest = {
                                showManualSecretDialog = false
                            },
                            title = { Text("Enter Secret Manually") },
                            text = {
                                Column {
                                    Text(
                                        text = "Enter the complete secret code from the sender's device.",
                                        style = MaterialTheme.typography.bodyMedium
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    // Text field for manual secret input
                                    TextField(
                                        value = manualSecretInput,
                                        onValueChange = { manualSecretInput = it },
                                        label = { Text("Secret Code") },
                                        singleLine = true,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                }
                            },
                            confirmButton = {
                                TextButton(onClick = {
                                    // Verify and proceed with manual secret
                                    if (manualSecretInput.length >= 30) { // UUID length
                                        handshakeSecret = manualSecretInput
                                        displayedSecret = manualSecretInput.take(12)
                                        status = "Secret received! Connecting to sender..."
                                        showManualSecretDialog = false
                                        waitingForSecret = false
                                        manualSecretInput = "" // Clear the input
                                        startWifiTransfer()
                                    } else {
                                        Toast.makeText(this@MainActivity, "Please enter the complete secret code (should be around 36 characters)", Toast.LENGTH_LONG).show()
                                    }
                                }) { Text("Confirm Secret") }
                            },
                            dismissButton = {
                                TextButton(onClick = {
                                    showManualSecretDialog = false
                                    manualSecretInput = "" // Clear the input
                                    resetToIdle()
                                }) { Text("Cancel") }
                            }
                        )
                    }

                    // Show received file dialog
                    if (showFileReceivedDialog) {
                        AlertDialog(
                            onDismissRequest = {
                                showFileReceivedDialog = false
                            },
                            title = { Text("File Received") },
                            text = {
                                Column {
                                    Text(
                                        text = "The file has been received successfully.",
                                        style = MaterialTheme.typography.bodyMedium
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text(
                                        text = "File path: $receivedFilePath",
                                        style = MaterialTheme.typography.bodySmall,
                                        textAlign = TextAlign.Start
                                    )
                                }
                            },
                            confirmButton = {
                                TextButton(onClick = {
                                    showFileReceivedDialog = false
                                }) { Text("OK") }
                            }
                        )
                    }

                    // Request permissions if not granted
                    if (waitingForSecret && !hasRequiredPermissions()) {
                        LaunchedEffect(Unit) {
                            // Show permission rationale and request permissions
                            showPermissionDialog = true
                        }
                    }

                    if (showPermissionDialog) {
                        AlertDialog(
                            onDismissRequest = {
                                showPermissionDialog = false
                            },
                            title = { Text("Permissions Required") },
                            text = {
                                Text(
                                    text = "This app requires certain permissions to be granted for file transfer to work. Please allow the required permissions.",
                                    style = MaterialTheme.typography.bodyMedium
                                )
                            },
                            confirmButton = {
                                TextButton(onClick = {
                                    showPermissionDialog = false
                                    // Request permissions
                                    requestRequiredPermissions()
                                }) { Text("Grant Permissions") }
                            },
                            dismissButton = {
                                TextButton(onClick = {
                                    showPermissionDialog = false
                                    resetToIdle()
                                }) { Text("Cancel") }
                            }
                        )
                    }
                }
            }
        }
    }

    private fun resetState() {
        handshakeSecret = null
        displayedSecret = ""
        selectedFileUri = null
        peerIpAddress = null
    }

    private fun resetToIdle() {
        waitingForSecret = false
        showConfirmDialog = false
        status = "Ready to start secure file transfer"
        isSender = false
        resetState()
    }

    private fun getFileNameFromUri(context: Context, uri: Uri): String? {
        val cursor = context.contentResolver.query(uri, null, null, null, null)
        return cursor?.use {
            if (it.moveToFirst()) {
                val index = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (index >= 0) it.getString(index) else null
            } else null
        }
    }

    override fun onResume() {
        super.onResume()
    }

    override fun onPause() {
        super.onPause()
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(fileTransferReceiver)
        wifiTransferHelper.cleanup()
    }

    // WiFiTransferHelper.TransferListener implementation
    override fun onTransferProgress(bytesTransferred: Long, totalBytes: Long) {
        runOnUiThread {
            val progress = (bytesTransferred * 100 / totalBytes).toInt()
            status = "Transfer progress: $progress%"
        }
    }

    override fun onTransferComplete(success: Boolean, message: String) {
        runOnUiThread {
            status = message
            if (success) {
                Toast.makeText(this, "Transfer completed successfully!", Toast.LENGTH_LONG).show()
                resetToIdle()
            } else {
                Toast.makeText(this, "Transfer failed: $message", Toast.LENGTH_LONG).show()
            }
        }
    }

    override fun onPeerDiscovered(peerIp: String) {
        runOnUiThread {
            status = "Found peer device on network: $peerIp"
        }
    }

    override fun onConnectionEstablished(peerIp: String) {
        runOnUiThread {
            peerIpAddress = peerIp
            if (isSender) {
                status = "Connected to receiver device. Verifying secrets..."
            } else {
                status = "Connected to sender device. Verifying secrets..."
            }
            showConfirmDialog = true
        }
    }

    private fun startWifiTransfer() {
        if (handshakeSecret != null) {
            wifiTransferHelper.setTransferListener(this)
            if (isSender) {
                status = "Starting as sender. Searching for receiver device..."
                wifiTransferHelper.startSender(handshakeSecret!!)
            } else {
                status = "Starting as receiver. Searching for sender device..."
                wifiTransferHelper.startReceiver(handshakeSecret!!)
                // Don't start file receiver here - wait for connection to be established
                // It will be started in startFileTransfer() with the correct save directory
            }
        }
    }

    private fun startFileTransfer() {
        if (isSender) {
            if (selectedFileUri == null || peerIpAddress == null) {
                status = "Missing file or peer connection"
                return
            }

            val filePath = copyUriToCache(selectedFileUri!!)
            if (filePath == null) {
                status = "Failed to prepare file for transfer"
                return
            }

            status = "Sending encrypted file..."
            wifiTransferHelper.sendFile(filePath, peerIpAddress!!)
        } else {
            status = "Ready to receive encrypted file..."
            // Pass the selected directory to the file receiver
            wifiTransferHelper.startFileReceiver(selectedSaveDirectory)
        }
    }

    private fun copyUriToCache(uri: Uri): String? {
        return try {
            val fileName = getFileNameFromUri(this, uri) ?: "tempfile"
            val file = File(cacheDir, fileName)
            contentResolver.openInputStream(uri)?.use { input ->
                java.io.FileOutputStream(file).use { output ->
                    input.copyTo(output)
                }
            }
            file.absolutePath
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    fun onSecretVerified(groupOwnerAddress: String?) {
        runOnUiThread {
            if (isSender && groupOwnerAddress != null) {
                this@MainActivity.peerIpAddress = groupOwnerAddress
            }
            status = "Connection established! Secrets match."
            showConfirmDialog = true
        }
    }

    fun onSecretRejected() {
        runOnUiThread {
            status = "Secret verification failed! Connection rejected for security."
            Toast.makeText(this@MainActivity, "Security check failed - secrets don't match!", Toast.LENGTH_LONG).show()
            resetToIdle()
        }
    }

    private fun requestRequiredPermissions() {
        val permissions = mutableListOf<String>()

        // Add permissions based on Android version
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.addAll(listOf(
                Manifest.permission.READ_MEDIA_IMAGES,
                Manifest.permission.READ_MEDIA_VIDEO,
                Manifest.permission.READ_MEDIA_AUDIO,
                Manifest.permission.CAMERA
            ))
        } else {
            permissions.addAll(listOf(
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE,
                Manifest.permission.CAMERA
            ))
        }

        permissions.addAll(listOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.CHANGE_WIFI_STATE
        ))

        permissionLauncher.launch(permissions.toTypedArray())
    }

    private fun hasRequiredPermissions(): Boolean {
        val cameraPermission = ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
        val locationPermission = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        val wifiPermission = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_WIFI_STATE) == PackageManager.PERMISSION_GRANTED

        val storagePermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(this, Manifest.permission.READ_MEDIA_IMAGES) == PackageManager.PERMISSION_GRANTED
        } else {
            ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
        }

        return cameraPermission && locationPermission && wifiPermission && storagePermission
    }
}
