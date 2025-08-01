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
import androidx.compose.foundation.clickable
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
import androidx.compose.ui.text.style.TextDecoration
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
import androidx.core.content.ContextCompat
import android.content.pm.PackageManager
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.width
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.material3.Icon
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material3.IconButton
import androidx.compose.runtime.Composable

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
    private var showAboutDialog by mutableStateOf(false)
    private var isSearchingDevices by mutableStateOf(false)

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
                displayedSecret = scannedSecret
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
                    isSearchingDevices = false
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
            displayedSecret = generatedSecret
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
            MainContent()
        }
    }

    @Composable
    private fun MainContent() {
        MaterialTheme {
            val clipboardManager = LocalClipboardManager.current

            Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                Column(
                    modifier = Modifier
                        .padding(innerPadding)
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = "🔐 Secure File Transfer",
                        style = MaterialTheme.typography.headlineMedium,
                        fontWeight = FontWeight.Bold,
                        textAlign = TextAlign.Center,
                        color = MaterialTheme.colorScheme.primary
                    )

                    // Information card explaining how to use the app
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer)
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp)
                        ) {
                            Text(
                                text = "📱 How it works:",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onTertiaryContainer
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "• Send: Select file → Share QR code/secret → Wait for receiver → Confirm transfer\n" +
                                        "• Receive: Select save folder → Scan QR/Enter secret → Confirm → File received securely\n" +
                                        "• All files are encrypted with AES-256 during transfer",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onTertiaryContainer
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            TextButton(
                                onClick = { showAboutDialog = true }
                            ) {
                                Text("Learn more about security features")
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    // Status card with search indicator
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                    ) {
                        Row(
                            modifier = Modifier.padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center
                        ) {
                            if (isSearchingDevices) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(20.dp),
                                    strokeWidth = 2.dp,
                                    color = MaterialTheme.colorScheme.primary
                                )
                                Spacer(modifier = Modifier.width(12.dp))
                            }
                            Text(
                                text = if (isSearchingDevices) "🔍 Searching for devices..." else status,
                                style = MaterialTheme.typography.bodyLarge,
                                textAlign = TextAlign.Center,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    Button(
                        onClick = {
                            isSender = true
                            resetState()
                            status = "Select a file to send"
                            pickFileLauncher.launch("*/*")
                        },
                        enabled = !waitingForSecret && !isSearchingDevices
                    ) {
                        Text("📤 Send File")
                    }

                    Button(
                        onClick = {
                            isSender = false
                            resetState()
                            status = "Select a directory to save received files"
                            // Open directory picker for receiver
                            directoryPickerLauncher.launch(null)
                        },
                        enabled = !waitingForSecret && !isSearchingDevices
                    ) {
                        Text("📥 Receive File")
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
                                    text = "🔑 Secret Code:",
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer
                                )
                                Spacer(modifier = Modifier.height(8.dp))

                                // Selectable secret text with copy button
                                Card(
                                    modifier = Modifier.fillMaxWidth(),
                                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                                ) {
                                    Row(
                                        modifier = Modifier.padding(12.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        SelectionContainer(
                                            modifier = Modifier.weight(1f)
                                        ) {
                                            Text(
                                                text = handshakeSecret ?: "",
                                                style = MaterialTheme.typography.bodySmall,
                                                fontWeight = FontWeight.Medium,
                                                color = MaterialTheme.colorScheme.onSurface,
                                                textAlign = TextAlign.Center
                                            )
                                        }
                                        IconButton(
                                            onClick = {
                                                clipboardManager.setText(AnnotatedString(handshakeSecret ?: ""))
                                                Toast.makeText(this@MainActivity, "Secret copied to clipboard", Toast.LENGTH_SHORT).show()
                                            }
                                        ) {
                                            Icon(
                                                imageVector = Icons.Default.ContentCopy,
                                                contentDescription = "Copy secret",
                                                tint = MaterialTheme.colorScheme.primary
                                            )
                                        }
                                    }
                                }

                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    text = "Share this secret with the receiver device!",
                                    style = MaterialTheme.typography.bodySmall,
                                    textAlign = TextAlign.Center,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer
                                )

                                if (isSender && qrCodeBitmap != null) {
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Button(
                                        onClick = {
                                            showQRCode = true
                                        }
                                    ) {
                                        Text("📱 Show QR Code")
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
                            Text("📷 Scan QR Code")
                        }
                    }

                    if (waitingForSecret) {
                        Button(
                            onClick = {
                                // Manual secret input
                                showManualSecretDialog = true
                            }
                        ) {
                            Text("⌨️ Enter Secret Manually")
                        }
                    }

                    // All the existing dialogs...
                    ShowDialogs(clipboardManager)
                }
            }
        }
    }

    @Composable
    private fun ShowDialogs(clipboardManager: androidx.compose.ui.platform.ClipboardManager) {
        // Show all the dialogs: confirm, QR, manual secret, file received, permissions, about
        if (showConfirmDialog) {
            AlertDialog(
                onDismissRequest = {},
                title = {
                    Text(
                        if (isSender) "📤 Ready to Send File" else "📥 Ready to Receive File",
                        color = MaterialTheme.colorScheme.primary
                    )
                },
                text = {
                    Column {
                        Text(
                            text = if (isSender) {
                                "Connected to receiver device! Verify the secret codes match on both screens before proceeding."
                            } else {
                                "Connected to sender device! Verify the secret codes match on both screens before proceeding."
                            },
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Spacer(modifier = Modifier.height(12.dp))

                        // Show secret key for verification
                        Text(
                            text = "🔑 Secret Key:",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
                        ) {
                            SelectionContainer {
                                Text(
                                    text = handshakeSecret ?: "",
                                    modifier = Modifier.padding(8.dp),
                                    style = MaterialTheme.typography.bodySmall,
                                    textAlign = TextAlign.Center,
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(12.dp))
                        if (!isSender) {
                            Card(
                                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
                            ) {
                                Text(
                                    text = "⚠️ RECEIVER: Please confirm first to prepare for file reception",
                                    modifier = Modifier.padding(8.dp),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.primary,
                                    fontWeight = FontWeight.Bold,
                                    textAlign = TextAlign.Center
                                )
                            }
                        } else {
                            Card(
                                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)
                            ) {
                                Text(
                                    text = "📤 SENDER: Wait for receiver to confirm first, then confirm to start sending",
                                    modifier = Modifier.padding(8.dp),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.secondary,
                                    fontWeight = FontWeight.Bold,
                                    textAlign = TextAlign.Center
                                )
                            }
                        }
                    }
                },
                confirmButton = {
                    Button(onClick = {
                        showConfirmDialog = false
                        startFileTransfer()
                    }) {
                        Text(if (isSender) "✅ Start Sending" else "✅ Ready to Receive")
                    }
                },
                dismissButton = {
                    TextButton(onClick = {
                        showConfirmDialog = false
                        resetToIdle()
                    }) { Text("❌ Cancel") }
                }
            )
        }

        if (showQRCode) {
            AlertDialog(
                onDismissRequest = {
                    showQRCode = false
                },
                title = {
                    Text(
                        "📱 Share QR Code",
                        color = MaterialTheme.colorScheme.primary
                    )
                },
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
                            Card(
                                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                            ) {
                                Image(
                                    bitmap = bitmap.asImageBitmap(),
                                    contentDescription = "QR Code",
                                    modifier = Modifier
                                        .size(250.dp)
                                        .padding(8.dp)
                                )
                            }
                        }
                        Spacer(modifier = Modifier.height(16.dp))
                        // Show the actual secret key text
                        Text(
                            text = "🔑 Secret Key:",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                        ) {
                            SelectionContainer {
                                Text(
                                    text = handshakeSecret ?: "",
                                    modifier = Modifier.padding(8.dp),
                                    style = MaterialTheme.typography.bodySmall,
                                    textAlign = TextAlign.Center,
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }
                    }
                },
                confirmButton = {
                    Button(onClick = {
                        showQRCode = false
                        // Start WiFi transfer after showing QR code
                        startWifiTransfer()
                    }) { Text("✅ Continue") }
                },
                dismissButton = {
                    TextButton(onClick = {
                        showQRCode = false
                        resetToIdle()
                    }) { Text("❌ Cancel") }
                }
            )
        }

        // Continue with other dialogs...
        if (showManualSecretDialog) {
            AlertDialog(
                onDismissRequest = {
                    showManualSecretDialog = false
                },
                title = {
                    Text(
                        "⌨️ Enter Secret Manually",
                        color = MaterialTheme.colorScheme.primary
                    )
                },
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
                    Button(onClick = {
                        // Verify and proceed with manual secret
                        if (manualSecretInput.length >= 30) { // UUID length
                            handshakeSecret = manualSecretInput
                            displayedSecret = manualSecretInput
                            status = "Secret received! Connecting to sender..."
                            showManualSecretDialog = false
                            waitingForSecret = false
                            manualSecretInput = "" // Clear the input
                            startWifiTransfer()
                        } else {
                            Toast.makeText(this@MainActivity, "Please enter the complete secret code (should be around 36 characters)", Toast.LENGTH_LONG).show()
                        }
                    }) { Text("✅ Confirm Secret") }
                },
                dismissButton = {
                    TextButton(onClick = {
                        showManualSecretDialog = false
                        manualSecretInput = "" // Clear the input
                        resetToIdle()
                    }) { Text("❌ Cancel") }
                }
            )
        }

        // Show received file dialog
        if (showFileReceivedDialog) {
            AlertDialog(
                onDismissRequest = {
                    showFileReceivedDialog = false
                },
                title = {
                    Text(
                        "🎉 File Received Successfully!",
                        color = MaterialTheme.colorScheme.primary
                    )
                },
                text = {
                    Column {
                        Text(
                            text = "The file has been received and decrypted successfully.",
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Spacer(modifier = Modifier.height(12.dp))

                        Text(
                            text = "📁 Saved to:",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(4.dp))

                        // Clickable file path with folder icon
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
                        ) {
                            Row(
                                modifier = Modifier
                                    .clickable {
                                        openFileLocation(receivedFilePath)
                                    }
                                    .padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    imageVector = Icons.Default.FolderOpen,
                                    contentDescription = "Open folder",
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(20.dp)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = receivedFilePath,
                                    style = MaterialTheme.typography.bodySmall.copy(
                                        textDecoration = TextDecoration.Underline
                                    ),
                                    color = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.weight(1f)
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "📁 Tap the path above to open the file location",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.secondary,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                },
                confirmButton = {
                    Button(onClick = {
                        showFileReceivedDialog = false
                    }) { Text("✅ OK") }
                },
                dismissButton = {
                    TextButton(onClick = {
                        showFileReceivedDialog = false
                        openFileLocation(receivedFilePath)
                    }) { Text("📁 Open Location") }
                }
            )
        }

        // Rest of dialogs (permissions, about)...
        if (waitingForSecret && !hasRequiredPermissions()) {
            LaunchedEffect(Unit) {
                showPermissionDialog = true
            }
        }

        if (showPermissionDialog) {
            AlertDialog(
                onDismissRequest = {
                    showPermissionDialog = false
                },
                title = {
                    Text(
                        "🔐 Permissions Required",
                        color = MaterialTheme.colorScheme.primary
                    )
                },
                text = {
                    Text(
                        text = "This app requires certain permissions to be granted for file transfer to work. Please allow the required permissions.",
                        style = MaterialTheme.typography.bodyMedium
                    )
                },
                confirmButton = {
                    Button(onClick = {
                        showPermissionDialog = false
                        requestRequiredPermissions()
                    }) { Text("✅ Grant Permissions") }
                },
                dismissButton = {
                    TextButton(onClick = {
                        showPermissionDialog = false
                        resetToIdle()
                    }) { Text("❌ Cancel") }
                }
            )
        }

        if (showAboutDialog) {
            AlertDialog(
                onDismissRequest = {
                    showAboutDialog = false
                },
                title = {
                    Text(
                        "ℹ️ About Secure File Transfer",
                        color = MaterialTheme.colorScheme.primary
                    )
                },
                text = {
                    Column {
                        Text(
                            text = "This app allows secure file transfer between devices using Wi-Fi Direct and QR codes. Files are encrypted with AES-256 for security.",
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Spacer(modifier = Modifier.height(12.dp))

                        Card(
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text(
                                    text = "🔒 Security Features:",
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.Bold
                                )
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = "• Wi-Fi Direct: Direct device connection without internet\n" +
                                            "• QR Codes: Quick and secure secret key sharing\n" +
                                            "• AES-256 Encryption: Military-grade file encryption\n" +
                                            "• No cloud storage: Files stay on your devices",
                                    style = MaterialTheme.typography.bodySmall
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "Developed by: 4skl with AI",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Bold,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                },
                confirmButton = {
                    Button(onClick = {
                        showAboutDialog = false
                    }) { Text("✅ Close") }
                }
            )
        }
    }

    // Required helper functions
    private fun resetState() {
        handshakeSecret = null
        displayedSecret = ""
        selectedFileUri = null
        peerIpAddress = null
        isSearchingDevices = false
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

    private fun hasRequiredPermissions(): Boolean {
        val requiredPermissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            arrayOf(
                Manifest.permission.ACCESS_WIFI_STATE,
                Manifest.permission.CHANGE_WIFI_STATE,
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.NEARBY_WIFI_DEVICES
            )
        } else {
            arrayOf(
                Manifest.permission.ACCESS_WIFI_STATE,
                Manifest.permission.CHANGE_WIFI_STATE,
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION
            )
        }

        return requiredPermissions.all { permission ->
            ContextCompat.checkSelfPermission(this, permission) == PackageManager.PERMISSION_GRANTED
        }
    }

    private fun requestRequiredPermissions() {
        val requiredPermissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            arrayOf(
                Manifest.permission.ACCESS_WIFI_STATE,
                Manifest.permission.CHANGE_WIFI_STATE,
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.NEARBY_WIFI_DEVICES
            )
        } else {
            arrayOf(
                Manifest.permission.ACCESS_WIFI_STATE,
                Manifest.permission.CHANGE_WIFI_STATE,
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION
            )
        }

        permissionLauncher.launch(requiredPermissions)
    }

    private fun openFileLocation(filePath: String) {
        try {
            val file = File(filePath)
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(Uri.fromFile(file.parentFile), "resource/folder")
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }

            if (intent.resolveActivity(packageManager) != null) {
                startActivity(intent)
            } else {
                val fileIntent = Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(Uri.fromFile(file), "*/*")
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION
                }
                if (fileIntent.resolveActivity(packageManager) != null) {
                    startActivity(fileIntent)
                } else {
                    Toast.makeText(this, "No file manager found. File saved at: $filePath", Toast.LENGTH_LONG).show()
                }
            }
        } catch (_: Exception) {
            Toast.makeText(this, "Cannot open file location. File saved at: $filePath", Toast.LENGTH_LONG).show()
        }
    }

    private fun startWifiTransfer() {
        if (handshakeSecret != null) {
            isSearchingDevices = true
            wifiTransferHelper.setTransferListener(this)
            if (isSender) {
                status = "Starting as sender..."
                wifiTransferHelper.startSender(handshakeSecret!!)
            } else {
                status = "Starting as receiver..."
                wifiTransferHelper.startReceiver(handshakeSecret!!)
            }
        }
    }

    private fun startFileTransfer() {
        if (isSender) {
            if (selectedFileUri == null) {
                status = "Missing file"
                return
            }

            if(peerIpAddress == null) {
                status = "Missing peer connection"
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

    // WiFiTransferHelper.TransferListener implementation
    override fun onTransferProgress(bytesTransferred: Long, totalBytes: Long) {
        runOnUiThread {
            val progress = (bytesTransferred * 100 / totalBytes).toInt()
            status = "Transfer progress: $progress%"
        }
    }

    override fun onTransferComplete(success: Boolean, message: String) {
        runOnUiThread {
            isSearchingDevices = false
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
            isSearchingDevices = false
        }
    }

    override fun onConnectionEstablished(peerIp: String) {
        runOnUiThread {
            peerIpAddress = peerIp
            isSearchingDevices = false
            if (isSender) {
                status = "Connected to receiver device. Verifying secrets..."
            } else {
                status = "Connected to sender device. Verifying secrets..."
            }
            showConfirmDialog = true
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
        try {
            unregisterReceiver(fileTransferReceiver)
        } catch (_: Exception) {
            // Receiver may not be registered
        }
        wifiTransferHelper.cleanup()
    }
}
