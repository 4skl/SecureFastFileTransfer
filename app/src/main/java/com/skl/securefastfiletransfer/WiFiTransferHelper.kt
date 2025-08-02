package com.skl.securefastfiletransfer

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import java.io.*
import java.net.*
import java.util.concurrent.Executors

class WiFiTransferHelper(private val context: Context) {

    interface TransferListener {
        fun onTransferProgress(bytesTransferred: Long, totalBytes: Long)
        fun onTransferComplete(success: Boolean, message: String)
        fun onPeerDiscovered(peerIp: String)
        fun onConnectionEstablished(peerIp: String)
    }

    private var transferListener: TransferListener? = null
    private var discoverySocket: DatagramSocket? = null
    private var secretServerSocket: ServerSocket? = null
    private var currentSecret: String? = null
    private val executor = Executors.newCachedThreadPool()
    private var isRunning = false
    private var isSender = false

    companion object {
        private const val DISCOVERY_PORT = 8987
        private const val SECRET_VERIFICATION_PORT = 8988
        private const val BROADCAST_MESSAGE = "NFConnect_Discovery"
    }

    fun setTransferListener(listener: TransferListener) {
        this.transferListener = listener
    }

    fun startSender(secret: String) {
        currentSecret = secret
        isRunning = true
        isSender = true

        Log.d("WiFiTransferHelper", "Starting sender with secret: ${secret.take(8)}...")

        // Start discovery server to respond to receiver's broadcast
        executor.submit {
            startDiscoveryServer()
        }

        // Start secret verification server
        executor.submit {
            startSecretVerificationServer()
        }
    }

    fun startReceiver(secret: String) {
        currentSecret = secret
        isRunning = true
        isSender = false

        Log.d("WiFiTransferHelper", "Starting receiver with secret: ${secret.take(8)}...")

        // Small delay to ensure sender is ready
        Thread.sleep(2000)

        // Start discovery by broadcasting
        executor.submit {
            discoverSender()
        }
    }

    private fun startDiscoveryServer() {
        try {
            // Close existing socket if any
            discoverySocket?.close()

            discoverySocket = DatagramSocket(DISCOVERY_PORT)
            discoverySocket?.soTimeout = 30000 // 30 second timeout

            Log.d("WiFiTransferHelper", "Discovery server listening on port $DISCOVERY_PORT")
            val buffer = ByteArray(1024)

            while (isRunning) {
                try {
                    val packet = DatagramPacket(buffer, buffer.size)
                    discoverySocket?.receive(packet)

                    val message = String(packet.data, 0, packet.length)
                    Log.d("WiFiTransferHelper", "Received discovery message: $message")

                    if (message.startsWith(BROADCAST_MESSAGE)) {
                        // Respond to discovery request
                        val response = "NFConnect_Response:${currentSecret?.take(8)}"
                        val responsePacket = DatagramPacket(
                            response.toByteArray(),
                            response.length,
                            packet.address,
                            packet.port
                        )
                        discoverySocket?.send(responsePacket)

                        Log.d("WiFiTransferHelper", "Responded to discovery from ${packet.address.hostAddress}")
                        transferListener?.onPeerDiscovered(packet.address.hostAddress)

                        // Break after first successful response to avoid conflicts
                        break
                    }
                } catch (e: SocketTimeoutException) {
                    if (isRunning) {
                        Log.d("WiFiTransferHelper", "Discovery server timeout, continuing...")
                    }
                } catch (e: Exception) {
                    if (isRunning) {
                        Log.e("WiFiTransferHelper", "Discovery server error: ${e.message}")
                    }
                    break
                }
            }
        } catch (e: Exception) {
            Log.e("WiFiTransferHelper", "Failed to start discovery server: ${e.message}")
        } finally {
            discoverySocket?.close()
        }
    }

    private fun discoverSender() {
        try {
            val socket = DatagramSocket()
            socket.broadcast = true
            socket.soTimeout = 5000 // 5 second timeout per attempt

            val message = "$BROADCAST_MESSAGE:${currentSecret?.take(8)}"
            val buffer = message.toByteArray()

            // Try to discover on multiple network addresses
            val addresses = listOf(
                "255.255.255.255",
                "192.168.1.255",
                "192.168.0.255",
                "10.0.0.255"
            )

            var found = false

            for (attempt in 1..5) {
                if (found) break

                Log.d("WiFiTransferHelper", "Discovery attempt $attempt")

                for (addressString in addresses) {
                    try {
                        val broadcast = InetAddress.getByName(addressString)
                        val packet = DatagramPacket(buffer, buffer.size, broadcast, DISCOVERY_PORT)
                        socket.send(packet)

                        // Listen for response
                        val responseBuffer = ByteArray(1024)
                        val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
                        socket.receive(responsePacket)

                        val response = String(responsePacket.data, 0, responsePacket.length)
                        Log.d("WiFiTransferHelper", "Received response: $response")

                        if (response.startsWith("NFConnect_Response")) {
                            val senderIp = responsePacket.address.hostAddress
                            Log.d("WiFiTransferHelper", "Found sender at: $senderIp")
                            transferListener?.onPeerDiscovered(senderIp)

                            // Small delay before verification
                            Thread.sleep(1000)

                            // Attempt secret verification
                            verifySecretWithSender(senderIp)
                            found = true
                            break
                        }
                    } catch (e: SocketTimeoutException) {
                        // Try next address
                        continue
                    } catch (e: Exception) {
                        Log.w("WiFiTransferHelper", "Error with address $addressString: ${e.message}")
                    }
                }

                if (!found) {
                    Thread.sleep(2000) // Wait before next attempt
                }
            }

            socket.close()

            if (!found) {
                transferListener?.onTransferComplete(false, "Could not find sender device")
            }

        } catch (e: Exception) {
            Log.e("WiFiTransferHelper", "Discovery error: ${e.message}")
            transferListener?.onTransferComplete(false, "Discovery failed: ${e.message}")
        }
    }

    private fun startSecretVerificationServer() {
        try {
            // Close existing socket if any
            secretServerSocket?.close()

            secretServerSocket = ServerSocket(SECRET_VERIFICATION_PORT)
            secretServerSocket?.soTimeout = 60000 // 1 minute timeout

            Log.d("WiFiTransferHelper", "Secret verification server listening on port $SECRET_VERIFICATION_PORT")

            while (isRunning) {
                try {
                    val client = secretServerSocket?.accept() ?: break
                    Log.d("WiFiTransferHelper", "Client connected for secret verification")

                    executor.submit {
                        handleSecretVerification(client)
                    }

                    // Only handle one verification to avoid conflicts
                    break
                } catch (e: SocketTimeoutException) {
                    if (isRunning) {
                        Log.d("WiFiTransferHelper", "Secret server timeout, continuing...")
                    }
                } catch (e: Exception) {
                    if (isRunning) {
                        Log.e("WiFiTransferHelper", "Secret verification server error: ${e.message}")
                    }
                    break
                }
            }
        } catch (e: Exception) {
            Log.e("WiFiTransferHelper", "Failed to start secret verification server: ${e.message}")
        }
    }

    private fun handleSecretVerification(client: Socket) {
        try {
            client.soTimeout = 10000 // 10 second timeout
            val input = BufferedReader(InputStreamReader(client.getInputStream()))
            val output = PrintWriter(client.getOutputStream(), true)

            val receivedSecret = input.readLine()
            Log.d("WiFiTransferHelper", "Received secret verification: ${receivedSecret?.take(8)}...")

            if (receivedSecret == currentSecret) {
                output.println("SECRET_VERIFIED")
                Log.d("WiFiTransferHelper", "Secret verified with client: ${client.inetAddress.hostAddress}")
                transferListener?.onConnectionEstablished(client.inetAddress.hostAddress)
            } else {
                output.println("SECRET_REJECTED")
                Log.w("WiFiTransferHelper", "Secret rejected from client: ${client.inetAddress.hostAddress}")
                transferListener?.onTransferComplete(false, "Secret mismatch - security check failed")
            }

            client.close()
        } catch (e: Exception) {
            Log.e("WiFiTransferHelper", "Secret verification error: ${e.message}")
            transferListener?.onTransferComplete(false, "Secret verification failed: ${e.message}")
        }
    }

    private fun verifySecretWithSender(senderIp: String) {
        executor.submit {
            try {
                // Multiple connection attempts with delays
                var connected = false

                for (attempt in 1..3) {
                    try {
                        Log.d("WiFiTransferHelper", "Secret verification attempt $attempt to $senderIp")

                        val socket = Socket()
                        socket.connect(InetSocketAddress(senderIp, SECRET_VERIFICATION_PORT), 10000)
                        socket.soTimeout = 10000

                        val output = PrintWriter(socket.getOutputStream(), true)
                        val input = BufferedReader(InputStreamReader(socket.getInputStream()))

                        output.println(currentSecret)
                        val response = input.readLine()

                        if (response == "SECRET_VERIFIED") {
                            Log.d("WiFiTransferHelper", "Secret verified with sender")
                            transferListener?.onConnectionEstablished(senderIp)
                            connected = true
                            socket.close()
                            break
                        } else {
                            Log.w("WiFiTransferHelper", "Secret rejected by sender: $response")
                            socket.close()
                        }
                    } catch (e: Exception) {
                        Log.w("WiFiTransferHelper", "Secret verification attempt $attempt failed: ${e.message}")
                        if (attempt < 3) {
                            Thread.sleep(2000) // Wait before retry
                        }
                    }
                }

                if (!connected) {
                    transferListener?.onTransferComplete(false, "Secret verification failed after multiple attempts")
                }

            } catch (e: Exception) {
                Log.e("WiFiTransferHelper", "Secret verification error: ${e.message}")
                transferListener?.onTransferComplete(false, "Connection failed: ${e.message}")
            }
        }
    }

    fun sendFile(filePath: String, peerIp: String) {
        if (currentSecret == null) {
            transferListener?.onTransferComplete(false, "No secret available for encryption")
            return
        }

        Log.d("WiFiTransferHelper", "Starting encrypted file transfer to $peerIp")

        // Use updated FileTransferService
        FileTransferService.startService(
            context = context,
            action = FileTransferService.ACTION_SEND_FILE,
            filePath = filePath,
            hostAddress = peerIp,
            secret = currentSecret!!
        )
    }

    fun startFileReceiver(saveDirectory: Uri? = null) {
        if (currentSecret == null) {
            transferListener?.onTransferComplete(false, "No secret available for decryption")
            return
        }

        Log.d("WiFiTransferHelper", "Starting encrypted file receiver")

        // Use updated FileTransferService with save directory
        FileTransferService.startService(
            context = context,
            action = FileTransferService.ACTION_RECEIVE_FILE,
            secret = currentSecret!!,
            saveDirectoryUri = saveDirectory
        )
    }

    fun cleanup() {
        isRunning = false
        try {
            discoverySocket?.close()
            secretServerSocket?.close()
        } catch (e: Exception) {
            Log.w("WiFiTransferHelper", "Error during cleanup: ${e.message}")
        }
        executor.shutdown()
    }
}
