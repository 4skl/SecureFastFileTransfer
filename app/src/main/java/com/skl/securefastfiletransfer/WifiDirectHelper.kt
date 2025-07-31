package com.skl.securefastfiletransfer

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager.ActionListener
import android.net.wifi.p2p.WifiP2pManager.PeerListListener
import android.util.Log
import android.net.wifi.p2p.WifiP2pManager
import androidx.annotation.RequiresPermission

class WifiDirectHelper(context: Context) {
    private val manager = context.getSystemService(Context.WIFI_P2P_SERVICE) as WifiP2pManager
    private val channel = manager.initialize(context, context.mainLooper, null)

    private var secret: String? = null
    private var isGroupOwner = false
    private var discoveredPeers: List<WifiP2pDevice> = emptyList()
    private var connectionInfoListener: WifiP2pManager.ConnectionInfoListener? = null

    // Callback interface for secret verification result
    interface SecretVerificationListener {
        fun onSecretVerified(groupOwnerAddress: String?)
        fun onSecretRejected()
    }

    private var secretVerificationListener: SecretVerificationListener? = null

    fun setSecretVerificationListener(listener: SecretVerificationListener) {
        this.secretVerificationListener = listener
    }

    private var lastGroupOwnerAddress: String? = null

    fun getLastGroupOwnerAddress(): String? = lastGroupOwnerAddress

    private val appContext = context.applicationContext
    private val connectionChangedReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION) {
                manager.requestConnectionInfo(channel) { info ->
                    connectionInfoListener?.onConnectionInfoAvailable(info)
                }
            }
        }
    }

    init {
        connectionInfoListener = WifiP2pManager.ConnectionInfoListener { info ->
            if (info.groupFormed) {
                lastGroupOwnerAddress = info.groupOwnerAddress?.hostAddress
                Log.d("WifiDirectHelper", "Wi-Fi Direct group formed. Group owner: ${info.isGroupOwner}, address: $lastGroupOwnerAddress")
                if (isGroupOwner) {
                    // Start server socket to receive secret from client
                    Thread {
                        try {
                            val serverSocket = java.net.ServerSocket(8988)
                            val client = serverSocket.accept()
                            val input = client.getInputStream()
                            val reader = input.bufferedReader()
                            val receivedSecret = reader.readLine()
                            if (receivedSecret == secret) {
                                Log.d("WifiDirectHelper", "Secret verified! Waiting for user confirmation.")
                                secretVerificationListener?.onSecretVerified(lastGroupOwnerAddress)
                                // Wait for user confirmation before file transfer
                            } else {
                                Log.e("WifiDirectHelper", "Secret mismatch! Rejecting connection.")
                                secretVerificationListener?.onSecretRejected()
                                client.close()
                            }
                            serverSocket.close()
                        } catch (e: Exception) {
                            Log.e("WifiDirectHelper", "Server error: ${e.message}")
                        }
                    }.start()
                } else {
                    // Connect to group owner and send secret
                    Thread {
                        try {
                            val host = info.groupOwnerAddress.hostAddress
                            val socket = java.net.Socket(host, 8988)
                            val writer = socket.getOutputStream().bufferedWriter()
                            writer.write(secret)
                            writer.newLine()
                            writer.flush()
                            Log.d("WifiDirectHelper", "Secret sent to group owner. Waiting for user confirmation.")
                            secretVerificationListener?.onSecretVerified(lastGroupOwnerAddress)
                            socket.close()
                        } catch (e: Exception) {
                            Log.e("WifiDirectHelper", "Client error: ${e.message}")
                            secretVerificationListener?.onSecretRejected()
                        }
                    }.start()
                }
            }
        }

        // Register receiver for connection changes
        val filter = IntentFilter(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
        appContext.registerReceiver(connectionChangedReceiver, filter)
    }

    @RequiresPermission(allOf = [Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.NEARBY_WIFI_DEVICES])
    fun startGroupOwnerWithSecret(secret: String) {
        this.secret = secret
        isGroupOwner = true
        // Create group (become group owner)
        manager.createGroup(channel, object : ActionListener {
            override fun onSuccess() {
                Log.d("WifiDirectHelper", "Group created as owner. Waiting for client.")
                // Wait for connection, then verify secret in your connection logic
            }
            override fun onFailure(reason: Int) {
                Log.e("WifiDirectHelper", "Failed to create group: $reason")
            }
        })
    }

    @RequiresPermission(allOf = [Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.NEARBY_WIFI_DEVICES])
    fun startDiscoveryWithSecret(secret: String) {
        this.secret = secret
        isGroupOwner = false
        // Discover peers
        manager.discoverPeers(channel, object : ActionListener {
            override fun onSuccess() {
                Log.d("WifiDirectHelper", "Peer discovery started.")
            }
            override fun onFailure(reason: Int) {
                Log.e("WifiDirectHelper", "Peer discovery failed: $reason")
            }
        })
        // Listen for peers
        manager.requestPeers(channel, PeerListListener { peers ->
            discoveredPeers = peers.deviceList.toList()
            if (discoveredPeers.isNotEmpty()) {
                // Connect to the first peer (group owner)
                val config = WifiP2pConfig().apply {
                    deviceAddress = discoveredPeers[0].deviceAddress
                }
                manager.connect(channel, config, object : ActionListener {
                    override fun onSuccess() {
                        Log.d("WifiDirectHelper", "Connecting to group owner.")
                        // Wait for connection, then verify secret in your connection logic
                    }
                    override fun onFailure(reason: Int) {
                        Log.e("WifiDirectHelper", "Connection failed: $reason")
                    }
                })
            }
        })
    }

    fun cleanup() {
        appContext.unregisterReceiver(connectionChangedReceiver)
    }

    // TODO: Add connection info listener and secret verification logic in your connection callback
}