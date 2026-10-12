/*
 * This file is part of KotSafe.
 *
 * KotSafe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KotSafe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KotSafe.  If not, see <http://www.gnu.org/licenses/>.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.vpn

import android.content.Context
import android.content.SharedPreferences
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import androidx.annotation.RequiresApi
import com.kotsafe.security.Log
import com.kotsafe.security.R
import com.kotsafe.security.Utils
import com.kotsafe.security.model.CaptureSettings
import com.kotsafe.security.model.Prefs

/**
 * Clean-room Kotlin network and link properties monitor for KotSafe VPN Service.
 * Tracks underlying network connectivity, handles network switches, manages
 * DNS fallback, and enforces Opportunistic/Strict Private DNS controls.
 */
class VpnNetworkMonitor(
    private val context: Context,
    private val prefs: SharedPreferences,
    private val settings: CaptureSettings,
    private val onUnderlyingNetworkChanged: (Array<Network>?) -> Unit,
    private val onDnsServerChanged: (String) -> Unit,
    private val onPrivateDnsBlockStateChanged: (Boolean) -> Unit
) {
    companion object {
        private const val TAG = "VpnNetworkMonitor"
    }

    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    var underlyingNetwork: Network? = null
        private set

    var monitoredNetwork: Long = 0
        private set

    var privateDnsMode: Utils.PrivateDnsMode? = null
        private set

    var isDnsEncrypted: Boolean = false
        private set

    var isPrivateDnsBlocked: Boolean = false
        private set

    private var strictDnsNoticeShown: Boolean = false

    @RequiresApi(Build.VERSION_CODES.M)
    fun register(currentDnsServer: String) {
        if (networkCallback != null) return

        val fallbackDns = Prefs.getDnsServerV4(prefs)
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                super.onAvailable(network)
                Log.d(TAG, "Network onAvailable: $network")
                underlyingNetwork = network
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                    onUnderlyingNetworkChanged(arrayOf(network))
                }
            }

            override fun onLost(network: Network) {
                Log.d(TAG, "onLost $network")
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                    onUnderlyingNetworkChanged(null)
                }

                // If the network goes offline we roll back to fallback DNS server
                if (network.networkHandle == monitoredNetwork) {
                    Log.i(TAG, "Main network $network lost, using fallback DNS $fallbackDns")
                    monitoredNetwork = 0
                    unregister()
                    onDnsServerChanged(fallbackDns)
                }
            }

            @RequiresApi(Build.VERSION_CODES.O)
            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                Log.d(TAG, "onLinkPropertiesChanged $network")
                if (network.networkHandle == monitoredNetwork) {
                    handleLinkProperties(linkProperties)
                }
            }
        }

        try {
            Log.d(TAG, "registerNetworkCallback")
            cm.registerNetworkCallback(
                NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build(),
                networkCallback!!
            )
        } catch (e: SecurityException) {
            // Android 11 bug: https://issuetracker.google.com/issues/175055271?pli=1
            Log.w(TAG, "registerNetworkCallback failed, DNS server detection disabled: $e")
            networkCallback = null
            onDnsServerChanged(fallbackDns)
        }
    }

    fun setMonitoredNetworkHandle(handle: Long) {
        monitoredNetwork = handle
    }

    fun handleLinkProperties(linkProperties: LinkProperties?) {
        if (linkProperties == null) return

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            privateDnsMode = Utils.getPrivateDnsMode(linkProperties)
            Log.i(TAG, "Private DNS: $privateDnsMode")

            if (settings.readFromPcap()) {
                isDnsEncrypted = false
                isPrivateDnsBlocked = false
                onPrivateDnsBlockStateChanged(false)
            } else if (!settings.root_capture && settings.auto_block_private_dns) {
                isDnsEncrypted = privateDnsMode == Utils.PrivateDnsMode.STRICT
                val opportunisticMode = privateDnsMode == Utils.PrivateDnsMode.OPPORTUNISTIC

                if (isPrivateDnsBlocked != opportunisticMode) {
                    isPrivateDnsBlocked = opportunisticMode
                    onPrivateDnsBlockStateChanged(isPrivateDnsBlocked)
                }
            } else {
                isDnsEncrypted = privateDnsMode != Utils.PrivateDnsMode.DISABLED
                isPrivateDnsBlocked = false
                onPrivateDnsBlockStateChanged(false)
            }

            if (isDnsEncrypted && !strictDnsNoticeShown) {
                strictDnsNoticeShown = true
                Utils.showToastLong(context, R.string.private_dns_message_notice)
            }
        }
    }

    fun unregister() {
        networkCallback?.let { cb ->
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            try {
                Log.d(TAG, "unregisterNetworkCallback")
                cm?.unregisterNetworkCallback(cb)
            } catch (e: IllegalArgumentException) {
                Log.w(TAG, "unregisterNetworkCallback failed: $e")
            }
            networkCallback = null
        }
    }
}
