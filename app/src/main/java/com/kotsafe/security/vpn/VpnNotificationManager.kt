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

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.kotsafe.security.AppsResolver
import com.kotsafe.security.CaptureService
import com.kotsafe.security.Log
import com.kotsafe.security.R
import com.kotsafe.security.Utils
import com.kotsafe.security.activities.AppsActivity
import com.kotsafe.security.activities.ConnectionsActivity
import com.kotsafe.security.activities.MainActivity
import com.kotsafe.security.activities.SecurityActionsActivity
import com.kotsafe.security.activities.StatsActivity
import com.kotsafe.security.fragments.ConnectionsFragment
import com.kotsafe.security.model.CaptureStats
import com.kotsafe.security.model.ConnectionDescriptor
import com.kotsafe.security.model.FilterDescriptor
import com.kotsafe.security.model.MatchList
import com.kotsafe.security.model.Prefs
import java.util.concurrent.ConcurrentHashMap

/**
 * Clean-room Kotlin notification manager for KotSafe VPN Service.
 * Manages foreground service status notification, malware alert notifications,
 * low-memory notices, and P2P leak shield warnings.
 */
class VpnNotificationManager(
    private val context: Context,
    private val prefs: SharedPreferences,
    private val onStopRequested: Runnable
) {
    companion object {
        private const val TAG = "VpnNotificationManager"
        const val NOTIFY_CHAN_VPNSERVICE = "VPNService"
        const val NOTIFY_CHAN_MALWARE_DETECTION = "Malware detection"
        const val NOTIFY_CHAN_OTHER = "Other"

        const val NOTIFY_ID_VPNSERVICE = 1
        const val NOTIFY_ID_LOW_MEMORY = 2

        private const val BLACKLIST_NOTIF_COOLDOWN_MS = 60_000L
    }

    private val mainHandler = Handler(Looper.getMainLooper())
    private var statusBuilder: NotificationCompat.Builder? = null
    private var malwareBuilder: NotificationCompat.Builder? = null
    private var notificationReceiver: BroadcastReceiver? = null

    @Volatile
    var isNotificationDismissed = false
        private set

    private val blacklistNotifDebounce = ConcurrentHashMap<String, Long>()

    fun setupNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            nm?.let {
                // VPN running notification channel (low importance = no sound)
                val chanVpn = NotificationChannel(
                    NOTIFY_CHAN_VPNSERVICE,
                    NOTIFY_CHAN_VPNSERVICE,
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    setShowBadge(false)
                }
                it.createNotificationChannel(chanVpn)

                // Blacklisted connection notification channel (high importance)
                val chanMalware = NotificationChannel(
                    NOTIFY_CHAN_MALWARE_DETECTION,
                    context.getString(R.string.malware_detection),
                    NotificationManager.IMPORTANCE_HIGH
                )
                it.createNotificationChannel(chanMalware)

                // Other notifications
                val chanOther = NotificationChannel(
                    NOTIFY_CHAN_OTHER,
                    context.getString(R.string.other_prefs),
                    NotificationManager.IMPORTANCE_DEFAULT
                )
                it.createNotificationChannel(chanOther)
            }
        }

        val pi = PendingIntent.getActivity(
            context, 0,
            Intent(context, MainActivity::class.java),
            Utils.getIntentFlags(PendingIntent.FLAG_UPDATE_CURRENT)
        )

        val dismissIntent = Intent(CaptureService.ACTION_DISMISS_NOTIFICATION).setPackage(context.packageName)
        val dismissPi = PendingIntent.getBroadcast(
            context, 100, dismissIntent,
            Utils.getIntentFlags(PendingIntent.FLAG_UPDATE_CURRENT)
        )

        val stopIntent = Intent(CaptureService.ACTION_STOP_SERVICE).setPackage(context.packageName)
        val stopPi = PendingIntent.getBroadcast(
            context, 101, stopIntent,
            Utils.getIntentFlags(PendingIntent.FLAG_UPDATE_CURRENT)
        )

        val appsIntent = Intent(context, AppsActivity::class.java)
        val appsPi = PendingIntent.getActivity(
            context, 102, appsIntent,
            Utils.getIntentFlags(PendingIntent.FLAG_UPDATE_CURRENT)
        )

        val statsIntent = Intent(context, StatsActivity::class.java)
        val statsPi = PendingIntent.getActivity(
            context, 103, statsIntent,
            Utils.getIntentFlags(PendingIntent.FLAG_UPDATE_CURRENT)
        )

        statusBuilder = NotificationCompat.Builder(context, NOTIFY_CHAN_VPNSERVICE)
            .setSmallIcon(R.drawable.ic_logo)
            .setColor(ContextCompat.getColor(context, R.color.colorPrimary))
            .setContentIntent(pi)
            .setDeleteIntent(dismissPi)
            .addAction(R.drawable.ic_apps, context.getString(R.string.apps), appsPi)
            .addAction(R.drawable.ic_stacked_bar_chart, context.getString(R.string.stats), statsPi)
            .addAction(R.drawable.ic_media_stop, context.getString(R.string.stop_button), stopPi)
            .setOngoing(false)
            .setAutoCancel(true)
            .setContentTitle(getVpnRunningTitle())
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setPriority(NotificationCompat.PRIORITY_LOW)

        if (notificationReceiver == null) {
            notificationReceiver = object : BroadcastReceiver() {
                override fun onReceive(ctx: Context?, intent: Intent?) {
                    val action = intent?.action ?: return
                    when (action) {
                        CaptureService.ACTION_DISMISS_NOTIFICATION -> {
                            Log.d(TAG, "Capture running notification dismissed by user")
                            isNotificationDismissed = true
                        }
                        CaptureService.ACTION_STOP_SERVICE -> {
                            Log.d(TAG, "Stop capture requested from notification")
                            onStopRequested.run()
                        }
                    }
                }
            }
            val filter = IntentFilter().apply {
                addAction(CaptureService.ACTION_DISMISS_NOTIFICATION)
                addAction(CaptureService.ACTION_STOP_SERVICE)
            }
            androidx.core.content.ContextCompat.registerReceiver(
                context,
                notificationReceiver,
                filter,
                androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED
            )
        }

        malwareBuilder = NotificationCompat.Builder(context, NOTIFY_CHAN_MALWARE_DETECTION)
            .setSmallIcon(R.drawable.ic_skull)
            .setAutoCancel(true)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
    }

    fun getStatusNotification(stats: CaptureStats?, lastBytes: Long, lastConns: Int): Notification {
        val builder = statusBuilder ?: return NotificationCompat.Builder(context, NOTIFY_CHAN_VPNSERVICE).build()

        val msg = if (stats != null && (stats.bytes_sent > 0 || stats.bytes_rcvd > 0)) {
            String.format(
                "⬇ %s  ⬆ %s  •  %s conns (%s pkts)",
                Utils.formatBytes(stats.bytes_rcvd),
                Utils.formatBytes(stats.bytes_sent),
                Utils.formatNumber(context, lastConns.toLong()),
                Utils.formatIntShort((stats.pkts_rcvd + stats.pkts_sent).toLong())
            )
        } else {
            String.format(
                context.getString(R.string.notification_msg),
                Utils.formatBytes(lastBytes),
                Utils.formatNumber(context, lastConns.toLong())
            )
        }

        builder.setContentText(msg)
        return builder.build()
    }

    fun updateNotification(isStopping: Boolean, stats: CaptureStats?, lastBytes: Long, lastConns: Int) {
        if (isStopping || isNotificationDismissed) return

        val notification = getStatusNotification(stats, lastBytes, lastConns)
        val manager = NotificationManagerCompat.from(context)
        if (manager.areNotificationsEnabled()) {
            manager.notify(NOTIFY_ID_VPNSERVICE, notification)
        }
    }

    fun showKillSwitchActiveNotification(isStopping: Boolean) {
        if (isStopping || isNotificationDismissed) return
        mainHandler.post {
            statusBuilder?.let { builder ->
                builder.setContentTitle("🛡️ P2P Leak Shield Active")
                builder.setContentText("Exit Node disconnected. Traffic paused to prevent leak.")
                val manager = NotificationManagerCompat.from(context)
                if (manager.areNotificationsEnabled()) {
                    manager.notify(NOTIFY_ID_VPNSERVICE, builder.build())
                }
            }
        }
    }

    fun restoreStatusNotification(isStopping: Boolean, stats: CaptureStats?, lastBytes: Long, lastConns: Int) {
        if (isStopping || isNotificationDismissed) return
        mainHandler.post {
            statusBuilder?.setContentTitle(getVpnRunningTitle())
            updateNotification(isStopping, stats, lastBytes, lastConns)
        }
    }

    fun notifyBlacklistedConnection(conn: ConnectionDescriptor) {
        val uid = conn.uid
        val resolver = AppsResolver(context)
        val app = resolver.getAppByUid(conn.uid, 0) ?: return

        val target = if (!conn.info.isNullOrEmpty()) conn.info else (conn.url ?: conn.dst_ip)
        val debounceKey = "${conn.uid}_${target ?: ""}"
        val now = System.currentTimeMillis()
        val lastTime = blacklistNotifDebounce[debounceKey]
        if (lastTime != null && (now - lastTime < BLACKLIST_NOTIF_COOLDOWN_MS)) {
            return
        }
        blacklistNotifDebounce[debounceKey] = now

        val filter = FilterDescriptor().apply {
            onlyBlacklisted = true
        }

        val connIntent = Intent(context, ConnectionsActivity::class.java)
            .putExtra(ConnectionsFragment.FILTER_EXTRA, filter)
            .putExtra(ConnectionsFragment.QUERY_EXTRA, app.packageName)
        val connPi = PendingIntent.getActivity(
            context, (now and 0xFFFF).toInt(),
            connIntent, Utils.getIntentFlags(PendingIntent.FLAG_UPDATE_CURRENT)
        )

        val rulesIntent = Intent(context, SecurityActionsActivity::class.java)
        val rulesPi = PendingIntent.getActivity(
            context, ((now + 1) and 0xFFFF).toInt(),
            rulesIntent, Utils.getIntentFlags(PendingIntent.FLAG_UPDATE_CURRENT)
        )

        val ruleLabel = if (conn.isBlacklistedHost) {
            MatchList.getRuleLabel(context, MatchList.RuleType.HOST, conn.info)
        } else {
            MatchList.getRuleLabel(context, MatchList.RuleType.IP, conn.dst_ip)
        }

        val content = String.format(
            context.resources.getString(R.string.malicious_connection_description),
            app.name,
            ruleLabel
        )

        malwareBuilder?.let { mb ->
            mb.setContentIntent(connPi)
                .setWhen(System.currentTimeMillis())
                .setContentTitle(context.resources.getString(R.string.malware_detection))
                .setStyle(NotificationCompat.BigTextStyle().bigText(content))
                .setContentText(content)
                .setOnlyAlertOnce(true)
                .setGroup("KotSafe_FIREWALL_BLOCKS")
                .clearActions()
                .addAction(R.drawable.ic_search, "View Connections", connPi)
                .addAction(R.drawable.ic_shield, "Manage Rules", rulesPi)

            val notification = mb.build()
            mainHandler.post {
                Utils.sendImportantNotification(context, uid, notification)
            }
        }
    }

    fun notifyLowMemory(msg: CharSequence) {
        val notification = NotificationCompat.Builder(context, NOTIFY_CHAN_OTHER)
            .setAutoCancel(true)
            .setSmallIcon(R.drawable.ic_logo)
            .setColor(ContextCompat.getColor(context, R.color.colorPrimary))
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setWhen(System.currentTimeMillis())
            .setContentTitle(context.getString(R.string.low_memory))
            .setContentText(msg)
            .build()

        mainHandler.post {
            Utils.sendImportantNotification(context, NOTIFY_ID_LOW_MEMORY, notification)
        }
    }

    fun getVpnRunningTitle(): String {
        val isP2PClient = prefs.getBoolean(
            com.kotsafe.security.p2p.GatewayPreferenceKeys.CLIENT_ENABLED,
            prefs.getBoolean(Prefs.PREF_P2P_EXIT_NODE_CLIENT_ENABLED, false)
        )
        if (isP2PClient) {
            val routingMode = prefs.getString(
                com.kotsafe.security.p2p.GatewayPreferenceKeys.APP_ROUTING_MODE,
                com.kotsafe.security.p2p.GatewayPreferenceKeys.ROUTING_MODE_ALL
            )
            return when (routingMode) {
                com.kotsafe.security.p2p.GatewayPreferenceKeys.ROUTING_MODE_ONLY_SELECTED -> "🛡️ Personal Gateway (Split Tunnel)"
                com.kotsafe.security.p2p.GatewayPreferenceKeys.ROUTING_MODE_BYPASS_SELECTED -> "🛡️ Personal Gateway (Bypass Mode)"
                else -> "🛡️ Personal Gateway (Full Tunnel)"
            }
        }
        return context.resources.getString(R.string.capture_running)
    }

    fun resetDismissed() {
        isNotificationDismissed = false
    }

    fun destroy() {
        notificationReceiver?.let {
            try {
                context.unregisterReceiver(it)
            } catch (ignored: IllegalArgumentException) {}
            notificationReceiver = null
        }
    }
}
