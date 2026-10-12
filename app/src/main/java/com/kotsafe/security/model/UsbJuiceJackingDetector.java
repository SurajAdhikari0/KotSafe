/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * UsbJuiceJackingDetector
 * =======================
 * Defends against "Juice Jacking" attacks where public USB charging kiosks
 * negotiate hidden MTP / ADB / PTP data sessions while appearing to charge.
 *
 * HOW DETECTION WORKS
 * -------------------
 * Android broadcasts "android.hardware.usb.action.USB_STATE" on every USB
 * mode change. The intent extras include:
 *   connected  – VBUS 5 V power present (cable plugged in)
 *   configured – USB device enumerated by host (data channel open)
 *   adb        – Android Debug Bridge session active
 *   mtp        – Media Transfer Protocol filesystem exposed
 *   ptp        – Picture Transfer Protocol exposed
 *   rndis      – USB-tethering active
 *
 * A CRITICAL alert fires when: connected && (configured || adb || mtp || ptp || rndis)
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.Intent;

import com.kotsafe.security.Log;
import com.kotsafe.security.security.event.EventTypes;
import com.kotsafe.security.security.event.SecurityEvent;
import com.kotsafe.security.security.event.SecurityEventBus;

/**
 * Stateless utility called from {@link PhysicalSecurityReceiver#onReceive(Context, Intent)}.
 */
public final class UsbJuiceJackingDetector {

    public static final String ACTION_USB_STATE = "android.hardware.usb.action.USB_STATE";
    private static final String TAG = "UsbJuiceJackingDetector";

    /** Per-session trust flag — reset every time the cable is physically unplugged. */
    private static volatile boolean sSessionTrusted = false;

    private UsbJuiceJackingDetector() {}

    /** Called when the user explicitly trusts the currently connected USB host. */
    public static void trustCurrentSession() {
        sSessionTrusted = true;
        Log.i(TAG, "USB host marked as trusted for this session.");
    }

    /** Resets per-session trust (cable unplugged). */
    public static void resetSessionTrust() {
        sSessionTrusted = false;
    }

    /**
     * Inspects a USB_STATE broadcast and publishes a CRITICAL SecurityEvent if
     * an unauthorized data channel has been established.
     *
     * @return true if a juice-jacking alert was raised.
     */
    public static boolean inspect(Context context, Intent intent) {
        if (intent == null || !ACTION_USB_STATE.equals(intent.getAction())) return false;

        boolean connected  = intent.getBooleanExtra("connected",  false);
        boolean configured = intent.getBooleanExtra("configured", false);
        boolean adb        = intent.getBooleanExtra("adb",        false);
        boolean mtp        = intent.getBooleanExtra("mtp",        false);
        boolean ptp        = intent.getBooleanExtra("ptp",        false);
        boolean rndis      = intent.getBooleanExtra("rndis",      false);

        // Cable unplugged — reset session trust so next plug-in is checked fresh
        if (!connected) {
            resetSessionTrust();
            return false;
        }

        boolean dataChannelActive = configured || adb || mtp || ptp || rndis;
        if (!dataChannelActive) return false;   // pure power-only charging — safe

        if (sSessionTrusted) {
            Log.d(TAG, "USB data channel active but host is trusted this session.");
            return false;
        }

        // Build human-readable channel list
        StringBuilder channels = new StringBuilder();
        if (adb)   channels.append("ADB-Debugging ");
        if (mtp)   channels.append("MTP-FileTransfer ");
        if (ptp)   channels.append("PTP-PictureTransfer ");
        if (rndis) channels.append("USB-Tethering ");
        if (configured && channels.length() == 0) channels.append("USB-DataChannel ");
        String channelDesc = channels.toString().trim();

        Log.e(TAG, "JUICE JACKING DETECTED — active channels: " + channelDesc);

        SecurityEvent event = new SecurityEvent.Builder(
                    SecurityEvent.Domain.PHYSICAL, EventTypes.USB_JUICE_JACKING)
                .severity(SecurityEvent.Severity.CRITICAL)
                .title("\u26A1 Juice Jacking Alert: USB Data Active!")
                .description(
                    "A connected USB cable is negotiating a data transfer channel. "
                    + "If using a public charger, DISCONNECT IMMEDIATELY.\n"
                    + "Active channels: " + channelDesc)
                .attribute("channel", channelDesc)
                .attribute("adb",  adb)
                .attribute("mtp",  mtp)
                .attribute("ptp",  ptp)
                .attribute("rndis", rndis)
                .build();

        SecurityEventBus.getInstance().publish(event);
        return true;
    }
}
