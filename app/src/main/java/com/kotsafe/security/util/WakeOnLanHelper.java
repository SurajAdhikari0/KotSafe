/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.util;

import android.os.Handler;
import android.os.Looper;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Locale;

/**
 * Wake-on-LAN (WoL) Magic Packet Generator & Broadcaster.
 * Enables waking sleeping home computers / servers remotely to activate SOCKS5 proxy services.
 */
public class WakeOnLanHelper {

    public interface WakeCallback {
        void onSuccess(String targetMac);
        void onError(String errorMessage);
    }

    public static byte[] parseMacAddress(String macStr) throws IllegalArgumentException {
        if (macStr == null) {
            throw new IllegalArgumentException("MAC address cannot be null");
        }
        String cleanMac = macStr.replaceAll("[:\\-\\s]", "").trim().toUpperCase(Locale.ROOT);
        if (cleanMac.length() != 12) {
            throw new IllegalArgumentException("Invalid MAC format. Expected 12 hexadecimal characters (e.g. AA:BB:CC:DD:EE:FF)");
        }

        byte[] macBytes = new byte[6];
        for (int i = 0; i < 6; i++) {
            String byteStr = cleanMac.substring(i * 2, (i * 2) + 2);
            try {
                macBytes[i] = (byte) Integer.parseInt(byteStr, 16);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid hex digit in MAC address: " + byteStr);
            }
        }
        return macBytes;
    }

    public static byte[] buildMagicPacket(byte[] macBytes) {
        byte[] bytes = new byte[102];
        // 6 bytes of 0xFF
        for (int i = 0; i < 6; i++) {
            bytes[i] = (byte) 0xFF;
        }
        // 16 iterations of target MAC
        for (int i = 6; i < 102; i += 6) {
            System.arraycopy(macBytes, 0, bytes, i, 6);
        }
        return bytes;
    }

    public static void sendWakeOnLanAsync(String macStr, String broadcastIp, int port, WakeCallback callback) {
        new Thread(() -> {
            Handler handler = new Handler(Looper.getMainLooper());
            try {
                byte[] macBytes = parseMacAddress(macStr);
                byte[] magicBytes = buildMagicPacket(macBytes);

                String targetIp = (broadcastIp != null && !broadcastIp.trim().isEmpty())
                        ? broadcastIp.trim() : "255.255.255.255";
                int targetPort = port > 0 ? port : 9;

                InetAddress address = InetAddress.getByName(targetIp);
                try (DatagramSocket socket = new DatagramSocket()) {
                    socket.setBroadcast(true);
                    DatagramPacket packet = new DatagramPacket(magicBytes, magicBytes.length, address, targetPort);
                    socket.send(packet);

                    // Also send to port 7 (Echo port standard for WoL) for broader compatibility
                    if (targetPort == 9) {
                        DatagramPacket packet7 = new DatagramPacket(magicBytes, magicBytes.length, address, 7);
                        socket.send(packet7);
                    }
                }

                if (callback != null) {
                    handler.post(() -> callback.onSuccess(macStr));
                }
            } catch (Exception e) {
                if (callback != null) {
                    handler.post(() -> callback.onError(e.getMessage() != null ? e.getMessage() : "Failed to dispatch WoL packet"));
                }
            }
        }).start();
    }
}
