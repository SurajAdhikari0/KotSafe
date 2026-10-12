/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.util;

import android.content.Context;
import android.net.wifi.WifiManager;
import android.os.Handler;
import android.os.Looper;
import android.text.format.Formatter;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;

/**
 * Automated Zero-Touch Router Port Mapping Helper using NAT-PMP (RFC 6886) and UPnP IGD.
 * Enables 1-tap port forwarding on consumer Wi-Fi routers without logging into router admin panels.
 */
public class UpnpPortMapper {

    public interface PortMapCallback {
        void onSuccess(String protocol, int externalPort, String message);
        void onFailure(String reason);
    }

    public static String getGatewayIp(Context context) {
        if (context == null) return null;
        try {
            WifiManager wm = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wm != null && wm.getDhcpInfo() != null) {
                int gw = wm.getDhcpInfo().gateway;
                if (gw != 0) {
                    return Formatter.formatIpAddress(gw);
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    public static String getLocalDeviceIp(Context context) {
        if (context == null) return null;
        try {
            WifiManager wm = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wm != null && wm.getConnectionInfo() != null) {
                int ip = wm.getConnectionInfo().getIpAddress();
                if (ip != 0) {
                    return Formatter.formatIpAddress(ip);
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    public static void requestAutoPortMapAsync(Context context, int targetPort, PortMapCallback callback) {
        new Thread(() -> {
            Handler handler = new Handler(Looper.getMainLooper());
            String gateway = getGatewayIp(context);
            String localIp = getLocalDeviceIp(context);

            if (gateway == null || gateway.isEmpty()) {
                if (callback != null) {
                    handler.post(() -> callback.onFailure("No active Wi-Fi router gateway detected. Make sure you are connected to home Wi-Fi."));
                }
                return;
            }

            // 1. Try NAT-PMP (RFC 6886) first (very fast, UDP 5351)
            try {
                int mappedPort = tryNatPmpMapping(gateway, targetPort, 86400);
                if (mappedPort > 0) {
                    if (callback != null) {
                        handler.post(() -> callback.onSuccess("NAT-PMP", mappedPort,
                                "Successfully opened external port " + mappedPort + " on router " + gateway + " via NAT-PMP!"));
                    }
                    return;
                }
            } catch (Exception ignored) {}

            // 2. Try UPnP SSDP & SOAP Port Mapping
            try {
                boolean upnpSuccess = tryUpnpMapping(gateway, localIp, targetPort);
                if (upnpSuccess) {
                    if (callback != null) {
                        handler.post(() -> callback.onSuccess("UPnP IGD", targetPort,
                                "Successfully opened external port " + targetPort + " on router " + gateway + " via UPnP!"));
                    }
                    return;
                }
            } catch (Exception ignored) {}

            if (callback != null) {
                handler.post(() -> callback.onFailure(
                        "Router at " + gateway + " did not respond to automated UPnP or NAT-PMP.\n"
                        + "UPnP may be disabled in router security settings, or the router blocks automatic port mapping. "
                        + "You can enable UPnP in your router dashboard or use Option 1 (KotSafe P2P Mesh)."));
            }
        }).start();
    }

    /**
     * Attempts NAT-PMP (RFC 6886) Port Mapping request to gateway on UDP port 5351.
     */
    private static int tryNatPmpMapping(String gatewayIp, int port, int lifetimeSeconds) throws Exception {
        byte[] request = new byte[12];
        request[0] = 0; // Version 0
        request[1] = 2; // OP: TCP Map
        request[2] = 0; // Reserved
        request[3] = 0;
        // Internal port (bytes 4-5)
        request[4] = (byte) ((port >> 8) & 0xFF);
        request[5] = (byte) (port & 0xFF);
        // External port suggested (bytes 6-7)
        request[6] = (byte) ((port >> 8) & 0xFF);
        request[7] = (byte) (port & 0xFF);
        // Lifetime (bytes 8-11)
        request[8] = (byte) ((lifetimeSeconds >> 24) & 0xFF);
        request[9] = (byte) ((lifetimeSeconds >> 16) & 0xFF);
        request[10] = (byte) ((lifetimeSeconds >> 8) & 0xFF);
        request[11] = (byte) (lifetimeSeconds & 0xFF);

        InetAddress gwAddr = InetAddress.getByName(gatewayIp);
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(1800);
            DatagramPacket sendPkt = new DatagramPacket(request, request.length, gwAddr, 5351);
            socket.send(sendPkt);

            byte[] buffer = new byte[16];
            DatagramPacket recvPkt = new DatagramPacket(buffer, buffer.length);
            socket.receive(recvPkt);

            if (buffer.length >= 12 && buffer[0] == 0 && (buffer[1] & 0xFF) == 130) {
                int resultCode = ((buffer[2] & 0xFF) << 8) | (buffer[3] & 0xFF);
                if (resultCode == 0) {
                    int assignedPort = ((buffer[10] & 0xFF) << 8) | (buffer[11] & 0xFF);
                    return assignedPort > 0 ? assignedPort : port;
                }
            }
        }
        return -1;
    }

    /**
     * Attempts UPnP SSDP Discovery and AddPortMapping SOAP call.
     */
    private static boolean tryUpnpMapping(String gatewayIp, String localIp, int port) {
        if (localIp == null || localIp.isEmpty()) return false;

        String[] candidatePorts = {"5000", "5555", "1900", "49152", "49153"};
        String soapBody = "<?xml version=\"1.0\"?>\n"
                + "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n"
                + "<s:Body>\n"
                + "<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\n"
                + "<NewRemoteHost></NewRemoteHost>\n"
                + "<NewExternalPort>" + port + "</NewExternalPort>\n"
                + "<NewProtocol>TCP</NewProtocol>\n"
                + "<NewInternalPort>" + port + "</NewInternalPort>\n"
                + "<NewInternalClient>" + localIp + "</NewInternalClient>\n"
                + "<NewEnabled>1</NewEnabled>\n"
                + "<NewPortMappingDescription>KotSafe SOCKS5</NewPortMappingDescription>\n"
                + "<NewLeaseDuration>0</NewLeaseDuration>\n"
                + "</u:AddPortMapping>\n"
                + "</s:Body>\n"
                + "</s:Envelope>";

        for (String p : candidatePorts) {
            try {
                URL url = new URL("http://" + gatewayIp + ":" + p + "/ctl/IPConn");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(800);
                conn.setReadTimeout(1200);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "text/xml; charset=\"utf-8\"");
                conn.setRequestProperty("SOAPAction", "\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"");

                byte[] postData = soapBody.getBytes("UTF-8");
                conn.setRequestProperty("Content-Length", String.valueOf(postData.length));
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(postData);
                }

                int code = conn.getResponseCode();
                if (code == 200 || code == 201) {
                    return true;
                }
            } catch (Exception ignored) {}
        }
        return false;
    }
}
