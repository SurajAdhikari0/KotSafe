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
 *
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import com.kotsafe.security.Log;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class UpnpPortMapper {
    private static final String TAG = "UpnpPortMapper";
    private static final String SSDP_IP = "239.255.255.250";
    private static final int SSDP_PORT = 1900;
    private static final ExecutorService sExecutor = Executors.newSingleThreadExecutor();

    public interface Callback {
        void onResult(boolean success, String message);
    }

    public interface PublicIpCallback {
        void onPublicIp(String publicIp);
    }

    public static void mapPortAsync(int port, Callback callback) {
        sExecutor.execute(() -> {
            try {
                String localIp = getLocalWifiIpAddress();
                if (localIp == null) {
                    if (callback != null) callback.onResult(false, "No active Wi-Fi connection detected.");
                    return;
                }

                String controlUrl = discoverRouterControlUrl();
                if (controlUrl == null) {
                    if (callback != null) callback.onResult(false, "UPnP router not found or disabled on Wi-Fi network.");
                    return;
                }

                boolean ok = sendAddPortMappingSoap(controlUrl, port, localIp);
                if (callback != null) {
                    if (ok) {
                        callback.onResult(true, "Port " + port + " successfully mapped on router via UPnP.");
                    } else {
                        callback.onResult(false, "Router rejected UPnP port mapping request.");
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "UPnP error: " + e.getMessage());
                if (callback != null) callback.onResult(false, "UPnP Error: " + e.getMessage());
            }
        });
    }

    public static void fetchPublicIpv4Async(PublicIpCallback callback) {
        sExecutor.execute(() -> {
            String[] endpoints = {"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"};
            for (String endpoint : endpoints) {
                try {
                    URL url = new URL(endpoint);
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setConnectTimeout(3000);
                    conn.setReadTimeout(3000);
                    conn.setRequestProperty("User-Agent", "curl/7.88.1");
                    if (conn.getResponseCode() == 200) {
                        BufferedReader r = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                        String ip = r.readLine();
                        r.close();
                        if (ip != null) {
                            ip = ip.trim();
                            if (!ip.isEmpty() && callback != null) {
                                callback.onPublicIp(ip);
                                return;
                            }
                        }
                    }
                } catch (Exception ignored) {}
            }
            if (callback != null) callback.onPublicIp(null);
        });
    }

    public static String getGlobalIpv6Address() {
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                NetworkInterface intf = en.nextElement();
                if (intf.isLoopback() || !intf.isUp()) continue;

                for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements(); ) {
                    InetAddress addr = enumIpAddr.nextElement();
                    if (!addr.isLoopbackAddress() && addr.getAddress().length == 16) {
                        String host = addr.getHostAddress();
                        if (host != null) {
                            int pct = host.indexOf('%');
                            if (pct != -1) host = host.substring(0, pct);
                            // Exclude link-local (fe80::) and unique-local (fc00:: / fd00::)
                            if (!host.startsWith("fe80:") && !host.startsWith("fc") && !host.startsWith("fd")) {
                                return host;
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    public static String getLocalWifiIpAddress() {
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                NetworkInterface intf = en.nextElement();
                if (intf.isLoopback() || !intf.isUp()) continue;
                String name = intf.getName().toLowerCase();
                if (!name.contains("wlan") && !name.contains("eth") && !name.contains("wifi")) continue;

                for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements(); ) {
                    InetAddress inetAddress = enumIpAddr.nextElement();
                    if (!inetAddress.isLoopbackAddress() && inetAddress.getAddress().length == 4) {
                        return inetAddress.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    public static String getLocalCellularIpAddress() {
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                NetworkInterface intf = en.nextElement();
                if (intf.isLoopback() || !intf.isUp()) continue;
                String name = intf.getName().toLowerCase();
                if (!name.contains("rmnet") && !name.contains("ccmni") && !name.contains("pdp")) continue;

                for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements(); ) {
                    InetAddress inetAddress = enumIpAddr.nextElement();
                    if (!inetAddress.isLoopbackAddress() && inetAddress.getAddress().length == 4) {
                        return inetAddress.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    public static String getBestLocalIpAddress() {
        String wifi = getLocalWifiIpAddress();
        if (wifi != null && !wifi.isEmpty()) return wifi;

        // Check for Hotspot / USB Tethering / AP interfaces
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                NetworkInterface intf = en.nextElement();
                if (intf.isLoopback() || !intf.isUp()) continue;
                String name = intf.getName().toLowerCase();
                if (name.contains("ap") || name.contains("rndis") || name.contains("usb")) {
                    for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements(); ) {
                        InetAddress inetAddress = enumIpAddr.nextElement();
                        if (!inetAddress.isLoopbackAddress() && inetAddress.getAddress().length == 4) {
                            return inetAddress.getHostAddress();
                        }
                    }
                }
            }
        } catch (Exception ignored) {}

        String cellular = getLocalCellularIpAddress();
        if (cellular != null && !cellular.isEmpty()) return cellular;

        return "127.0.0.1";
    }

    public static java.util.List<String> getAllLocalCandidateIps() {
        java.util.List<String> ips = new java.util.ArrayList<>();
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                NetworkInterface intf = en.nextElement();
                if (intf.isLoopback() || !intf.isUp()) continue;
                for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements(); ) {
                    InetAddress inetAddress = enumIpAddr.nextElement();
                    if (!inetAddress.isLoopbackAddress() && inetAddress.getAddress().length == 4) {
                        String ip = inetAddress.getHostAddress();
                        if (!ips.contains(ip)) ips.add(ip);
                    }
                }
            }
        } catch (Exception ignored) {}
        return ips;
    }

    private static String discoverRouterControlUrl() {
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(3000);

            String query = "M-SEARCH * HTTP/1.1\r\n" +
                    "HOST: " + SSDP_IP + ":" + SSDP_PORT + "\r\n" +
                    "MAN: \"ssdp:discover\"\r\n" +
                    "MX: 2\r\n" +
                    "ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\r\n";

            byte[] data = query.getBytes(StandardCharsets.UTF_8);
            DatagramPacket packet = new DatagramPacket(data, data.length, InetAddress.getByName(SSDP_IP), SSDP_PORT);
            socket.send(packet);

            byte[] buffer = new byte[2048];
            DatagramPacket response = new DatagramPacket(buffer, buffer.length);
            socket.receive(response);

            String responseStr = new String(response.getData(), 0, response.getLength());
            String location = null;
            for (String line : responseStr.split("\r\n")) {
                if (line.toLowerCase().startsWith("location:")) {
                    location = line.substring(9).trim();
                    break;
                }
            }

            if (location != null) {
                return parseControlUrl(location);
            }
        } catch (Exception e) {
            Log.d(TAG, "SSDP discovery failed: " + e.getMessage());
        } finally {
            if (socket != null) socket.close();
        }
        return null;
    }

    private static String parseControlUrl(String locationUrl) {
        try {
            URL url = new URL(locationUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder xml = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                xml.append(line);
            }
            reader.close();

            String xmlStr = xml.toString();
            int serviceIdx = xmlStr.indexOf("WANIPConnection:1");
            if (serviceIdx == -1) serviceIdx = xmlStr.indexOf("WANPPPConnection:1");
            if (serviceIdx != -1) {
                int controlTagStart = xmlStr.indexOf("<controlURL>", serviceIdx);
                int controlTagEnd = xmlStr.indexOf("</controlURL>", controlTagStart);
                if (controlTagStart != -1 && controlTagEnd != -1) {
                    String relControlUrl = xmlStr.substring(controlTagStart + 12, controlTagEnd).trim();
                    if (relControlUrl.startsWith("http://") || relControlUrl.startsWith("https://")) {
                        return relControlUrl;
                    } else {
                        if (!relControlUrl.startsWith("/")) relControlUrl = "/" + relControlUrl;
                        return url.getProtocol() + "://" + url.getHost() + ":" + url.getPort() + relControlUrl;
                    }
                }
            }
        } catch (Exception e) {
            Log.d(TAG, "Failed to parse control URL: " + e.getMessage());
        }
        return null;
    }

    private static boolean sendAddPortMappingSoap(String controlUrl, int port, String localIp) {
        String[] services = {"WANIPConnection:1", "WANPPPConnection:1"};
        for (String svc : services) {
            try {
                URL url = new URL(controlUrl);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(4000);
                conn.setReadTimeout(4000);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "text/xml; charset=\"utf-8\"");
                conn.setRequestProperty("SOAPAction", "\"urn:schemas-upnp-org:service:" + svc + "#AddPortMapping\"");

                String soapBody = "<?xml version=\"1.0\"?>\r\n" +
                        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n" +
                        "<s:Body>\r\n" +
                        "<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:" + svc + "\">\r\n" +
                        "<NewRemoteHost></NewRemoteHost>\r\n" +
                        "<NewExternalPort>" + port + "</NewExternalPort>\r\n" +
                        "<NewProtocol>TCP</NewProtocol>\r\n" +
                        "<NewInternalPort>" + port + "</NewInternalPort>\r\n" +
                        "<NewInternalClient>" + localIp + "</NewInternalClient>\r\n" +
                        "<NewEnabled>1</NewEnabled>\r\n" +
                        "<NewPortMappingDescription>KotSafe SOCKS5</NewPortMappingDescription>\r\n" +
                        "<NewLeaseDuration>0</NewLeaseDuration>\r\n" +
                        "</u:AddPortMapping>\r\n" +
                        "</s:Body>\r\n" +
                        "</s:Envelope>";

                byte[] postData = soapBody.getBytes(StandardCharsets.UTF_8);
                conn.setRequestProperty("Content-Length", String.valueOf(postData.length));
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(postData);
                    os.flush();
                }

                int code = conn.getResponseCode();
                if (code == 200 || code == 201) return true;
            } catch (Exception e) {
                Log.d(TAG, "SOAP AddPortMapping error for " + svc + ": " + e.getMessage());
            }
        }
        return false;
    }
}
