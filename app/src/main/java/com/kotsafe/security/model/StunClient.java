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

import java.io.DataInputStream;
import java.io.ByteArrayInputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Lightweight RFC 5389 STUN Client for NAT Hole Punching and Public IP/Port reflection.
 * Allows P2P connections to traverse home routers without manual port forwarding.
 */
public class StunClient {
    private static final String TAG = "StunClient";
    private static final int STUN_MAGIC_COOKIE = 0x2112A442;
    private static final int STUN_BINDING_REQUEST = 0x0001;
    private static final int STUN_BINDING_RESPONSE = 0x0101;

    // Public reliable STUN servers for NAT hole punching
    private static final String[] STUN_SERVERS = {
            "stun.cloudflare.com:3478",
            "stun.l.google.com:19302",
            "stun1.l.google.com:19302",
            "stun2.l.google.com:19302"
    };

    private static final ExecutorService sExecutor = Executors.newSingleThreadExecutor();

    public static class StunResult {
        public final boolean success;
        public final String publicIp;
        public final int publicPort;
        public final String message;

        public StunResult(boolean success, String publicIp, int publicPort, String message) {
            this.success = success;
            this.publicIp = publicIp;
            this.publicPort = publicPort;
            this.message = message;
        }
    }

    public interface StunCallback {
        void onResult(StunResult result);
    }

    public static void discoverPublicEndpointAsync(int localPort, StunCallback callback) {
        sExecutor.execute(() -> {
            for (String server : STUN_SERVERS) {
                StunResult result = queryStunServer(server, localPort);
                if (result != null && result.success) {
                    if (callback != null) callback.onResult(result);
                    return;
                }
            }
            if (callback != null) {
                callback.onResult(new StunResult(false, null, 0, "STUN NAT traversal failed on all candidate servers."));
            }
        });
    }

    public static void discoverPublicEndpointWithSocketAsync(DatagramSocket socket, StunCallback callback) {
        sExecutor.execute(() -> {
            for (String server : STUN_SERVERS) {
                StunResult result = queryStunWithSocket(socket, server);
                if (result != null && result.success) {
                    if (callback != null) callback.onResult(result);
                    return;
                }
            }
            if (callback != null) {
                callback.onResult(new StunResult(false, null, 0, "STUN NAT traversal failed on all candidate servers."));
            }
        });
    }

    private static StunResult queryStunServer(String serverHostPort, int localPort) {
        DatagramSocket socket = null;
        try {
            try {
                socket = new DatagramSocket(localPort);
            } catch (Exception e) {
                socket = new DatagramSocket();
            }
            try {
                com.kotsafe.security.CaptureService vpn = com.kotsafe.security.CaptureService.getInstance();
                if (vpn != null) vpn.protect(socket);
            } catch (Exception ignored) {}
            return queryStunWithSocket(socket, serverHostPort);
        } catch (Exception e) {
            Log.d(TAG, "STUN socket creation failed: " + e.getMessage());
            return null;
        } finally {
            if (socket != null && !socket.isClosed()) socket.close();
        }
    }

    public static StunResult queryStunWithSocket(DatagramSocket socket, String serverHostPort) {
        try {
            try {
                com.kotsafe.security.CaptureService vpn = com.kotsafe.security.CaptureService.getInstance();
                if (vpn != null) vpn.protect(socket);
            } catch (Exception ignored) {}
            String[] parts = serverHostPort.split(":");
            String host = parts[0];
            int port = Integer.parseInt(parts[1]);
            socket.setSoTimeout(3000);

            byte[] transactionId = new byte[12];
            new SecureRandom().nextBytes(transactionId);

            // Build RFC 5389 STUN Binding Request header (20 bytes)
            byte[] request = new byte[20];
            // Message Type: Binding Request (0x0001)
            request[0] = 0x00;
            request[1] = 0x01;
            // Message Length: 0x0000 (No attributes in request)
            request[2] = 0x00;
            request[3] = 0x00;
            // Magic Cookie: 0x2112A442
            request[4] = 0x21;
            request[5] = 0x12;
            request[6] = (byte) 0xA4;
            request[7] = 0x42;
            // Transaction ID (96 bits)
            System.arraycopy(transactionId, 0, request, 8, 12);

            InetAddress serverAddr = InetAddress.getByName(host);
            DatagramPacket sendPacket = new DatagramPacket(request, request.length, serverAddr, port);
            socket.send(sendPacket);

            byte[] buffer = new byte[1024];
            DatagramPacket receivePacket = new DatagramPacket(buffer, buffer.length);
            socket.receive(receivePacket);

            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(receivePacket.getData(), 0, receivePacket.getLength()));
            int msgType = dis.readUnsignedShort();
            int msgLength = dis.readUnsignedShort();
            int magicCookie = dis.readInt();

            byte[] respTransId = new byte[12];
            dis.readFully(respTransId);

            if (msgType != STUN_BINDING_RESPONSE || magicCookie != STUN_MAGIC_COOKIE) {
                return null;
            }

            // Parse attributes
            int bytesLeft = msgLength;
            while (bytesLeft >= 4) {
                int attrType = dis.readUnsignedShort();
                int attrLength = dis.readUnsignedShort();
                bytesLeft -= 4;

                if (attrLength > bytesLeft) break;

                byte[] attrValue = new byte[attrLength];
                dis.readFully(attrValue);
                bytesLeft -= attrLength;

                // Handle padding to 4-byte boundary
                int pad = (4 - (attrLength % 4)) % 4;
                if (pad > 0 && bytesLeft >= pad) {
                    dis.skipBytes(pad);
                    bytesLeft -= pad;
                }

                // XOR-MAPPED-ADDRESS (0x0020)
                if (attrType == 0x0020 && attrLength >= 8) {
                    DataInputStream attrDis = new DataInputStream(new ByteArrayInputStream(attrValue));
                    attrDis.readByte(); // reserved
                    int family = attrDis.readByte();
                    int xorPort = attrDis.readUnsignedShort();
                    int mappedPort = xorPort ^ (STUN_MAGIC_COOKIE >> 16);

                    if (family == 0x01) { // IPv4
                        byte[] xorIp = new byte[4];
                        attrDis.readFully(xorIp);
                        byte[] cookieBytes = {0x21, 0x12, (byte) 0xA4, 0x42};
                        byte[] mappedIp = new byte[4];
                        for (int i = 0; i < 4; i++) {
                            mappedIp[i] = (byte) (xorIp[i] ^ cookieBytes[i]);
                        }
                        String ipStr = InetAddress.getByAddress(mappedIp).getHostAddress();
                        return new StunResult(true, ipStr, mappedPort, "STUN hole punched via " + host);
                    }
                }
                // MAPPED-ADDRESS (0x0001) fallback
                else if (attrType == 0x0001 && attrLength >= 8) {
                    DataInputStream attrDis = new DataInputStream(new ByteArrayInputStream(attrValue));
                    attrDis.readByte(); // reserved
                    int family = attrDis.readByte();
                    int mappedPort = attrDis.readUnsignedShort();
                    if (family == 0x01) {
                        byte[] ipBytes = new byte[4];
                        attrDis.readFully(ipBytes);
                        String ipStr = InetAddress.getByAddress(ipBytes).getHostAddress();
                        return new StunResult(true, ipStr, mappedPort, "STUN mapping resolved via " + host);
                    }
                }
            }
        } catch (Exception e) {
            Log.d(TAG, "STUN query error: " + e.getMessage());
        }
        return null;
    }
}
