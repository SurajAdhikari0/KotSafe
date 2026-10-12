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
 */

package com.kotsafe.security.decoders;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * High-performance wire decoder for HTTPS traffic:
 * 1. HTTP/1.1 over TLS (Requests & Responses, Headers, Methods, Query params, Bodies)
 * 2. HTTP/2 over TLS (Client Preface, HEADERS, DATA, SETTINGS, PING, RST_STREAM, GOAWAY frames)
 * 3. TLS Handshake Records (ClientHello SNI, ALPN protocols, Cipher Suites, Supported Versions)
 */
public class HttpsDecoder {
    private static final String HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    public enum ProtocolType {
        HTTP_1_1_REQUEST,
        HTTP_1_1_RESPONSE,
        HTTP_2,
        TLS_HANDSHAKE,
        TLS_APPLICATION_DATA,
        UNKNOWN
    }

    public static class DecodedHttps {
        public final ProtocolType type;
        public final String method;
        public final String pathOrUrl;
        public final int statusCode;
        public final String statusMessage;
        public final String sniHost;
        public final String alpn;
        public final String tlsVersion;
        public final Map<String, String> headers;
        public final String body;
        public final String summary;
        public final String json;
        public final String ja3Raw;
        public final String ja3Hash;
        public final Ja3Fingerprinter.Ja3Result ja3Result;
        public final com.kotsafe.security.ips.IpsEngine.IpsMatch ipsMatch;

        public DecodedHttps(ProtocolType type, String method, String pathOrUrl, int statusCode,
                            String statusMessage, String sniHost, String alpn, String tlsVersion,
                            Map<String, String> headers, String body, String summary, String json) {
            this(type, method, pathOrUrl, statusCode, statusMessage, sniHost, alpn, tlsVersion, headers, body, summary, json, null, null);
        }

        public DecodedHttps(ProtocolType type, String method, String pathOrUrl, int statusCode,
                            String statusMessage, String sniHost, String alpn, String tlsVersion,
                            Map<String, String> headers, String body, String summary, String json,
                            Ja3Fingerprinter.Ja3Result ja3Result) {
            this(type, method, pathOrUrl, statusCode, statusMessage, sniHost, alpn, tlsVersion, headers, body, summary, json, ja3Result, null);
        }

        public DecodedHttps(ProtocolType type, String method, String pathOrUrl, int statusCode,
                            String statusMessage, String sniHost, String alpn, String tlsVersion,
                            Map<String, String> headers, String body, String summary, String json,
                            Ja3Fingerprinter.Ja3Result ja3Result,
                            com.kotsafe.security.ips.IpsEngine.IpsMatch ipsMatch) {
            this.type = type;
            this.method = method;
            this.pathOrUrl = pathOrUrl;
            this.statusCode = statusCode;
            this.statusMessage = statusMessage;
            this.sniHost = sniHost;
            this.alpn = alpn;
            this.tlsVersion = tlsVersion;
            this.headers = headers != null ? headers : new LinkedHashMap<>();
            this.body = body != null ? body : "";
            this.summary = summary != null ? summary : "";
            this.json = json != null ? json : "{}";
            this.ja3Result = ja3Result;
            this.ja3Raw = ja3Result != null ? ja3Result.raw : "";
            this.ja3Hash = ja3Result != null ? ja3Result.hash : "";
            this.ipsMatch = ipsMatch != null ? ipsMatch : com.kotsafe.security.ips.IpsEngine.IpsMatch.clean();
        }
    }

    /**
     * Determines if the given byte buffer represents HTTPS/HTTP traffic (decrypted or handshake)
     */
    public static boolean isHttpsOrHttp(byte[] payload) {
        if (payload == null || payload.length < 4) return false;

        // Check TLS record header: ContentType 20..23, Version 0x03 0x01..0x04
        if ((payload[0] >= 20 && payload[0] <= 23) && payload[1] == 0x03 && (payload[2] >= 0x01 && payload[2] <= 0x04)) {
            return true;
        }

        // Check HTTP/1.1 methods
        String s = new String(payload, 0, Math.min(payload.length, 16), StandardCharsets.US_ASCII);
        if (s.startsWith("GET ") || s.startsWith("POST ") || s.startsWith("PUT ") ||
                s.startsWith("DELETE ") || s.startsWith("HEAD ") || s.startsWith("OPTIONS ") ||
                s.startsWith("PATCH ") || s.startsWith("CONNECT ") || s.startsWith("HTTP/")) {
            return true;
        }

        // Check HTTP/2 preface
        return s.startsWith("PRI ");
    }

    /**
     * Inspects and decodes the HTTPS payload. Returns null if not recognizable as HTTPS or HTTP.
     */
    @Nullable
    public static DecodedHttps decode(@NonNull byte[] data) {
        if (!isHttpsOrHttp(data)) return null;

        try {
            // 1. Try TLS Handshake (ClientHello / ServerHello)
            if (data[0] == 0x16 && data[1] == 0x03) { // 0x16 = Handshake, 0x03 = SSLv3 / TLS
                return decodeTlsHandshake(data);
            }

            // 2. Try HTTP/2
            String prefix = new String(data, 0, Math.min(data.length, 24), StandardCharsets.US_ASCII);
            if (prefix.startsWith("PRI * HTTP/2.0") || isHttp2Frame(data)) {
                return decodeHttp2(data);
            }

            // 3. Try HTTP/1.1 Request
            if (prefix.startsWith("GET ") || prefix.startsWith("POST ") || prefix.startsWith("PUT ") ||
                    prefix.startsWith("DELETE ") || prefix.startsWith("HEAD ") || prefix.startsWith("OPTIONS ") ||
                    prefix.startsWith("PATCH ") || prefix.startsWith("CONNECT ")) {
                return decodeHttp1Request(data);
            }

            // 4. Try HTTP/1.1 Response
            if (prefix.startsWith("HTTP/")) {
                return decodeHttp1Response(data);
            }

            // 5. TLS Application Data
            if (data[0] == 0x17 && data[1] == 0x03) {
                return decodeTlsAppData(data);
            }

        } catch (Exception ignored) {
        }

        return null;
    }

    private static DecodedHttps decodeHttp1Request(byte[] data) throws Exception {
        String text = new String(data, StandardCharsets.UTF_8);
        int headerEnd = text.indexOf("\r\n\r\n");
        String headerPart = (headerEnd != -1) ? text.substring(0, headerEnd) : text;
        String bodyPart = (headerEnd != -1 && headerEnd + 4 < text.length()) ? text.substring(headerEnd + 4) : "";

        String[] lines = headerPart.split("\r\n");
        if (lines.length == 0) return null;

        String requestLine = lines[0];
        String[] parts = requestLine.split(" ");
        String method = parts.length > 0 ? parts[0] : "GET";
        String path = parts.length > 1 ? parts[1] : "/";
        String version = parts.length > 2 ? parts[2] : "HTTP/1.1";

        Map<String, String> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                String k = lines[i].substring(0, colon).trim();
                String v = lines[i].substring(colon + 1).trim();
                headers.put(k, v);
            }
        }

        String host = headers.getOrDefault("Host", headers.getOrDefault("host", ""));
        String fullUrl = (!host.isEmpty()) ? "https://" + host + path : path;

        JsonObject json = new JsonObject();
        json.addProperty("protocol", version);
        json.addProperty("type", "REQUEST");
        json.addProperty("method", method);
        json.addProperty("url", fullUrl);
        json.addProperty("path", path);

        JsonObject headersObj = new JsonObject();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            headersObj.addProperty(entry.getKey(), entry.getValue());
        }
        json.add("headers", headersObj);

        if (!bodyPart.isEmpty()) {
            json.addProperty("body_preview", bodyPart.length() > 500 ? bodyPart.substring(0, 500) + "..." : bodyPart);
            json.addProperty("body_length", bodyPart.length());
        }

        byte[] bodyBytes = (!bodyPart.isEmpty()) ? bodyPart.getBytes(StandardCharsets.UTF_8) : null;
        com.kotsafe.security.ips.IpsEngine.IpsMatch ipsMatch =
                com.kotsafe.security.ips.IpsEngine.inspect(method, fullUrl, headers, bodyBytes);

        if (ipsMatch.hasThreat) {
            json.addProperty("ips_threat_detected", true);
            json.addProperty("ips_rule_id", ipsMatch.ruleId);
            json.addProperty("ips_rule_name", ipsMatch.ruleName);
            json.addProperty("ips_category", ipsMatch.category);
            json.addProperty("ips_severity", ipsMatch.severity);
            json.addProperty("ips_snippet", ipsMatch.matchedSnippet);
            json.addProperty("ips_mitigation", ipsMatch.mitigation);
        }

        String ipsSuffix = ipsMatch.hasThreat ? " [IPS: " + ipsMatch.ruleName + "]" : "";
        String summary = method + " " + fullUrl + " (" + headers.size() + " headers)" + ipsSuffix;
        return new DecodedHttps(ProtocolType.HTTP_1_1_REQUEST, method, fullUrl, 0, "", host, "http/1.1",
                "TLS (Decrypted)", headers, bodyPart, summary, GSON.toJson(json), null, ipsMatch);
    }

    private static DecodedHttps decodeHttp1Response(byte[] data) throws Exception {
        String text = new String(data, StandardCharsets.UTF_8);
        int headerEnd = text.indexOf("\r\n\r\n");
        String headerPart = (headerEnd != -1) ? text.substring(0, headerEnd) : text;
        String bodyPart = (headerEnd != -1 && headerEnd + 4 < text.length()) ? text.substring(headerEnd + 4) : "";

        String[] lines = headerPart.split("\r\n");
        if (lines.length == 0) return null;

        String statusLine = lines[0];
        String[] parts = statusLine.split(" ", 3);
        String version = parts.length > 0 ? parts[0] : "HTTP/1.1";
        int statusCode = 200;
        String statusMsg = "OK";
        if (parts.length > 1) {
            try { statusCode = Integer.parseInt(parts[1]); } catch (Exception ignored) {}
        }
        if (parts.length > 2) {
            statusMsg = parts[2];
        }

        Map<String, String> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                String k = lines[i].substring(0, colon).trim();
                String v = lines[i].substring(colon + 1).trim();
                headers.put(k, v);
            }
        }

        JsonObject json = new JsonObject();
        json.addProperty("protocol", version);
        json.addProperty("type", "RESPONSE");
        json.addProperty("status_code", statusCode);
        json.addProperty("status_message", statusMsg);

        JsonObject headersObj = new JsonObject();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            headersObj.addProperty(entry.getKey(), entry.getValue());
        }
        json.add("headers", headersObj);

        if (!bodyPart.isEmpty()) {
            json.addProperty("body_preview", bodyPart.length() > 500 ? bodyPart.substring(0, 500) + "..." : bodyPart);
            json.addProperty("body_length", bodyPart.length());
        }

        String summary = "HTTP " + statusCode + " " + statusMsg + " (" + headers.getOrDefault("Content-Type", "text/plain") + ")";
        return new DecodedHttps(ProtocolType.HTTP_1_1_RESPONSE, "", "", statusCode, statusMsg, "", "http/1.1",
                "TLS (Decrypted)", headers, bodyPart, summary, GSON.toJson(json));
    }

    private static boolean isHttp2Frame(byte[] data) {
        if (data.length < 9) return false;
        int frameType = data[3] & 0xFF;
        return (frameType <= 9); // Frame types 0x0 to 0x9
    }

    private static DecodedHttps decodeHttp2(byte[] data) throws Exception {
        int offset = 0;
        if (data.length >= 24 && new String(data, 0, 24, StandardCharsets.US_ASCII).startsWith("PRI * HTTP/2.0")) {
            offset = 24;
        }

        List<String> frames = new ArrayList<>();
        JsonArray framesArr = new JsonArray();

        while (offset + 9 <= data.length) {
            int length = ((data[offset] & 0xFF) << 16) | ((data[offset + 1] & 0xFF) << 8) | (data[offset + 2] & 0xFF);
            int type = data[offset + 3] & 0xFF;
            int flags = data[offset + 4] & 0xFF;
            int streamId = ((data[offset + 5] & 0x7F) << 24) | ((data[offset + 6] & 0xFF) << 16) |
                    ((data[offset + 7] & 0xFF) << 8) | (data[offset + 8] & 0xFF);

            String typeName = getHttp2FrameTypeName(type);
            JsonObject frameObj = new JsonObject();
            frameObj.addProperty("type", typeName);
            frameObj.addProperty("type_id", type);
            frameObj.addProperty("stream_id", streamId);
            frameObj.addProperty("length", length);
            frameObj.addProperty("flags", String.format("0x%02x", flags));
            framesArr.add(frameObj);

            frames.add(typeName + " [Stream " + streamId + ", " + length + "B]");
            offset += 9 + length;
            if (frames.size() >= 20) break; // cap inspection
        }

        JsonObject json = new JsonObject();
        json.addProperty("protocol", "HTTP/2 (h2)");
        json.addProperty("frames_count", framesArr.size());
        json.add("frames", framesArr);

        String summary = "HTTP/2 stream (" + framesArr.size() + " frames: " + String.join(", ", frames) + ")";
        return new DecodedHttps(ProtocolType.HTTP_2, "HTTP/2", "h2", 0, "", "", "h2",
                "TLSv1.3", null, "", summary, GSON.toJson(json));
    }

    private static String getHttp2FrameTypeName(int type) {
        switch (type) {
            case 0: return "DATA";
            case 1: return "HEADERS";
            case 2: return "PRIORITY";
            case 3: return "RST_STREAM";
            case 4: return "SETTINGS";
            case 5: return "PUSH_PROMISE";
            case 6: return "PING";
            case 7: return "GOAWAY";
            case 8: return "WINDOW_UPDATE";
            case 9: return "CONTINUATION";
            default: return "UNKNOWN_" + type;
        }
    }

    private static DecodedHttps decodeTlsHandshake(byte[] data) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(data);
        buf.get(); // ContentType (0x16)
        int majorVer = buf.get() & 0xFF;
        int minorVer = buf.get() & 0xFF;
        int recordLen = buf.getShort() & 0xFFFF;

        String tlsVer = parseTlsVersion(majorVer, minorVer);
        int handshakeType = buf.get() & 0xFF;

        String hsName = "Unknown Handshake";
        String sni = "";
        String alpn = "";
        List<String> cipherSuites = new ArrayList<>();
        List<Integer> cipherIds = new ArrayList<>();
        List<Integer> extensionIds = new ArrayList<>();
        List<Integer> supportedGroups = new ArrayList<>();
        List<Integer> ecPointFormats = new ArrayList<>();
        Ja3Fingerprinter.Ja3Result ja3 = null;

        if (handshakeType == 0x01) { // ClientHello
            hsName = "ClientHello";
            int hsLen = ((buf.get() & 0xFF) << 16) | (buf.getShort() & 0xFFFF);
            int chVerMajor = buf.get() & 0xFF;
            int chVerMinor = buf.get() & 0xFF;
            tlsVer = parseTlsVersion(chVerMajor, chVerMinor);
            int rawClientHelloVer = (chVerMajor << 8) | chVerMinor;

            // Skip Random (32 bytes)
            if (buf.remaining() >= 32) {
                buf.position(buf.position() + 32);
            }

            // Session ID
            if (buf.hasRemaining()) {
                int sessIdLen = buf.get() & 0xFF;
                if (buf.remaining() >= sessIdLen) {
                    buf.position(buf.position() + sessIdLen);
                }
            }

            // Cipher Suites
            if (buf.remaining() >= 2) {
                int cipherLen = buf.getShort() & 0xFFFF;
                int count = Math.min(cipherLen / 2, 64);
                for (int i = 0; i < count && buf.remaining() >= 2; i++) {
                    int c = buf.getShort() & 0xFFFF;
                    cipherIds.add(c);
                    cipherSuites.add(String.format("0x%04X", c));
                }
            }

            // Compression Methods
            if (buf.hasRemaining()) {
                int compLen = buf.get() & 0xFF;
                if (buf.remaining() >= compLen) {
                    buf.position(buf.position() + compLen);
                }
            }

            // Extensions
            if (buf.remaining() >= 2) {
                int extLen = buf.getShort() & 0xFFFF;
                int extEnd = Math.min(buf.position() + extLen, buf.limit());

                while (buf.position() + 4 <= extEnd) {
                    int extType = buf.getShort() & 0xFFFF;
                    int extDataLen = buf.getShort() & 0xFFFF;
                    int nextPos = buf.position() + extDataLen;
                    extensionIds.add(extType);

                    if (extType == 0x0000 && buf.remaining() >= 2) { // Server Name Indication (SNI)
                        int listLen = buf.getShort() & 0xFFFF;
                        if (buf.hasRemaining() && (buf.get() & 0xFF) == 0) { // Host Name type
                            int nameLen = buf.getShort() & 0xFFFF;
                            if (buf.remaining() >= nameLen) {
                                byte[] nameBytes = new byte[nameLen];
                                buf.get(nameBytes);
                                sni = new String(nameBytes, StandardCharsets.US_ASCII);
                            }
                        }
                    } else if (extType == 0x000a && buf.remaining() >= 2) { // Supported Groups / Elliptic Curves
                        int groupsListLen = buf.getShort() & 0xFFFF;
                        int groupsEnd = Math.min(buf.position() + groupsListLen, nextPos);
                        while (buf.position() + 2 <= groupsEnd) {
                            supportedGroups.add(buf.getShort() & 0xFFFF);
                        }
                    } else if (extType == 0x000b && buf.remaining() >= 1) { // EC Point Formats
                        int ecpfLen = buf.get() & 0xFF;
                        int ecpfEnd = Math.min(buf.position() + ecpfLen, nextPos);
                        while (buf.position() < ecpfEnd && buf.hasRemaining()) {
                            ecPointFormats.add(buf.get() & 0xFF);
                        }
                    } else if (extType == 0x0010 && buf.remaining() >= 2) { // ALPN
                        int alpnListLen = buf.getShort() & 0xFFFF;
                        List<String> protos = new ArrayList<>();
                        int alpnEnd = Math.min(buf.position() + alpnListLen, nextPos);
                        while (buf.position() < alpnEnd) {
                            int pLen = buf.get() & 0xFF;
                            if (buf.remaining() >= pLen) {
                                byte[] pb = new byte[pLen];
                                buf.get(pb);
                                protos.add(new String(pb, StandardCharsets.US_ASCII));
                            } else break;
                        }
                        alpn = String.join(", ", protos);
                    } else if (extType == 0x002b && buf.remaining() >= 1) { // Supported Versions (TLS 1.3)
                        int svLen = buf.get() & 0xFF;
                        for (int s = 0; s < svLen / 2 && buf.remaining() >= 2; s++) {
                            int v = buf.getShort() & 0xFFFF;
                            if (v == 0x0304) tlsVer = "TLSv1.3";
                        }
                    }

                    if (nextPos <= extEnd && nextPos >= buf.position()) {
                        buf.position(nextPos);
                    } else {
                        break;
                    }
                }
            }

            // Compute JA3 fingerprint
            ja3 = Ja3Fingerprinter.compute(rawClientHelloVer, cipherIds, extensionIds, supportedGroups, ecPointFormats);
        } else if (handshakeType == 0x02) {
            hsName = "ServerHello";
        } else if (handshakeType == 0x0b) {
            hsName = "Certificate";
        }

        JsonObject json = new JsonObject();
        json.addProperty("protocol", "TLS Handshake");
        json.addProperty("record_version", tlsVer);
        json.addProperty("handshake_type", hsName);
        if (!sni.isEmpty()) json.addProperty("sni_target", sni);
        if (!alpn.isEmpty()) json.addProperty("alpn_protocols", alpn);
        if (!cipherSuites.isEmpty()) json.addProperty("cipher_suites_count", cipherSuites.size());
        if (ja3 != null && !ja3.hash.isEmpty()) {
            json.addProperty("ja3_hash", ja3.hash);
            json.addProperty("ja3_raw", ja3.raw);
            if (ja3.isSuspicious) {
                json.addProperty("threat_detected", ja3.threatName);
                json.addProperty("threat_category", ja3.threatCategory);
            }
        }

        String threatSuffix = (ja3 != null && ja3.isSuspicious) ? " [THREAT: " + ja3.threatName + "]" : "";
        String summary = hsName + " (" + tlsVer + (!sni.isEmpty() ? " SNI: " + sni : "") + (!alpn.isEmpty() ? " ALPN: " + alpn : "") + ")" + threatSuffix;
        return new DecodedHttps(ProtocolType.TLS_HANDSHAKE, hsName, sni.isEmpty() ? "" : "https://" + sni,
                0, "", sni, alpn, tlsVer, null, "", summary, GSON.toJson(json), ja3);
    }

    private static DecodedHttps decodeTlsAppData(byte[] data) throws Exception {
        int len = data.length;
        String tlsVer = parseTlsVersion(data[1] & 0xFF, data[2] & 0xFF);

        JsonObject json = new JsonObject();
        json.addProperty("protocol", "TLS Encrypted Application Data");
        json.addProperty("version", tlsVer);
        json.addProperty("ciphertext_bytes", len);

        String summary = "Encrypted TLS Application Data (" + len + " bytes)";
        return new DecodedHttps(ProtocolType.TLS_APPLICATION_DATA, "TLS", "", 0, "", "", "",
                tlsVer, null, "", summary, GSON.toJson(json));
    }

    private static String parseTlsVersion(int major, int minor) {
        if (major == 3 && minor == 1) return "TLSv1.0";
        if (major == 3 && minor == 2) return "TLSv1.1";
        if (major == 3 && minor == 3) return "TLSv1.2";
        if (major == 3 && minor == 4) return "TLSv1.3";
        return String.format("TLS (%d.%d)", major, minor);
    }
}
