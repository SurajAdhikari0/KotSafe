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
 * Copyright 2026 - KotSafe
 */

package com.kotsafe.security.decoders;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * DNS-over-HTTPS (DoH, RFC 8484) wireformat packet decoder.
 * Parses raw RFC 1035 binary DNS messages (queries and responses) transported over HTTPS.
 */
public class DohDecoder {
    private static final String TAG = "DohDecoder";
    private static final Gson GSON_PRETTY = new GsonBuilder().setPrettyPrinting().create();

    // DNS Record Types
    public static final int TYPE_A = 1;
    public static final int TYPE_NS = 2;
    public static final int TYPE_CNAME = 5;
    public static final int TYPE_SOA = 6;
    public static final int TYPE_PTR = 12;
    public static final int TYPE_MX = 15;
    public static final int TYPE_TXT = 16;
    public static final int TYPE_AAAA = 28;
    public static final int TYPE_SRV = 33;
    public static final int TYPE_OPT = 41;
    public static final int TYPE_SVCB = 64;
    public static final int TYPE_HTTPS = 65;
    public static final int TYPE_ANY = 255;

    public static class DnsQuestion {
        public final String name;
        public final int type;
        public final String typeName;
        public final int dnsClass;

        public DnsQuestion(String name, int type, String typeName, int dnsClass) {
            this.name = name;
            this.type = type;
            this.typeName = typeName;
            this.dnsClass = dnsClass;
        }

        public JsonObject toJsonObject() {
            JsonObject obj = new JsonObject();
            obj.addProperty("name", name);
            obj.addProperty("type", type);
            obj.addProperty("typeName", typeName);
            obj.addProperty("class", dnsClass);
            return obj;
        }
    }

    public static class DnsRecord {
        public final String name;
        public final int type;
        public final String typeName;
        public final int dnsClass;
        public final long ttl;
        public final String data;

        public DnsRecord(String name, int type, String typeName, int dnsClass, long ttl, String data) {
            this.name = name;
            this.type = type;
            this.typeName = typeName;
            this.dnsClass = dnsClass;
            this.ttl = ttl;
            this.data = data;
        }

        public JsonObject toJsonObject() {
            JsonObject obj = new JsonObject();
            obj.addProperty("name", name);
            obj.addProperty("type", type);
            obj.addProperty("typeName", typeName);
            obj.addProperty("class", dnsClass);
            obj.addProperty("ttl", ttl);
            obj.addProperty("data", data);
            return obj;
        }
    }

    public static class DohResult {
        public final int id;
        public final boolean isResponse;
        public final int opcode;
        public final boolean authoritativeAnswer;
        public final boolean truncated;
        public final boolean recursionDesired;
        public final boolean recursionAvailable;
        public final int rcode;
        public final String rcodeName;
        public final List<DnsQuestion> questions;
        public final List<DnsRecord> answers;
        public final List<DnsRecord> authorities;
        public final List<DnsRecord> additionals;
        public final String prettyJson;
        public final String summary;
        public final int rawLength;

        public DohResult(int id, boolean isResponse, int opcode, boolean authoritativeAnswer,
                         boolean truncated, boolean recursionDesired, boolean recursionAvailable,
                         int rcode, String rcodeName,
                         List<DnsQuestion> questions, List<DnsRecord> answers,
                         List<DnsRecord> authorities, List<DnsRecord> additionals,
                         String prettyJson, String summary, int rawLength) {
            this.id = id;
            this.isResponse = isResponse;
            this.opcode = opcode;
            this.authoritativeAnswer = authoritativeAnswer;
            this.truncated = truncated;
            this.recursionDesired = recursionDesired;
            this.recursionAvailable = recursionAvailable;
            this.rcode = rcode;
            this.rcodeName = rcodeName;
            this.questions = questions;
            this.answers = answers;
            this.authorities = authorities;
            this.additionals = additionals;
            this.prettyJson = prettyJson;
            this.summary = summary;
            this.rawLength = rawLength;
        }
    }

    /**
     * Decodes Base64URL-encoded wireformat DNS query (e.g. from GET /dns-query?dns=...).
     */
    @Nullable
    public static DohResult decodeBase64Url(@Nullable String base64Url) {
        if (base64Url == null || base64Url.isEmpty()) return null;
        try {
            byte[] raw = null;
            try {
                raw = java.util.Base64.getUrlDecoder().decode(base64Url);
            } catch (Throwable t) {
                raw = android.util.Base64.decode(base64Url, android.util.Base64.URL_SAFE | android.util.Base64.NO_PADDING | android.util.Base64.NO_WRAP);
            }
            if (raw == null) return null;
            return decode(raw);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Attempts to parse binary DNS wireformat packet (RFC 1035 / RFC 8484).
     */
    @Nullable
    public static DohResult decode(@Nullable byte[] data) {
        if (data == null || data.length < 12) {
            return null;
        }

        try {
            ByteBuffer buffer = ByteBuffer.wrap(data);
            buffer.order(ByteOrder.BIG_ENDIAN);

            int id = buffer.getShort() & 0xFFFF;
            int flags = buffer.getShort() & 0xFFFF;

            boolean qr = ((flags >> 15) & 0x01) == 1;
            int opcode = (flags >> 11) & 0x0F;
            boolean aa = ((flags >> 10) & 0x01) == 1;
            boolean tc = ((flags >> 9) & 0x01) == 1;
            boolean rd = ((flags >> 8) & 0x01) == 1;
            boolean ra = ((flags >> 7) & 0x01) == 1;
            int rcode = flags & 0x0F;

            int qdCount = buffer.getShort() & 0xFFFF;
            int anCount = buffer.getShort() & 0xFFFF;
            int nsCount = buffer.getShort() & 0xFFFF;
            int arCount = buffer.getShort() & 0xFFFF;

            // Basic sanity checks for DNS header
            if (qdCount > 50 || anCount > 200 || nsCount > 100 || arCount > 100) {
                return null;
            }

            List<DnsQuestion> questions = new ArrayList<>(qdCount);
            for (int i = 0; i < qdCount; i++) {
                String name = readDomainName(buffer, data);
                if (name == null || buffer.remaining() < 4) return null;
                int qtype = buffer.getShort() & 0xFFFF;
                int qclass = buffer.getShort() & 0xFFFF;
                questions.add(new DnsQuestion(name, qtype, typeToString(qtype), qclass));
            }

            List<DnsRecord> answers = parseRecords(buffer, data, anCount);
            if (answers == null && anCount > 0) return null;

            List<DnsRecord> authorities = parseRecords(buffer, data, nsCount);
            if (authorities == null && nsCount > 0) return null;

            List<DnsRecord> additionals = parseRecords(buffer, data, arCount);
            if (additionals == null && arCount > 0) return null;

            if (questions.isEmpty() && (answers == null || answers.isEmpty())) {
                return null;
            }

            String rcodeName = rcodeToString(rcode);
            JsonObject json = new JsonObject();
            json.addProperty("id", "0x" + Integer.toHexString(id).toUpperCase());
            json.addProperty("type", qr ? "RESPONSE" : "QUERY");
            json.addProperty("opcode", opcode);
            json.addProperty("status", rcodeName);

            JsonObject flagsObj = new JsonObject();
            flagsObj.addProperty("authoritativeAnswer", aa);
            flagsObj.addProperty("truncated", tc);
            flagsObj.addProperty("recursionDesired", rd);
            flagsObj.addProperty("recursionAvailable", ra);
            json.add("flags", flagsObj);

            JsonArray qArr = new JsonArray();
            for (DnsQuestion q : questions) qArr.add(q.toJsonObject());
            json.add("questions", qArr);

            JsonArray aArr = new JsonArray();
            if (answers != null) {
                for (DnsRecord a : answers) aArr.add(a.toJsonObject());
            }
            json.add("answers", aArr);

            JsonArray nsArr = new JsonArray();
            if (authorities != null) {
                for (DnsRecord ns : authorities) nsArr.add(ns.toJsonObject());
            }
            json.add("authorities", nsArr);

            JsonArray arArr = new JsonArray();
            if (additionals != null) {
                for (DnsRecord ar : additionals) arArr.add(ar.toJsonObject());
            }
            json.add("additionals", arArr);

            String prettyJson = GSON_PRETTY.toJson(json);

            // Build concise summary string
            StringBuilder summary = new StringBuilder();
            if (!questions.isEmpty()) {
                DnsQuestion q0 = questions.get(0);
                summary.append(q0.name).append(" (").append(q0.typeName).append(")");
            }
            if (qr) {
                summary.append(" -> ").append(rcodeName);
                if (answers != null && !answers.isEmpty()) {
                    summary.append(" [");
                    for (int i = 0; i < answers.size(); i++) {
                        if (i > 0) summary.append(", ");
                        if (i >= 3) {
                            summary.append("+").append(answers.size() - i).append(" more");
                            break;
                        }
                        summary.append(answers.get(i).data);
                    }
                    summary.append("]");
                }
            }

            return new DohResult(id, qr, opcode, aa, tc, rd, ra, rcode, rcodeName,
                    questions,
                    answers != null ? answers : Collections.emptyList(),
                    authorities != null ? authorities : Collections.emptyList(),
                    additionals != null ? additionals : Collections.emptyList(),
                    prettyJson, summary.toString(), data.length);
        } catch (Exception e) {
            return null;
        }
    }

    @Nullable
    private static List<DnsRecord> parseRecords(ByteBuffer buffer, byte[] fullData, int count) {
        List<DnsRecord> records = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            if (!buffer.hasRemaining()) return records;
            String name = readDomainName(buffer, fullData);
            if (name == null || buffer.remaining() < 10) return null;

            int type = buffer.getShort() & 0xFFFF;
            int rClass = buffer.getShort() & 0xFFFF;
            long ttl = buffer.getInt() & 0xFFFFFFFFL;
            int rdLength = buffer.getShort() & 0xFFFF;

            if (buffer.remaining() < rdLength) return null;

            int rDataStart = buffer.position();
            String dataStr = parseRData(buffer, fullData, type, rdLength);
            // Ensure buffer position advances by rdLength exactly
            buffer.position(rDataStart + rdLength);

            records.add(new DnsRecord(name, type, typeToString(type), rClass, ttl, dataStr));
        }
        return records;
    }

    private static String parseRData(ByteBuffer buffer, byte[] fullData, int type, int rdLength) {
        try {
            switch (type) {
                case TYPE_A: {
                    if (rdLength == 4) {
                        byte[] ip = new byte[4];
                        buffer.get(ip);
                        return InetAddress.getByAddress(ip).getHostAddress();
                    }
                    break;
                }
                case TYPE_AAAA: {
                    if (rdLength == 16) {
                        byte[] ip = new byte[16];
                        buffer.get(ip);
                        return InetAddress.getByAddress(ip).getHostAddress();
                    }
                    break;
                }
                case TYPE_CNAME:
                case TYPE_NS:
                case TYPE_PTR: {
                    String domain = readDomainName(buffer, fullData);
                    return domain != null ? domain : "<compressed name>";
                }
                case TYPE_TXT: {
                    StringBuilder sb = new StringBuilder();
                    int read = 0;
                    while (read < rdLength && buffer.hasRemaining()) {
                        int strLen = buffer.get() & 0xFF;
                        read++;
                        if (read + strLen > rdLength || buffer.remaining() < strLen) break;
                        byte[] strBytes = new byte[strLen];
                        buffer.get(strBytes);
                        read += strLen;
                        if (sb.length() > 0) sb.append(" ");
                        sb.append("\"").append(new String(strBytes, StandardCharsets.UTF_8)).append("\"");
                    }
                    return sb.toString();
                }
                case TYPE_MX: {
                    if (rdLength >= 2) {
                        int pref = buffer.getShort() & 0xFFFF;
                        String host = readDomainName(buffer, fullData);
                        return pref + " " + (host != null ? host : "");
                    }
                    break;
                }
                case TYPE_SOA: {
                    String mname = readDomainName(buffer, fullData);
                    String rname = readDomainName(buffer, fullData);
                    return (mname != null ? mname : "") + " " + (rname != null ? rname : "");
                }
                case TYPE_HTTPS:
                case TYPE_SVCB: {
                    if (rdLength >= 2) {
                        int priority = buffer.getShort() & 0xFFFF;
                        String target = readDomainName(buffer, fullData);
                        return "Priority: " + priority + " Target: " + (target != null ? target : ".");
                    }
                    break;
                }
            }
        } catch (Exception ignored) {
        }

        // Fallback to hex
        byte[] raw = new byte[rdLength];
        buffer.get(raw);
        return "0x" + ProtobufDecoder.bytesToHex(raw);
    }

    /**
     * Reads a domain name supporting RFC 1035 pointer compression.
     */
    @Nullable
    private static String readDomainName(ByteBuffer buffer, byte[] fullData) {
        StringBuilder sb = new StringBuilder();
        int jumpCount = 0;
        int maxJumps = 10; // Prevent cyclic pointer loops

        int currPos = buffer.position();
        boolean jumped = false;

        try {
            while (currPos < fullData.length) {
                int len = fullData[currPos] & 0xFF;
                if (len == 0) {
                    if (!jumped) {
                        buffer.position(currPos + 1);
                    }
                    return sb.toString();
                }

                // Check for 2-byte compression pointer (top 2 bits 11xx xxxx -> 0xC0)
                if ((len & 0xC0) == 0xC0) {
                    if (currPos + 1 >= fullData.length) return null;
                    int pointerOffset = ((len & 0x3F) << 8) | (fullData[currPos + 1] & 0xFF);
                    if (!jumped) {
                        buffer.position(currPos + 2);
                        jumped = true;
                    }
                    currPos = pointerOffset;
                    jumpCount++;
                    if (jumpCount > maxJumps) {
                        return null; // Circular reference protection
                    }
                    continue;
                }

                // Normal label
                currPos++;
                if (currPos + len > fullData.length) return null;

                if (sb.length() > 0) sb.append('.');
                sb.append(new String(fullData, currPos, len, StandardCharsets.UTF_8));
                currPos += len;

                if (!jumped) {
                    buffer.position(currPos);
                }
            }
        } catch (Exception e) {
            return null;
        }

        return sb.length() > 0 ? sb.toString() : null;
    }

    public static String typeToString(int type) {
        switch (type) {
            case TYPE_A: return "A";
            case TYPE_NS: return "NS";
            case TYPE_CNAME: return "CNAME";
            case TYPE_SOA: return "SOA";
            case TYPE_PTR: return "PTR";
            case TYPE_MX: return "MX";
            case TYPE_TXT: return "TXT";
            case TYPE_AAAA: return "AAAA";
            case TYPE_SRV: return "SRV";
            case TYPE_OPT: return "OPT";
            case TYPE_SVCB: return "SVCB";
            case TYPE_HTTPS: return "HTTPS";
            case TYPE_ANY: return "ANY";
            default: return "TYPE_" + type;
        }
    }

    public static String rcodeToString(int rcode) {
        switch (rcode) {
            case 0: return "NOERROR";
            case 1: return "FORMERR";
            case 2: return "SERVFAIL";
            case 3: return "NXDOMAIN";
            case 4: return "NOTIMP";
            case 5: return "REFUSED";
            case 6: return "YXDOMAIN";
            case 7: return "YXRRSET";
            case 8: return "NXRRSET";
            case 9: return "NOTAUTH";
            case 10: return "NOTZONE";
            default: return "RCODE_" + rcode;
        }
    }

    /**
     * Heuristic analysis to detect DNS Tunneling and covert data exfiltration.
     * Checks for high-entropy labels, abnormally long subdomains, and hex/base64 encoded payloads.
     */
    public static boolean isPossibleDnsTunnel(String domain) {
        if (domain == null || domain.length() < 30) return false;
        String d = domain.trim().toLowerCase();
        int firstDot = d.indexOf('.');
        if (firstDot <= 0) return false;

        String firstLabel = d.substring(0, firstDot);
        // Abnormally long subdomain label (standard hostnames are typically < 25 chars)
        if (firstLabel.length() > 45) {
            return true;
        }

        // Check Shannon entropy on subdomains >= 20 characters
        if (firstLabel.length() >= 20) {
            double entropy = calculateShannonEntropy(firstLabel);
            if (entropy > 3.85) {
                return true;
            }
        }

        return false;
    }

    private static double calculateShannonEntropy(String s) {
        int[] freq = new int[256];
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 256) freq[c]++;
        }
        double entropy = 0.0;
        double len = s.length();
        for (int f : freq) {
            if (f > 0) {
                double p = f / len;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }
}
