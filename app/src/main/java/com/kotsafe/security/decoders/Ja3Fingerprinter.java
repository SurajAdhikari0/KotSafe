/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.decoders;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * TLS JA3 Fingerprint extraction and anomaly/threat detection.
 * Follows the standard Salesforce JA3 specification:
 * SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
 *
 * Excludes GREASE (RFC 8701) values and generates standard MD5 hash.
 * Provides signature matching for known malicious bot/C2 clients
 * (Cobalt Strike, Metasploit, TrickBot, Emotet, Mirai, Dridex, etc.).
 */
public class Ja3Fingerprinter {

    public static class Ja3Result {
        public final String raw;
        public final String hash;
        public final boolean isSuspicious;
        public final String threatName;
        public final String threatCategory;

        public Ja3Result(String raw, String hash, boolean isSuspicious, String threatName, String threatCategory) {
            this.raw = raw != null ? raw : "";
            this.hash = hash != null ? hash : "";
            this.isSuspicious = isSuspicious;
            this.threatName = threatName != null ? threatName : "";
            this.threatCategory = threatCategory != null ? threatCategory : "";
        }
    }

    public static class MaliciousJa3Info {
        public final String name;
        public final String category; // C2, TROJAN, BOTNET, SCANNER, SCRIPT
        public final String description;

        public MaliciousJa3Info(String name, String category, String description) {
            this.name = name;
            this.category = category;
            this.description = description;
        }
    }

    // Curated high-confidence malicious and bot JA3 signatures
    private static final Map<String, MaliciousJa3Info> KNOWN_MALICIOUS_JA3;

    static {
        Map<String, MaliciousJa3Info> map = new HashMap<>();
        // Cobalt Strike
        map.put("a0e9f5d64349fb13191bc781f81f42e1", new MaliciousJa3Info(
                "Cobalt Strike (Default Beacon)", "C2", "Default Cobalt Strike HTTPS C2 Beacon listener fingerprint"));
        map.put("b38454743c3ac0360ded43a321e15f1f", new MaliciousJa3Info(
                "Cobalt Strike (Malleable C2)", "C2", "Malleable C2 HTTPS Profile used for covert C2 communications"));
        map.put("e352e8790310232490df1a5477d94f27", new MaliciousJa3Info(
                "Cobalt Strike (HTTPS TeamServer)", "C2", "Cobalt Strike TeamServer interactive agent TLS handshake"));

        // Metasploit
        map.put("650b0ee312d46e2746ebf49e49cb79e0", new MaliciousJa3Info(
                "Metasploit Meterpreter Stager", "EXPLOIT", "Standard Metasploit reverse_https payload stager"));
        map.put("e7d705a3286e19ea42f587b344ee6865", new MaliciousJa3Info(
                "Metasploit Reverse HTTPS", "EXPLOIT", "Metasploit Meterpreter Reverse HTTPS transport"));

        // Banking Trojans & Loaders
        map.put("72a589da586844d7f0818ce684948eea", new MaliciousJa3Info(
                "TrickBot Trojan", "TROJAN", "TrickBot banking trojan / modular C2 communications"));
        map.put("51c64c77e60f3980eea90869b68c58a8", new MaliciousJa3Info(
                "Emotet Botnet", "BOTNET", "Emotet malware distributor and banking botnet traffic"));
        map.put("3b5074b1b310a084ddb3644a24ef9d88", new MaliciousJa3Info(
                "Dridex Trojan", "TROJAN", "Dridex financial Trojan encrypted C2 payload exchange"));

        // IoT & DDoS Botnets
        map.put("4d7a28d6f22da2d5ee684d0d0f786da8", new MaliciousJa3Info(
                "Mirai Botnet Variant", "BOTNET", "Mirai / Okiru encrypted command execution bot"));

        // Scanners & Automated Attack Tools
        map.put("9e106927515155f9a67c6ebfa506a644", new MaliciousJa3Info(
                "Masscan/Nmap TLS Probe", "SCANNER", "Automated vulnerability scanner TLS handshake probe"));
        map.put("484c98e1e4854580bf61b369c02d1844", new MaliciousJa3Info(
                "Golang Automated Exploit Bot", "SCANNER", "Generic Go-based scanner/bot exploit payload"));
        map.put("b32309a26951912be7dba376398abc3b", new MaliciousJa3Info(
                "Python-Requests Suspicious Bot", "SCRIPT", "Unmodified Python-requests library making automated background requests"));

        KNOWN_MALICIOUS_JA3 = Collections.unmodifiableMap(map);
    }

    /**
     * Checks if a 16-bit integer is a GREASE value per RFC 8701:
     * {0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa}
     */
    public static boolean isGrease(int val) {
        return (val & 0x0F0F) == 0x0A0A && ((val >> 8) & 0xFF) == (val & 0xFF);
    }

    /**
     * Computes the JA3 fingerprint string and MD5 hash.
     *
     * @param sslVersion TLS version in ClientHello (e.g. 771 for TLS 1.2 / 0x0303)
     * @param ciphers List of cipher suite IDs (decimal)
     * @param extensions List of TLS extension IDs (decimal)
     * @param curves List of supported elliptic curves / groups (decimal)
     * @param pointFormats List of EC point formats (decimal)
     * @return Ja3Result with raw string, MD5 hash, and threat assessment
     */
    public static Ja3Result compute(int sslVersion,
                                   List<Integer> ciphers,
                                   List<Integer> extensions,
                                   List<Integer> curves,
                                   List<Integer> pointFormats) {
        StringBuilder raw = new StringBuilder();

        // 1. SSLVersion
        raw.append(sslVersion).append(",");

        // 2. Cipher suites (omitting GREASE)
        if (ciphers != null) {
            boolean first = true;
            for (int c : ciphers) {
                if (isGrease(c)) continue;
                if (!first) raw.append("-");
                raw.append(c);
                first = false;
            }
        }
        raw.append(",");

        // 3. SSLExtensions (omitting GREASE)
        if (extensions != null) {
            boolean first = true;
            for (int ext : extensions) {
                if (isGrease(ext)) continue;
                if (!first) raw.append("-");
                raw.append(ext);
                first = false;
            }
        }
        raw.append(",");

        // 4. EllipticCurves (omitting GREASE)
        if (curves != null) {
            boolean first = true;
            for (int crv : curves) {
                if (isGrease(crv)) continue;
                if (!first) raw.append("-");
                raw.append(crv);
                first = false;
            }
        }
        raw.append(",");

        // 5. EllipticCurvePointFormats (omitting GREASE)
        if (pointFormats != null) {
            boolean first = true;
            for (int pf : pointFormats) {
                if (isGrease(pf)) continue;
                if (!first) raw.append("-");
                raw.append(pf);
                first = false;
            }
        }

        String rawStr = raw.toString();
        String hash = computeMd5(rawStr);

        MaliciousJa3Info info = detectMalicious(hash);
        boolean isSuspicious = info != null;
        String threatName = info != null ? info.name : "";
        String threatCat = info != null ? info.category : "";

        return new Ja3Result(rawStr, hash, isSuspicious, threatName, threatCat);
    }

    /**
     * Checks if a JA3 hash is on the known malicious/bot list.
     */
    public static MaliciousJa3Info detectMalicious(String ja3Hash) {
        if (ja3Hash == null || ja3Hash.isEmpty()) return null;
        return KNOWN_MALICIOUS_JA3.get(ja3Hash.toLowerCase().trim());
    }

    /**
     * Computes MD5 hex string in lowercase.
     */
    public static String computeMd5(String input) {
        if (input == null || input.isEmpty()) return "";
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xFF));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }

    /**
     * Returns an unmodifiable map of all registered malicious JA3 signatures.
     */
    public static Map<String, MaliciousJa3Info> getKnownMaliciousSignatures() {
        return KNOWN_MALICIOUS_JA3;
    }
}
