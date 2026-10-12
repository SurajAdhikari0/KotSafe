/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * IOCExtractor
 * ============
 * Extracts Indicators of Compromise (IOCs) from APK files, DEX strings, and
 * static binary resources (IP addresses, suspicious domains, C2 URLs, dynamic
 * loading references, and crypto addresses).
 */

package com.kotsafe.security.model;

import com.kotsafe.security.Log;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class IOCExtractor {
    private static final String TAG = "IOCExtractor";

    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"
    );

    private static final Pattern URL_PATTERN = Pattern.compile(
            "https?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9._~:/?#\\[\\]@!$&'()*+,;=-]*)?"
    );

    private static final Pattern SUSPICIOUS_DOMAIN_PATTERN = Pattern.compile(
            "\\b[a-zA-Z0-9.-]+\\.(?:top|xyz|click|buzz|work|duckdns\\.org|hopto\\.org|no-ip\\.)\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final String[] DANGEROUS_STRINGS = new String[] {
            "dalvik.system.DexClassLoader",
            "dalvik.system.PathClassLoader",
            "/system/bin/su",
            "/system/xbin/su",
            "Runtime.getRuntime().exec",
            "api.telegram.org/bot",
            "pastebin.com/raw/",
            "discord.com/api/webhooks"
    };

    public static class ExtractedIocs {
        public Set<String> ipv4Addresses = new HashSet<>();
        public Set<String> urls = new HashSet<>();
        public Set<String> suspiciousDomains = new HashSet<>();
        public List<String> suspiciousStringMatches = new ArrayList<>();

        public boolean hasHighRiskIndicators() {
            return !suspiciousDomains.isEmpty() || !suspiciousStringMatches.isEmpty();
        }
    }

    public static ExtractedIocs extractFromApk(File apkFile) {
        ExtractedIocs iocs = new ExtractedIocs();
        if (apkFile == null || !apkFile.exists() || !apkFile.canRead()) {
            return iocs;
        }

        try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(new FileInputStream(apkFile)))) {
            ZipEntry entry;
            byte[] buffer = new byte[8192];
            int dexFilesChecked = 0;

            while ((entry = zis.getNextEntry()) != null && dexFilesChecked < 3) {
                String name = entry.getName();
                if (name != null && name.endsWith(".dex")) {
                    dexFilesChecked++;
                    StringBuilder sb = new StringBuilder();
                    int read;
                    int totalRead = 0;
                    // Read first 512KB of each dex for string tables
                    while ((read = zis.read(buffer)) != -1 && totalRead < 524288) {
                        totalRead += read;
                        for (int i = 0; i < read; i++) {
                            byte b = buffer[i];
                            // Printable ASCII characters only
                            if (b >= 32 && b <= 126) {
                                sb.append((char) b);
                            } else if (sb.length() > 0 && sb.charAt(sb.length() - 1) != ' ') {
                                sb.append(' ');
                            }
                        }
                    }

                    String extractedText = sb.toString();
                    scanTextForIocs(extractedText, iocs);
                }
                zis.closeEntry();
            }
        } catch (Exception e) {
            Log.d(TAG, "Error extracting IOCs from APK " + apkFile.getName() + ": " + e.getMessage());
        }

        return iocs;
    }

    public static void scanTextForIocs(String text, ExtractedIocs iocs) {
        if (text == null || text.isEmpty() || iocs == null) return;

        // 1. URLs
        Matcher urlMatcher = URL_PATTERN.matcher(text);
        int urlCount = 0;
        while (urlMatcher.find() && urlCount < 50) {
            String u = urlMatcher.group();
            if (!u.contains("schemas.android.com") && !u.contains("w3.org") && !u.contains("apache.org")) {
                iocs.urls.add(u);
                urlCount++;
            }
        }

        // 2. Suspicious Domains
        Matcher domainMatcher = SUSPICIOUS_DOMAIN_PATTERN.matcher(text);
        int domainCount = 0;
        while (domainMatcher.find() && domainCount < 30) {
            iocs.suspiciousDomains.add(domainMatcher.group());
            domainCount++;
        }

        // 3. IPv4
        Matcher ipMatcher = IPV4_PATTERN.matcher(text);
        int ipCount = 0;
        while (ipMatcher.find() && ipCount < 30) {
            String ip = ipMatcher.group();
            if (!ip.startsWith("0.") && !ip.startsWith("127.") && !ip.equals("255.255.255.255")) {
                iocs.ipv4Addresses.add(ip);
                ipCount++;
            }
        }

        // 4. Dangerous Strings
        for (String danger : DANGEROUS_STRINGS) {
            if (text.contains(danger) && !iocs.suspiciousStringMatches.contains(danger)) {
                iocs.suspiciousStringMatches.add(danger);
            }
        }
    }
}
