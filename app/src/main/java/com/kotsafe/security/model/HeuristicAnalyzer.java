/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.backend.BackendProviderFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Heuristic analyzer — local, offline threat scoring without any network calls.
 *
 * Applies lightweight rules derived from MITRE ATT&CK Mobile and known malware IOC patterns.
 * All rules return a risk contribution (0–100) and a description.
 *
 * Used as the "fast path" before queuing async TI enrichment.
 */
public class HeuristicAnalyzer {
    private static final String TAG = "HeuristicAnalyzer";

    public static class HeuristicResult {
        public int riskScore = 0;       // 0-100 aggregate
        public boolean isSuspicious = false;
        public boolean isMalicious = false;
        public List<String> findings = new ArrayList<>();

        public void addFinding(int score, String desc) {
            riskScore = Math.min(100, riskScore + score);
            findings.add("[+" + score + "] " + desc);
        }
    }

    // ─── Network heuristics ───────────────────────────────────────────────────

    public static HeuristicResult analyzeConnection(String domain, String ip,
                                                     int port, String appPackage) {
        HeuristicResult r = new HeuristicResult();

        // Official Android OS, Google, Samsung, OEM apps, KotSafe self, and official domains are whitelisted
        if ((appPackage != null && (Utils.isSystemApp(null, appPackage) || appPackage.startsWith("com.kotsafe.security") || appPackage.startsWith("com.kotsafe.security")))
                || SecurityBlocklistManager.isOfficialDomain(domain)
                || SecurityBlocklistManager.isTrustedAdOrAnalyticsDomain(domain)
                || (domain != null && domain.contains("trycloudflare.com"))
                || BackendProviderFactory.isRelayEndpoint(ip)) {
            return r;
        }

        // Suspicious TLDs
        if (domain != null) {
            String d = domain.toLowerCase();
            boolean isCdnOrCloud = isKnownCdnOrCloudDomain(d);

            if (matchesSuspiciousTld(d))
                r.addFinding(20, "Suspicious TLD: " + d);
            if (d.contains("dyndns") || d.contains("no-ip") || d.contains("hopto")
                    || d.contains("duckdns") || d.contains("ddns"))
                r.addFinding(25, "Dynamic DNS detected: " + d);
            if (!isCdnOrCloud && d.matches(".*[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}.*"))
                r.addFinding(15, "IP-in-domain (possible C2): " + d);
            if (!isCdnOrCloud && d.length() > 60)
                r.addFinding(10, "Unusually long domain (DGA?): " + d.substring(0, 30) + "…");
            // High entropy subdomain (DGA detection heuristic) — isolate first label to avoid FQDN/CDN false positives
            if (!isCdnOrCloud) {
                int firstDot = d.indexOf('.');
                String subLabel = firstDot > 0 ? d.substring(0, firstDot) : d;
                if (subLabel.length() >= 14 && domainEntropy(subLabel) >= 4.4) {
                    r.addFinding(20, "High entropy subdomain (possible DGA): " + subLabel);
                }
            }
        }

        // Suspicious ports
        if (isSuspiciousPort(port))
            r.addFinding(20, "Suspicious port: " + port);

        // Raw IP connection (no domain) to non-CDN range
        if (domain == null && ip != null && !isPrivateIp(ip) && !BackendProviderFactory.isRelayEndpoint(ip))
            r.addFinding(10, "Raw IP connection (no domain): " + ip);

        r.isSuspicious = r.riskScore >= 30;
        r.isMalicious  = r.riskScore >= 70;
        return r;
    }

    // ─── File heuristics ──────────────────────────────────────────────────────

    public static HeuristicResult analyzeFile(FileHashEntry entry) {
        HeuristicResult r = new HeuristicResult();

        if (entry == null || entry.isSystemApp || Utils.isSystemApp(null, entry.packageName)
                || (entry.packageName != null && (entry.packageName.startsWith("com.kotsafe.security") || entry.packageName.startsWith("com.kotsafe.security")))) return r;

        // Hidden service app with no launcher
        if (entry.isServiceApp && !entry.isSystemApp && entry.threatStatus != null
                && entry.threatStatus.contains("Hidden"))
            r.addFinding(35, "Hidden background service without launcher");

        // APK in Downloads directory (side-loaded)
        if (entry.filePath != null && entry.filePath.contains("/Download")
                && FileHashEntry.FILE_CLASS_APK.equals(entry.fileClass))
            r.addFinding(30, "APK in Downloads (possible side-load): " + entry.fileName);

        // Script in storage
        if (FileHashEntry.FILE_CLASS_SCRIPT.equals(entry.fileClass)
                && entry.filePath != null && !entry.filePath.startsWith("/system"))
            r.addFinding(25, "Executable script in user storage: " + entry.fileName);

        // Very small APK (possible stub/dropper, ignore standard Android App Bundle split APKs)
        if (FileHashEntry.FILE_CLASS_APK.equals(entry.fileClass) && entry.fileSize < 50_000
                && (entry.fileName == null || !entry.fileName.startsWith("split_")))
            r.addFinding(20, "Unusually small APK (" + (entry.fileSize / 1024) + " KB) — possible dropper");

        // .so file in non-standard location
        if (FileHashEntry.FILE_CLASS_SO.equals(entry.fileClass)
                && entry.filePath != null && !entry.filePath.contains("/data/app"))
            r.addFinding(15, "Native library outside app sandbox: " + entry.fileName);

        r.isSuspicious = r.riskScore >= 30;
        r.isMalicious  = r.riskScore >= 70;
        return r;
    }

    // ─── URL heuristics ───────────────────────────────────────────────────────

    public static HeuristicResult analyzeUrl(String url) {
        HeuristicResult r = new HeuristicResult();
        if (url == null || url.isEmpty()) return r;

        String lower = url.toLowerCase();

        if (lower.contains("cmd=") || lower.contains("exec=") || lower.contains("shell="))
            r.addFinding(40, "URL contains command injection pattern");
        if (lower.contains("base64") || lower.contains("%3c%73%63%72%69%70%74"))
            r.addFinding(20, "URL contains encoded payload");
        if (lower.contains("/wp-admin") || lower.contains("/phpmyadmin"))
            r.addFinding(10, "Admin panel URL detected");
        if (lower.startsWith("http://") && lower.contains("password"))
            r.addFinding(15, "Password transmitted over plain HTTP");
        if (lower.contains(".onion"))
            r.addFinding(35, "Tor .onion URL detected");

        r.isSuspicious = r.riskScore >= 25;
        r.isMalicious  = r.riskScore >= 60;
        return r;
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private static final java.util.Set<String> SUSPICIOUS_TLDS = new java.util.HashSet<>(
            java.util.Arrays.asList(".top", ".xyz", ".work", ".click", ".buzz",
                    ".cam", ".gq", ".cf", ".tk", ".ml", ".ga", ".loan", ".date",
                    ".racing", ".cricket", ".science", ".party", ".trade", ".win"));

    private static boolean matchesSuspiciousTld(String domain) {
        for (String tld : SUSPICIOUS_TLDS) {
            if (domain.endsWith(tld)) return true;
        }
        return false;
    }

    private static final java.util.Set<Integer> SUSPICIOUS_PORTS = new java.util.HashSet<>(
            java.util.Arrays.asList(23, 2323, 1337, 31337, 4444, 4445, 5554, 5555,
                    6666, 6667, 6668, 8554, 9999, 12345, 54321));

    private static boolean isSuspiciousPort(int port) {
        return SUSPICIOUS_PORTS.contains(port);
    }

    private static boolean isPrivateIp(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        return ip.startsWith("10.") || ip.startsWith("192.168.")
                || ip.startsWith("172.16.") || ip.startsWith("127.")
                || ip.equals("::1");
    }

    /** Shannon entropy of the domain labels — high entropy often indicates DGA. */
    private static double domainEntropy(String domain) {
        if (domain == null || domain.isEmpty()) return 0.0;
        int freq[] = new int[256];
        for (char c : domain.toCharArray()) if (c < 256) freq[c]++;
        double entropy = 0;
        int len = domain.length();
        if (len == 0) return 0.0;
        for (int f : freq) {
            if (f > 0) {
                double p = (double) f / len;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }

    public static boolean isKnownCdnOrCloudDomain(String d) {
        if (d == null || d.isEmpty()) return false;
        return d.endsWith(".cloudfront.net")
                || d.endsWith(".amazonaws.com")
                || d.endsWith(".akamaiedge.net")
                || d.endsWith(".akamaihd.net")
                || d.endsWith(".akamai.net")
                || d.endsWith(".fastly.net")
                || d.endsWith(".cloudflare.com")
                || d.endsWith(".cloudflare-dns.com")
                || d.endsWith(".trycloudflare.com")
                || d.endsWith(".1e100.net")
                || d.endsWith(".googleusercontent.com")
                || d.endsWith(".azureedge.net")
                || d.endsWith(".trafficmanager.net")
                || d.endsWith(".github.com")
                || d.endsWith(".githubusercontent.com")
                || d.endsWith(".jsdelivr.net");
    }
}
