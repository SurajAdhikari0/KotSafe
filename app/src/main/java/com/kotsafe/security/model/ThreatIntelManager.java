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

package com.kotsafe.security.model;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.widget.Toast;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

public class ThreatIntelManager {
    private static final String TAG = "ThreatIntelManager";

    public enum IndicatorType {
        IP,
        DOMAIN,
        URL,
        HASH
    }

    public interface ThreatIntelCallback {
        void onResult(String indicator, String verdict, int score, String details);
        void onError(String indicator, String error);
    }

    /**
     * Computes SHA-256 hash string for a byte array.
     */
    public static String computeSha256(byte[] data) {
        if(data == null || data.length == 0) return "";
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for(byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            Log.e(TAG, "SHA-256 calculation error: " + e.getMessage());
            return "";
        }
    }

    /**
     * Extracts and normalizes a clean domain or hostname from any raw input (URL, URI, host:port).
     * Returns lowercase hostname without protocol, port, path, query, or slashes.
     */
    public static String cleanDomain(String raw) {
        if (raw == null) return "";
        String s = raw.trim();
        if (s.isEmpty()) return "";

        // Remove wrapping quotes
        if ((s.startsWith("\"") && s.endsWith("\"")) || (s.startsWith("'") && s.endsWith("'"))) {
            s = s.substring(1, s.length() - 1).trim();
        }

        // If it starts with a scheme like http:// or https://
        if (s.contains("://")) {
            try {
                Uri uri = Uri.parse(s);
                String host = uri.getHost();
                if (host != null && !host.isEmpty()) {
                    s = host;
                } else {
                    s = s.substring(s.indexOf("://") + 3);
                }
            } catch (Exception ignored) {
                s = s.substring(s.indexOf("://") + 3);
            }
        }

        // Strip path, query, fragment
        int slashIdx = s.indexOf('/');
        if (slashIdx >= 0) {
            s = s.substring(0, slashIdx);
        }
        int qIdx = s.indexOf('?');
        if (qIdx >= 0) {
            s = s.substring(0, qIdx);
        }
        int hashIdx = s.indexOf('#');
        if (hashIdx >= 0) {
            s = s.substring(0, hashIdx);
        }

        // Strip port if present (and not an IPv6 literal)
        if (!s.startsWith("[") && s.contains(":")) {
            s = s.substring(0, s.indexOf(':'));
        } else if (s.startsWith("[") && s.contains("]:")) {
            s = s.substring(0, s.indexOf("]:") + 1);
        }

        // Strip leading/trailing dots or spaces
        while (s.startsWith(".")) s = s.substring(1);
        while (s.endsWith(".")) s = s.substring(0, s.length() - 1);

        return s.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Extracts and normalizes a clean IP address from raw input, stripping ports and protocols.
     */
    public static String cleanIp(String raw) {
        if (raw == null) return "";
        String s = raw.trim();
        if (s.isEmpty()) return "";

        // Remove scheme if present
        if (s.contains("://")) {
            try {
                Uri uri = Uri.parse(s);
                String host = uri.getHost();
                if (host != null && !host.isEmpty()) s = host;
                else s = s.substring(s.indexOf("://") + 3);
            } catch (Exception ignored) {
                s = s.substring(s.indexOf("://") + 3);
            }
        }

        // Strip path
        int slash = s.indexOf('/');
        if (slash >= 0) s = s.substring(0, slash);

        // Strip bracketed IPv6 port: [2001:db8::1]:80 -> 2001:db8::1
        if (s.startsWith("[") && s.contains("]")) {
            int close = s.indexOf(']');
            return s.substring(1, close).trim();
        }

        // IPv4 with port: 1.2.3.4:8080 -> 1.2.3.4
        if (s.contains(".") && s.contains(":")) {
            s = s.substring(0, s.indexOf(':'));
        }

        return s.trim();
    }

    /**
     * Checks if the IP address is a private, loopback, or link-local address.
     * Public threat feeds like VirusTotal / OTX do not index local/private addresses.
     */
    public static boolean isPrivateOrLocalIp(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        String clean = cleanIp(ip);
        if (clean.equals("localhost") || clean.equals("127.0.0.1") || clean.equals("::1") || clean.equals("0.0.0.0")) {
            return true;
        }
        if (clean.startsWith("10.") || clean.startsWith("192.168.") || clean.startsWith("169.254.")) {
            return true;
        }
        if (clean.startsWith("172.")) {
            try {
                String[] parts = clean.split("\\.");
                if (parts.length >= 2) {
                    int second = Integer.parseInt(parts[1]);
                    if (second >= 16 && second <= 31) return true;
                }
            } catch (Exception ignored) {}
        }
        String lower = clean.toLowerCase(Locale.ROOT);
        return lower.startsWith("fe80:") || lower.startsWith("fc00:") || lower.startsWith("fd00:");
    }

    /**
     * Extracts and normalizes a hash (MD5, SHA-1, SHA-256), stripping prefixes like 'sha256:'.
     */
    public static String cleanHash(String raw) {
        if (raw == null) return "";
        String s = raw.trim();
        String lower = s.toLowerCase(Locale.ROOT);
        if (lower.startsWith("sha256:")) {
            s = s.substring(7).trim();
        } else if (lower.startsWith("sha-256:")) {
            s = s.substring(8).trim();
        } else if (lower.startsWith("sha1:")) {
            s = s.substring(5).trim();
        } else if (lower.startsWith("sha-1:")) {
            s = s.substring(6).trim();
        } else if (lower.startsWith("md5:")) {
            s = s.substring(4).trim();
        }
        s = s.replaceAll("[\"'\\s]", "");
        return s.toLowerCase(Locale.ROOT);
    }

    /**
     * Determines whether a string is a hex hash (MD5, SHA1, or SHA256).
     */
    public static boolean isHash(String raw) {
        if (raw == null) return false;
        String h = cleanHash(raw);
        int len = h.length();
        if (len != 32 && len != 40 && len != 64) return false;
        return h.matches("^[0-9a-fA-F]+$");
    }

    /**
     * Determines whether a string is an IP address.
     */
    public static boolean isIpAddress(String raw) {
        if (raw == null) return false;
        String ip = cleanIp(raw);
        if (ip.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) {
            return true;
        }
        return ip.contains(":") && !ip.contains(".");
    }

    /**
     * Resolves the IndicatorType from a raw string and optional hint.
     */
    public static IndicatorType resolveIndicatorType(String indicator, String typeHint) {
        if (indicator == null || indicator.trim().isEmpty()) return IndicatorType.DOMAIN;
        String s = indicator.trim();

        if (typeHint != null) {
            String th = typeHint.toUpperCase(Locale.ROOT);
            if (th.contains("HASH") || th.contains("FILE")) return IndicatorType.HASH;
            if (th.contains("IP")) return IndicatorType.IP;
            if (th.contains("URL")) return IndicatorType.URL;
            if (th.contains("DOMAIN")) return IndicatorType.DOMAIN;
        }

        if (isHash(s)) return IndicatorType.HASH;
        if (isIpAddress(s)) return IndicatorType.IP;
        if (s.startsWith("http://") || s.startsWith("https://") || (s.contains("/") && !s.endsWith("/"))) {
            return IndicatorType.URL;
        }
        return IndicatorType.DOMAIN;
    }

    /**
     * Generates a direct VirusTotal web analysis URL for an indicator.
     * Prevents 404 / 'page does not exist' by sanitizing parameters and using
     * official search endpoints when applicable.
     */
    public static String getVirusTotalUrl(String indicator, IndicatorType type) {
        if (indicator == null || indicator.trim().isEmpty()) return "";
        String raw = indicator.trim();
        if (type == null) {
            type = resolveIndicatorType(raw, null);
        }

        switch (type) {
            case HASH:
                return "https://www.virustotal.com/gui/file/" + cleanHash(raw);

            case IP:
                return "https://www.virustotal.com/gui/ip-address/" + cleanIp(raw);

            case DOMAIN:
                String domain = cleanDomain(raw);
                if (!domain.isEmpty()) {
                    return "https://www.virustotal.com/gui/domain/" + domain;
                }
                return "https://www.virustotal.com/gui/search/" + Uri.encode(raw);

            case URL:
                String d = cleanDomain(raw);
                boolean hasDistinctPath = false;
                try {
                    Uri u = Uri.parse(raw.contains("://") ? raw : "http://" + raw);
                    String p = u.getPath();
                    if (p != null && !p.isEmpty() && !p.equals("/")) {
                        hasDistinctPath = true;
                    }
                } catch (Exception ignored) {}

                // If root URL (e.g. https://vegamoviess.mobi/), route to domain report for 100% reliability
                if (!hasDistinctPath && !d.isEmpty()) {
                    return "https://www.virustotal.com/gui/domain/" + d;
                }
                // For subpath URLs, use VT search endpoint so user gets report or 1-click analyze
                return "https://www.virustotal.com/gui/search/" + Uri.encode(raw);

            default:
                return "https://www.virustotal.com/gui/search/" + Uri.encode(raw);
        }
    }

    /**
     * Generates an AlienVault OTX (Open Threat Exchange) web URL for an indicator.
     * OTX requires clean indicator endpoints (no schemes, paths, or query params).
     */
    public static String getOtxUrl(String indicator, IndicatorType type) {
        if (indicator == null || indicator.trim().isEmpty()) return "";
        String raw = indicator.trim();
        if (type == null) {
            type = resolveIndicatorType(raw, null);
        }

        switch (type) {
            case HASH:
                return "https://otx.alienvault.com/indicator/file/" + cleanHash(raw);

            case IP:
                return "https://otx.alienvault.com/indicator/ip/" + cleanIp(raw);

            case DOMAIN:
            case URL:
                String domain = cleanDomain(raw);
                if (!domain.isEmpty() && (domain.contains(".") || !domain.contains("/"))) {
                    return "https://otx.alienvault.com/indicator/domain/" + domain;
                }
                return "https://otx.alienvault.com/browse/pulses?q=" + Uri.encode(domain.isEmpty() ? raw : domain);

            default:
                String d2 = cleanDomain(raw);
                return "https://otx.alienvault.com/browse/pulses?q=" + Uri.encode(d2.isEmpty() ? raw : d2);
        }
    }

    /**
     * Opens VirusTotal directly in browser for the given indicator.
     */
    public static void openVirusTotal(Context context, String indicator, IndicatorType type) {
        if (context == null || indicator == null || indicator.trim().isEmpty()) return;

        if (type == IndicatorType.IP || isIpAddress(indicator)) {
            String ip = cleanIp(indicator);
            if (isPrivateOrLocalIp(ip)) {
                Toast.makeText(context, ip + " is a private/local network address (not on public threat feeds)", Toast.LENGTH_LONG).show();
                return;
            }
        }

        String url = getVirusTotalUrl(indicator, type);
        if (!url.isEmpty()) {
            try {
                Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                context.startActivity(intent);
            } catch (Exception e) {
                Log.e(TAG, "Cannot launch VirusTotal URL: " + e.getMessage());
                Toast.makeText(context, "No web browser available to open VirusTotal", Toast.LENGTH_SHORT).show();
            }
        }
    }

    /**
     * Opens AlienVault OTX directly in browser for the given indicator.
     */
    public static void openOtx(Context context, String indicator, IndicatorType type) {
        if (context == null || indicator == null || indicator.trim().isEmpty()) return;

        if (type == IndicatorType.IP || isIpAddress(indicator)) {
            String ip = cleanIp(indicator);
            if (isPrivateOrLocalIp(ip)) {
                Toast.makeText(context, ip + " is a private/local network address (not on public threat feeds)", Toast.LENGTH_LONG).show();
                return;
            }
        }

        String url = getOtxUrl(indicator, type);
        if (!url.isEmpty()) {
            try {
                Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                context.startActivity(intent);
            } catch (Exception e) {
                Log.e(TAG, "Cannot launch OTX URL: " + e.getMessage());
                Toast.makeText(context, "No web browser available to open AlienVault OTX", Toast.LENGTH_SHORT).show();
            }
        }
    }

    /**
     * Automatically infers indicator type and opens VirusTotal safely.
     */
    public static void openVirusTotalAuto(Context context, String indicator, String typeHint) {
        IndicatorType type = resolveIndicatorType(indicator, typeHint);
        openVirusTotal(context, indicator, type);
    }

    /**
     * Automatically infers indicator type and opens AlienVault OTX safely.
     */
    public static void openOtxAuto(Context context, String indicator, String typeHint) {
        IndicatorType type = resolveIndicatorType(indicator, typeHint);
        openOtx(context, indicator, type);
    }

    public static void openVirusTotalIp(Context context, String ip) {
        openVirusTotal(context, ip, IndicatorType.IP);
    }

    public static void openVirusTotalDomain(Context context, String domain) {
        openVirusTotal(context, domain, IndicatorType.DOMAIN);
    }

    public static void openVirusTotalFile(Context context, String hash) {
        openVirusTotal(context, hash, IndicatorType.HASH);
    }

    public static void openOtxIp(Context context, String ip) {
        openOtx(context, ip, IndicatorType.IP);
    }

    public static void openOtxDomain(Context context, String domain) {
        openOtx(context, domain, IndicatorType.DOMAIN);
    }

    public static void openOtxFile(Context context, String hash) {
        openOtx(context, hash, IndicatorType.HASH);
    }

    /**
     * Future placeholder for automated API scanning against VirusTotal / OTX.
     */
    public static void queryThreatIntelligence(String indicator, IndicatorType type, String apiKey, ThreatIntelCallback callback) {
        if (apiKey == null || apiKey.isEmpty()) {
            if (callback != null) callback.onError(indicator, "No API key configured");
            return;
        }
    }
}
