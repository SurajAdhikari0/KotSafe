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

package com.kotsafe.security.model.parser;

import android.net.Uri;
import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Advanced log parser and security threat evaluation engine for browser and network logs.
 */
public class AdvancedLogParser {
    private static final String TAG = "AdvancedLogParser";
    private static final Gson GSON_PRETTY = new GsonBuilder().setPrettyPrinting().create();

    // High risk or commonly abused suspicious TLDs
    private static final Set<String> SUSPICIOUS_TLDS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "top", "xyz", "buzz", "fit", "work", "click", "gq", "cf", "ml", "tk", "ga",
            "rest", "country", "stream", "kim", "icu", "cam", "monster", "bar", "surf",
            "online", "loan", "racing", "vip", "win", "bid", "accountant", "date", "faith"
    )));

    // Marketing, ad tracking, and user telemetry parameter keys
    private static final Set<String> TRACKING_KEYS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
            "gclid", "fbclid", "msclkid", "ttclid", "twclid", "dclid", "wbraid", "gbraid",
            "_ga", "_gid", "_gat", "yclid", "mc_eid", "ajs_user_id", "ajs_anonymous_id",
            "distinct_id", "device_id", "advertising_id", "ad_id", "session_id", "track_id",
            "sp_rid", "sp_mid", "wickedid", "irclickid"
    )));

    // Query parameters that may inadvertently leak sensitive credentials
    private static final Set<String> SENSITIVE_PARAM_KEYS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "password", "pass", "pwd", "token", "access_token", "auth_token", "refresh_token",
            "api_key", "apikey", "secret", "client_secret", "private_key", "bearer", "session_token"
    )));

    // Known tracker and telemetry domains
    private static final Map<String, String> TRACKER_DOMAINS = new LinkedHashMap<>();
    static {
        TRACKER_DOMAINS.put("google-analytics.com", "Google Analytics (Telemetry)");
        TRACKER_DOMAINS.put("analytics.google.com", "Google Analytics (Telemetry)");
        TRACKER_DOMAINS.put("doubleclick.net", "Google DoubleClick (Ad Network)");
        TRACKER_DOMAINS.put("googlesyndication.com", "Google Ads (Advertising)");
        TRACKER_DOMAINS.put("appsflyer.com", "AppsFlyer (Mobile Tracking)");
        TRACKER_DOMAINS.put("branch.io", "Branch (Deep Linking / Attribution)");
        TRACKER_DOMAINS.put("adjust.com", "Adjust (Attribution / Telemetry)");
        TRACKER_DOMAINS.put("kochava.com", "Kochava (Ad Attribution)");
        TRACKER_DOMAINS.put("flurry.com", "Yahoo Flurry (Analytics)");
        TRACKER_DOMAINS.put("crashlytics.com", "Firebase Crashlytics");
        TRACKER_DOMAINS.put("facebook.com/tr", "Meta Pixel (Tracking)");
        TRACKER_DOMAINS.put("graph.facebook.com", "Meta Graph API (Analytics)");
        TRACKER_DOMAINS.put("amplitude.com", "Amplitude (User Tracking)");
        TRACKER_DOMAINS.put("mixpanel.com", "Mixpanel (Behavioral Analytics)");
        TRACKER_DOMAINS.put("segment.io", "Segment (Customer Data Platform)");
        TRACKER_DOMAINS.put("sentry.io", "Sentry (Error Telemetry)");
        TRACKER_DOMAINS.put("app-measurement.com", "Firebase App Measurement");
        TRACKER_DOMAINS.put("criteo.com", "Criteo (Ad Retargeting)");
        TRACKER_DOMAINS.put("scorecardresearch.com", "Comscore (Web Tracking)");
    }

    private static final Pattern IP_PATTERN = Pattern.compile(
            "^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$"
    );

    private static final Pattern SQLI_PATTERN = Pattern.compile(
            "(?i)(\\bunion\\s+all\\s+select\\b|\\bunion\\s+select\\b|'\\s*or\\s*['\"\\d\\s]+=\\s*['\"\\d]|'\\s*or\\s*1\\s*=\\s*1|--\\s*$|/\\*.*?\\*/|\\bdrop\\s+table\\b|\\bexec(\\s|\\+)+(s|x)p_|\\bselect\\s+@@version\\b|\\bbenchmark\\s*\\(\\s*\\d+|\\bsleep\\s*\\(\\s*\\d+)"
    );

    private static final Pattern XSS_PATTERN = Pattern.compile(
            "(?i)(<script[\\s>]|javascript:\\s*\\w|vbscript:\\s*\\w|data:text/html;base64|\\bonload\\s*=\\s*[\"']?|\\bonerror\\s*=\\s*[\"']?|\\bdocument\\.cookie\\b|<svg[\\s>].*?\\bonload)",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile(
            "(\\.\\./\\.\\.|\\.\\.\\\\|%2e%2e%2f|%2e%2e/|%252e%252e|/etc/passwd|/windows/win\\.ini)",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern RCE_PATTERN = Pattern.compile(
            "(?i)(;\\s*(rm\\s+-rf|cat\\s+/etc|whoami|id|bash\\s+-i|sh\\s+-i|curl\\s+http|wget\\s+http|powershell\\s+-e)\\b|\\|\\s*(rm\\s+-rf|cat\\s+/etc|whoami|id|bash\\s+-i|sh\\s+-i|curl\\s+http|wget\\s+http|powershell\\s+-e)\\b|`\\s*(whoami|id|cat\\s+/etc|curl|wget)\\s*`)"
    );

    private static final Pattern DANGEROUS_DOWNLOAD_EXT = Pattern.compile(
            ".*\\.(apk|exe|dex|scr|bat|cmd|vbs|ps1|msi)$",
            Pattern.CASE_INSENSITIVE
    );

    public enum RiskLevel {
        SAFE("SAFE", 0xFF2E7D32),             // Green
        INFORMATIONAL("INFO", 0xFF0288D1),    // Blue
        SUSPICIOUS("SUSPICIOUS", 0xFFF57C00), // Orange
        HIGH_RISK("HIGH RISK", 0xFFD32F2F);   // Red

        public final String label;
        public final int color;

        RiskLevel(String label, int color) {
            this.label = label;
            this.color = color;
        }
    }

    /**
     * Decomposed and parsed URL components.
     */
    public static class ParsedUrl {
        public final String rawUrl;
        public final String scheme;
        public final String host;
        public final int port;
        public final String portService;
        public final boolean isIpLiteral;
        public final String path;
        public final List<String> pathSegments;
        public final Map<String, String> queryParameters;
        public final Map<String, String> trackingParameters;
        public final Map<String, String> sensitiveParameters;
        public final String fragment;
        public final SecurityRiskAssessment riskAssessment;

        public ParsedUrl(String rawUrl, String scheme, String host, int port, String portService,
                         boolean isIpLiteral, String path, List<String> pathSegments,
                         Map<String, String> queryParameters, Map<String, String> trackingParameters,
                         Map<String, String> sensitiveParameters, String fragment,
                         SecurityRiskAssessment riskAssessment) {
            this.rawUrl = rawUrl;
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.portService = portService;
            this.isIpLiteral = isIpLiteral;
            this.path = path;
            this.pathSegments = pathSegments;
            this.queryParameters = queryParameters;
            this.trackingParameters = trackingParameters;
            this.sensitiveParameters = sensitiveParameters;
            this.fragment = fragment;
            this.riskAssessment = riskAssessment;
        }

        public boolean hasTrackingParams() {
            return trackingParameters != null && !trackingParameters.isEmpty();
        }

        public boolean hasSensitiveParams() {
            return sensitiveParameters != null && !sensitiveParameters.isEmpty();
        }

        public int getQueryParamCount() {
            return queryParameters != null ? queryParameters.size() : 0;
        }
    }

    /**
     * Security risk rating and explanation flags.
     */
    public static class SecurityRiskAssessment {
        public final RiskLevel riskLevel;
        public final int riskScore; // 0 - 100
        public final List<String> riskFlags;
        public final boolean isKnownTracker;
        public final String trackerDescription;

        public SecurityRiskAssessment(RiskLevel riskLevel, int riskScore, List<String> riskFlags,
                                      boolean isKnownTracker, String trackerDescription) {
            this.riskLevel = riskLevel;
            this.riskScore = Math.max(0, Math.min(100, riskScore));
            this.riskFlags = riskFlags != null ? riskFlags : new ArrayList<>();
            this.isKnownTracker = isKnownTracker;
            this.trackerDescription = trackerDescription;
        }
    }

    /**
     * Parsed User-Agent metadata.
     */
    public static class UserAgentInfo {
        public final String rawUserAgent;
        public final String browserName;
        public final String browserVersion;
        public final String operatingSystem;
        public final String engine;

        public UserAgentInfo(String rawUserAgent, String browserName, String browserVersion,
                             String operatingSystem, String engine) {
            this.rawUserAgent = rawUserAgent;
            this.browserName = browserName;
            this.browserVersion = browserVersion;
            this.operatingSystem = operatingSystem;
            this.engine = engine;
        }

        @Override
        public String toString() {
            return browserName + " " + browserVersion + " on " + operatingSystem + " (" + engine + ")";
        }
    }

    /**
     * Parsed HTTP status code information.
     */
    public static class ParsedHttpStatus {
        public final int code;
        public final String category;
        public final String reasonPhrase;
        public final String description;
        public final int badgeColor;

        public ParsedHttpStatus(int code, String category, String reasonPhrase, String description, int badgeColor) {
            this.code = code;
            this.category = category;
            this.reasonPhrase = reasonPhrase;
            this.description = description;
            this.badgeColor = badgeColor;
        }

        public String getFormatted() {
            return code + " " + reasonPhrase;
        }
    }

    /**
     * Parsed payload details (JSON, Form-data, or Hex/ASCII dump).
     */
    public static class ParsedPayload {
        public final boolean isJson;
        public final String formattedJson;
        public final boolean isFormEncoded;
        public final Map<String, String> formFields;
        public final String hexAsciiDump;
        public final String textPreview;

        public ParsedPayload(boolean isJson, String formattedJson, boolean isFormEncoded,
                             Map<String, String> formFields, String hexAsciiDump, String textPreview) {
            this.isJson = isJson;
            this.formattedJson = formattedJson;
            this.isFormEncoded = isFormEncoded;
            this.formFields = formFields;
            this.hexAsciiDump = hexAsciiDump;
            this.textPreview = textPreview;
        }
    }

    /**
     * Parse and decompose any URL or raw host into structured components with security assessment.
     */
    @NonNull
    public static ParsedUrl parseUrl(@Nullable String rawUrl) {
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            return new ParsedUrl("", "https", "", 443, "HTTPS", false, "/",
                    Collections.emptyList(), Collections.emptyMap(), Collections.emptyMap(),
                    Collections.emptyMap(), "",
                    new SecurityRiskAssessment(RiskLevel.SAFE, 0, Collections.emptyList(), false, null));
        }

        String input = rawUrl.trim();
        if (!input.contains("://")) {
            input = "https://" + input;
        }

        Uri uri = null;
        try {
            uri = Uri.parse(input);
        } catch (Exception ignored) {}

        String scheme = "https";
        String host = "";
        int port = -1;
        String path = "/";
        List<String> pathSegments = new ArrayList<>();
        String query = "";
        String fragment = "";

        if (uri != null && uri.getScheme() != null) {
            scheme = uri.getScheme().toLowerCase(Locale.US);
            host = uri.getHost() != null ? uri.getHost().toLowerCase(Locale.US) : "";
            port = uri.getPort();
            path = uri.getPath() != null && !uri.getPath().isEmpty() ? uri.getPath() : "/";
            if (uri.getPathSegments() != null) {
                pathSegments.addAll(uri.getPathSegments());
            }
            query = uri.getQuery() != null ? uri.getQuery() : "";
            fragment = uri.getFragment() != null ? uri.getFragment() : "";
        } else {
            try {
                java.net.URI javaUri = new java.net.URI(input);
                if (javaUri.getScheme() != null) scheme = javaUri.getScheme().toLowerCase(Locale.US);
                if (javaUri.getHost() != null) host = javaUri.getHost().toLowerCase(Locale.US);
                port = javaUri.getPort();
                if (javaUri.getPath() != null && !javaUri.getPath().isEmpty()) {
                    path = javaUri.getPath();
                    String[] segs = path.split("/");
                    for (String s : segs) {
                        if (!s.isEmpty()) pathSegments.add(s);
                    }
                }
                if (javaUri.getQuery() != null) query = javaUri.getQuery();
                if (javaUri.getFragment() != null) fragment = javaUri.getFragment();
            } catch (Exception ignored) {}
        }

        if (port <= 0) {
            port = "http".equalsIgnoreCase(scheme) ? 80 : 443;
        }

        String portService = resolvePortService(port);
        boolean isIpLiteral = isIpAddress(host);

        Map<String, String> queryParams = new LinkedHashMap<>();
        Map<String, String> trackingParams = new LinkedHashMap<>();
        Map<String, String> sensitiveParams = new LinkedHashMap<>();

        try {
            if (!query.isEmpty()) {
                String[] pairs = query.split("&");
                for (String pair : pairs) {
                    if (pair.isEmpty()) continue;
                    int idx = pair.indexOf("=");
                    String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), "UTF-8") : pair;
                    String value = (idx > 0 && pair.length() > idx + 1) ? URLDecoder.decode(pair.substring(idx + 1), "UTF-8") : "";

                    queryParams.put(key, value);
                    String lowerKey = key.toLowerCase(Locale.US);

                    if (TRACKING_KEYS.contains(lowerKey) || lowerKey.startsWith("utm_")) {
                        trackingParams.put(key, value);
                    }
                    if (SENSITIVE_PARAM_KEYS.contains(lowerKey)) {
                        sensitiveParams.put(key, value);
                    }
                }
            }
        } catch (Exception ignored) {}

        // Perform security risk evaluation
        SecurityRiskAssessment riskAssessment = evaluateSecurityRisk(host, scheme, port, isIpLiteral, path, rawUrl, queryParams, trackingParams, sensitiveParams);

        return new ParsedUrl(rawUrl, scheme, host, port, portService, isIpLiteral, path,
                pathSegments, queryParams, trackingParams, sensitiveParams, fragment, riskAssessment);
    }

    /**
     * Evaluates comprehensive security risk factors of a network request.
     * Only flags URLs as SUSPICIOUS or HIGH_RISK when confirmed malicious or suspicious activity is detected.
     */
    @NonNull
    public static SecurityRiskAssessment evaluateSecurityRisk(String host, String scheme, int port,
                                                              boolean isIpLiteral,
                                                              Map<String, String> queryParams,
                                                              Map<String, String> trackingParams,
                                                              Map<String, String> sensitiveParams) {
        return evaluateSecurityRisk(host, scheme, port, isIpLiteral, "/", "", queryParams, trackingParams, sensitiveParams);
    }

    /**
     * Evaluates comprehensive security risk factors with deep path and URL inspection.
     * Direct IPs, standard cleartext HTTP, and marketing query parameters are NOT treated as suspicious
     * unless confirmed malicious payloads, attacks, or threat intel indicators are detected.
     */
    @NonNull
    public static SecurityRiskAssessment evaluateSecurityRisk(String host, String scheme, int port,
                                                              boolean isIpLiteral,
                                                              String path,
                                                              String rawUrl,
                                                              Map<String, String> queryParams,
                                                              Map<String, String> trackingParams,
                                                              Map<String, String> sensitiveParams) {
        List<String> flags = new ArrayList<>();
        int score = 0;
        boolean isKnownTracker = false;
        String trackerDesc = null;

        String safeHost = host != null ? host.trim().toLowerCase(Locale.US) : "";
        String safePath = path != null ? path : "/";
        String safeRawUrl = rawUrl != null ? rawUrl : "";

        // Known tracker/ad detection (strictly informational attribution, NOT a security threat)
        for (Map.Entry<String, String> entry : TRACKER_DOMAINS.entrySet()) {
            if (safeHost.contains(entry.getKey())) {
                isKnownTracker = true;
                trackerDesc = entry.getValue();
                break;
            }
        }

        // Check if endpoint is known official, trusted, or CDN infrastructure
        boolean isTrustedEndpoint = com.kotsafe.security.model.SecurityBlocklistManager.isOfficialOrTrustedDomain(safeHost)
                || com.kotsafe.security.model.SecurityBlocklistManager.isSpeedTestOrDiagnosticDomain(safeHost)
                || com.kotsafe.security.model.SecurityBlocklistManager.isCloudflareCdnIp(safeHost)
                || com.kotsafe.security.model.SecurityBlocklistManager.isGoogleIp(safeHost)
                || com.kotsafe.security.model.SecurityBlocklistManager.isMetaWhatsAppIp(safeHost)
                || com.kotsafe.security.model.SecurityBlocklistManager.isLocalOrConnectedDeviceIp(safeHost);

        if (!isTrustedEndpoint) {
            // 1. Confirmed Malware C2 Endpoint match
            if (com.kotsafe.security.model.SecurityBlocklistManager.isKnownMalwareC2(safeHost)) {
                flags.add("Confirmed Malware Command & Control Endpoint (Threat Intelligence Match)");
                score = Math.max(score, 95);
            }

            // 2. Exploit / Attack Injections in Path, Query, or Full URL
            String decodedUrl = safeRawUrl;
            try {
                decodedUrl = URLDecoder.decode(safeRawUrl, "UTF-8");
            } catch (Exception ignored) {}
            String fullTargetForAnalysis = safeRawUrl + " " + decodedUrl + " " + safePath + " " + queryParams.toString();

            // SQL Injection
            if (SQLI_PATTERN.matcher(fullTargetForAnalysis).find()) {
                flags.add("Confirmed SQL Injection attack pattern detected in request");
                score = Math.max(score, 90);
            }

            // Cross-Site Scripting (XSS)
            if (XSS_PATTERN.matcher(fullTargetForAnalysis).find()) {
                flags.add("Confirmed Cross-Site Scripting (XSS) attack vector detected in request");
                score = Math.max(score, 90);
            }

            // Path Traversal / Arbitrary File Inclusion
            if (PATH_TRAVERSAL_PATTERN.matcher(fullTargetForAnalysis).find()) {
                flags.add("Confirmed Directory Traversal / Arbitrary File Access attempt");
                score = Math.max(score, 90);
            }

            // Remote Command Execution (RCE)
            if (RCE_PATTERN.matcher(fullTargetForAnalysis).find()) {
                flags.add("Confirmed OS Command Injection payload detected");
                score = Math.max(score, 90);
            }

            // 3. Unverified Executable/Package Download from untrusted origin
            if (DANGEROUS_DOWNLOAD_EXT.matcher(safePath).matches()) {
                flags.add("Direct unverified executable/package download (.apk/.exe) from untrusted host");
                score = Math.max(score, 75);
            }

            // 4. Base64 URL redirect to confirmed malware C2 or hidden executable payloads
            for (Map.Entry<String, String> entry : queryParams.entrySet()) {
                String val = entry.getValue();
                if (val != null && val.length() > 20 && isBase64(val)) {
                    try {
                        String decoded = new String(Base64.decode(val, Base64.DEFAULT), StandardCharsets.UTF_8);
                        if (decoded.contains("http://") || decoded.contains("https://")) {
                            String decodedHost = Uri.parse(decoded).getHost();
                            if (decodedHost != null && com.kotsafe.security.model.SecurityBlocklistManager.isKnownMalwareC2(decodedHost)) {
                                flags.add("Malicious redirection to confirmed C2 concealed in Base64 parameter '" + entry.getKey() + "'");
                                score = Math.max(score, 95);
                                break;
                            }
                        } else if (decoded.contains("/bin/sh") || decoded.contains("cmd.exe") || decoded.startsWith("PK\u0003\u0004")) {
                            flags.add("Concealed executable payload found in Base64 parameter '" + entry.getKey() + "'");
                            score = Math.max(score, 90);
                            break;
                        }
                    } catch (Exception ignored) {}
                }
            }

            // 5. Plaintext credentials transmitted over unencrypted cleartext HTTP
            if ("http".equalsIgnoreCase(scheme) && port == 80 && !sensitiveParams.isEmpty()) {
                flags.add("Sensitive credentials/tokens exposed over unencrypted cleartext HTTP (" + String.join(", ", sensitiveParams.keySet()) + ")");
                score = Math.max(score, 70);
            }
        }

        // STRICT RISK THRESHOLD:
        // Only classify as SUSPICIOUS or HIGH_RISK if confirmed suspicious activity was actually detected!
        RiskLevel level;
        if (score >= 85) {
            level = RiskLevel.HIGH_RISK;
        } else if (score >= 60) {
            level = RiskLevel.SUSPICIOUS;
        } else {
            level = RiskLevel.SAFE;
        }

        return new SecurityRiskAssessment(level, score, flags, isKnownTracker, trackerDesc);
    }

    /**
     * Parses User-Agent header string to extract human-readable client, version, OS, and rendering engine.
     */
    @NonNull
    public static UserAgentInfo parseUserAgent(@Nullable String ua) {
        if (ua == null || ua.trim().isEmpty()) {
            return new UserAgentInfo("", "Unknown Client", "", "Unknown OS", "Unknown Engine");
        }

        String browserName = "Unknown Browser";
        String browserVersion = "";
        String os = "Unknown OS";
        String engine = "Generic";

        String lower = ua.toLowerCase(Locale.US);

        // Detect OS
        if (lower.contains("android")) {
            Matcher m = Pattern.compile("Android\\s+([0-9.]+)").matcher(ua);
            os = m.find() ? "Android " + m.group(1) : "Android";
        } else if (lower.contains("iphone") || lower.contains("ipad")) {
            os = "iOS";
        } else if (lower.contains("windows")) {
            os = "Windows";
        } else if (lower.contains("mac os x")) {
            os = "macOS";
        } else if (lower.contains("linux")) {
            os = "Linux";
        }

        // Detect Browser
        if (lower.contains("chrome") && !lower.contains("edg") && !lower.contains("opr") && !lower.contains("brave")) {
            browserName = "Google Chrome";
            Matcher m = Pattern.compile("Chrome/([0-9.]+)").matcher(ua);
            if (m.find()) browserVersion = m.group(1);
        } else if (lower.contains("firefox") || lower.contains("fenix")) {
            browserName = "Mozilla Firefox";
            Matcher m = Pattern.compile("Firefox/([0-9.]+)").matcher(ua);
            if (m.find()) browserVersion = m.group(1);
        } else if (lower.contains("edg")) {
            browserName = "Microsoft Edge";
            Matcher m = Pattern.compile("Edg[A-Za-z]*/([0-9.]+)").matcher(ua);
            if (m.find()) browserVersion = m.group(1);
        } else if (lower.contains("brave")) {
            browserName = "Brave Browser";
        } else if (lower.contains("samsungbrowser")) {
            browserName = "Samsung Internet";
            Matcher m = Pattern.compile("SamsungBrowser/([0-9.]+)").matcher(ua);
            if (m.find()) browserVersion = m.group(1);
        } else if (lower.contains("opera") || lower.contains("opr")) {
            browserName = "Opera Browser";
            Matcher m = Pattern.compile("OPR/([0-9.]+)").matcher(ua);
            if (m.find()) browserVersion = m.group(1);
        } else if (lower.contains("safari") && !lower.contains("chrome")) {
            browserName = "Apple Safari";
            Matcher m = Pattern.compile("Version/([0-9.]+)").matcher(ua);
            if (m.find()) browserVersion = m.group(1);
        } else if (lower.contains("dalvik")) {
            browserName = "Android Dalvik VM";
        } else if (lower.contains("curl")) {
            browserName = "cURL Tool";
        }

        // Engine
        if (lower.contains("applewebkit")) {
            engine = "WebKit / Blink";
        } else if (lower.contains("gecko")) {
            engine = "Gecko";
        }

        return new UserAgentInfo(ua, browserName, browserVersion, os, engine);
    }

    /**
     * Parses HTTP Status Codes and provides semantic details.
     */
    @NonNull
    public static ParsedHttpStatus parseHttpStatus(int code) {
        if (code <= 0) {
            return new ParsedHttpStatus(200, "Success", "OK", "Standard successful HTTP response", 0xFF2E7D32);
        }

        String cat;
        String reason;
        String desc;
        int color;

        if (code >= 100 && code < 200) {
            cat = "Informational";
            reason = "Continue";
            desc = "Interim response before processing complete";
            color = 0xFF0288D1;
        } else if (code >= 200 && code < 300) {
            cat = "Success";
            switch (code) {
                case 200: reason = "OK"; desc = "Request succeeded normally"; break;
                case 201: reason = "Created"; desc = "Resource created successfully"; break;
                case 204: reason = "No Content"; desc = "Request fulfilled, no body returned"; break;
                default: reason = "Successful"; desc = "Request fulfilled successfully"; break;
            }
            color = 0xFF2E7D32; // Green
        } else if (code >= 300 && code < 400) {
            cat = "Redirection";
            switch (code) {
                case 301: reason = "Moved Permanently"; desc = "Resource moved permanently to new URL"; break;
                case 302: reason = "Found (Redirect)"; desc = "Resource temporarily located at another URL"; break;
                case 304: reason = "Not Modified"; desc = "Cached copy matches origin server"; break;
                case 307: reason = "Temporary Redirect"; desc = "Repeat request with same method at another URL"; break;
                case 308: reason = "Permanent Redirect"; desc = "Permanent redirect preserving HTTP method"; break;
                default: reason = "Redirect"; desc = "Further action required to complete request"; break;
            }
            color = 0xFF1976D2; // Blue
        } else if (code >= 400 && code < 500) {
            cat = "Client Error";
            switch (code) {
                case 400: reason = "Bad Request"; desc = "Malformed request syntax or invalid framing"; break;
                case 401: reason = "Unauthorized"; desc = "Authentication required or credentials invalid"; break;
                case 403: reason = "Forbidden"; desc = "Server understood request but refused authorization"; break;
                case 404: reason = "Not Found"; desc = "Requested resource does not exist on origin server"; break;
                case 405: reason = "Method Not Allowed"; desc = "HTTP method not supported for target resource"; break;
                case 429: reason = "Too Many Requests"; desc = "Rate limit exceeded; request throttled"; break;
                default: reason = "Client Error"; desc = "Client sent an invalid or unacceptable request"; break;
            }
            color = 0xFFF57C00; // Orange
        } else {
            cat = "Server Error";
            switch (code) {
                case 500: reason = "Internal Server Error"; desc = "Server encountered unexpected error"; break;
                case 502: reason = "Bad Gateway"; desc = "Invalid response from upstream server"; break;
                case 503: reason = "Service Unavailable"; desc = "Server currently overloaded or down for maintenance"; break;
                case 504: reason = "Gateway Timeout"; desc = "Upstream server timed out"; break;
                default: reason = "Server Error"; desc = "Server failed to fulfill an apparently valid request"; break;
            }
            color = 0xFFD32F2F; // Red
        }

        return new ParsedHttpStatus(code, cat, reason, desc, color);
    }

    /**
     * Parses byte payload into pretty JSON, Form-data key-values, or formatted Hex+ASCII dump.
     */
    @NonNull
    public static ParsedPayload parsePayload(@Nullable byte[] data) {
        if (data == null || data.length == 0) {
            return new ParsedPayload(false, null, false, Collections.emptyMap(),
                    "<Empty Payload>", "<Empty Payload>");
        }

        String rawText = new String(data, StandardCharsets.UTF_8);
        String textPreview = rawText.length() > 500 ? rawText.substring(0, 500) + "..." : rawText;

        // Try JSON parsing
        boolean isJson = false;
        String formattedJson = null;
        String trimmed = rawText.trim();
        if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
            try {
                JsonElement elem = JsonParser.parseString(trimmed);
                formattedJson = GSON_PRETTY.toJson(elem);
                isJson = true;
            } catch (Exception ignored) {}
        }

        // Try Form-data parsing
        boolean isForm = false;
        Map<String, String> formFields = new LinkedHashMap<>();
        if (!isJson && trimmed.contains("=") && (trimmed.contains("&") || !trimmed.contains(" "))) {
            try {
                String[] pairs = trimmed.split("&");
                for (String p : pairs) {
                    int eq = p.indexOf("=");
                    if (eq > 0) {
                        String k = URLDecoder.decode(p.substring(0, eq), "UTF-8");
                        String v = p.length() > eq + 1 ? URLDecoder.decode(p.substring(eq + 1), "UTF-8") : "";
                        formFields.put(k, v);
                    }
                }
                if (!formFields.isEmpty()) isForm = true;
            } catch (Exception ignored) {}
        }

        // Generate Hex + ASCII dump
        String hexDump = formatHexAsciiDump(data, 128);

        return new ParsedPayload(isJson, formattedJson, isForm, formFields, hexDump, textPreview);
    }

    /**
     * Formats bytes into standard hex editor view (Offset | Hex bytes | ASCII representation).
     */
    public static String formatHexAsciiDump(@NonNull byte[] data, int maxBytes) {
        int length = Math.min(data.length, maxBytes);
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < length; i += 16) {
            // Offset
            sb.append(String.format(Locale.US, "%04X  ", i));

            // Hex values
            for (int j = 0; j < 16; j++) {
                if (i + j < length) {
                    sb.append(String.format(Locale.US, "%02X ", data[i + j]));
                } else {
                    sb.append("   ");
                }
                if (j == 7) sb.append(" ");
            }

            sb.append(" ");

            // ASCII printable values
            for (int j = 0; j < 16 && (i + j) < length; j++) {
                byte b = data[i + j];
                if (b >= 32 && b <= 126) {
                    sb.append((char) b);
                } else {
                    sb.append(".");
                }
            }
            sb.append("\n");
        }

        if (data.length > length) {
            sb.append(String.format(Locale.US, "... [%d more payload bytes not shown]", data.length - length));
        }

        return sb.toString().trim();
    }

    public static String resolvePortService(int port) {
        switch (port) {
            case 80: return "HTTP";
            case 443: return "HTTPS";
            case 53: return "DNS";
            case 853: return "DoT";
            case 8080: return "HTTP-Proxy";
            case 8443: return "HTTPS-Alt";
            case 8088: return "NetP-Block";
            default: return "Port " + port;
        }
    }

    private static String extractTld(String host) {
        if (host == null || host.isEmpty() || isIpAddress(host)) return "";
        int dot = host.lastIndexOf('.');
        if (dot >= 0 && dot < host.length() - 1) {
            return host.substring(dot + 1).toLowerCase(Locale.US);
        }
        return "";
    }

    private static boolean isIpAddress(String host) {
        return host != null && IP_PATTERN.matcher(host).matches();
    }

    private static boolean isBase64(String str) {
        if (str == null || str.length() % 4 != 0) return false;
        return str.matches("^[A-Za-z0-9+/]+={0,2}$");
    }
}
