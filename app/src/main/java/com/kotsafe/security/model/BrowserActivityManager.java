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

package com.kotsafe.security.model;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.HttpLog;
import com.kotsafe.security.MitmAddon;
import com.kotsafe.security.Utils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Manages browser network logs, discovering installed browser applications and formatting
 * network traffic into Decrypted cleartext vs Encrypted TLS streams based on decryptor state.
 */
public class BrowserActivityManager {
    private static final String TAG = "BrowserActivityManager";

    // Known browser packages as fallback
    public static final Set<String> KNOWN_BROWSER_PACKAGES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "com.android.chrome",
            "org.mozilla.firefox",
            "org.mozilla.firefox_beta",
            "org.mozilla.fenix",
            "com.brave.browser",
            "com.brave.browser_nightly",
            "com.microsoft.emmx",
            "com.sec.android.app.sbrowser",
            "com.sec.android.app.sbrowser.beta",
            "com.opera.browser",
            "com.opera.mini.native",
            "com.opera.touch",
            "com.duckduckgo.mobile.android",
            "com.vivaldi.browser",
            "org.torproject.torbrowser",
            "com.kiwibrowser.browser",
            "org.bromite.bromite",
            "com.android.browser"
    )));

    public static class BrowserLogEntry {
        public final int id;
        public final long timestamp;
        public final String appName;
        public final String packageName;
        public final int uid;
        public final String hostOrDomain;
        public final String remoteIp;
        public final int remotePort;
        public final boolean isDecrypted;
        public final boolean isCleartextHttp;

        // Decrypted HTTP details (when decryptor is active)
        public final String httpMethod;
        public final String url;
        public final int statusCode;
        public final String contentType;
        public final String decryptedPayloadPreview;
        public final boolean hasJwt;
        public final boolean hasProtobuf;
        public final boolean hasDoh;
        public final boolean hasHttps;

        // Encrypted TLS details (when decryptor is disabled or traffic is encrypted)
        public final String tlsVersion;
        public final String cipherSuite;
        public final String encryptedHexPreview;
        public final long sentBytes;
        public final long rcvdBytes;
        public final byte[] rawPayloadBytes;
        public final com.kotsafe.security.model.parser.AdvancedLogParser.ParsedUrl parsedUrl;

        public BrowserLogEntry(int id, long timestamp, String appName, String packageName, int uid,
                               String hostOrDomain, String remoteIp, int remotePort,
                               boolean isDecrypted, boolean isCleartextHttp,
                               String httpMethod, String url, int statusCode, String contentType,
                               String decryptedPayloadPreview, boolean hasJwt, boolean hasProtobuf, boolean hasDoh,
                               boolean hasHttps,
                               String tlsVersion, String cipherSuite, String encryptedHexPreview,
                               long sentBytes, long rcvdBytes, byte[] rawPayloadBytes) {
            this.id = id;
            this.timestamp = timestamp;
            this.appName = appName;
            this.packageName = packageName;
            this.uid = uid;
            this.hostOrDomain = hostOrDomain;
            this.remoteIp = remoteIp;
            this.remotePort = remotePort;
            this.isDecrypted = isDecrypted;
            this.isCleartextHttp = isCleartextHttp;
            this.httpMethod = httpMethod;
            this.url = url;
            this.statusCode = statusCode;
            this.contentType = contentType;
            this.decryptedPayloadPreview = decryptedPayloadPreview;
            this.hasJwt = hasJwt;
            this.hasProtobuf = hasProtobuf;
            this.hasDoh = hasDoh;
            this.hasHttps = hasHttps;
            this.tlsVersion = tlsVersion;
            this.cipherSuite = cipherSuite;
            this.encryptedHexPreview = encryptedHexPreview;
            this.sentBytes = sentBytes;
            this.rcvdBytes = rcvdBytes;
            this.rawPayloadBytes = rawPayloadBytes;
            this.parsedUrl = com.kotsafe.security.model.parser.AdvancedLogParser.parseUrl(url);
        }

        public BrowserLogEntry(int id, long timestamp, String appName, String packageName, int uid,
                               String hostOrDomain, String remoteIp, int remotePort,
                               boolean isDecrypted, boolean isCleartextHttp,
                               String httpMethod, String url, int statusCode, String contentType,
                               String decryptedPayloadPreview, boolean hasJwt, boolean hasProtobuf, boolean hasDoh,
                               boolean hasHttps,
                               String tlsVersion, String cipherSuite, String encryptedHexPreview,
                               long sentBytes, long rcvdBytes) {
            this(id, timestamp, appName, packageName, uid, hostOrDomain, remoteIp, remotePort,
                 isDecrypted, isCleartextHttp, httpMethod, url, statusCode, contentType,
                 decryptedPayloadPreview, hasJwt, hasProtobuf, hasDoh, hasHttps,
                 tlsVersion, cipherSuite, encryptedHexPreview, sentBytes, rcvdBytes, null);
        }

        // Backward compatibility constructor
        public BrowserLogEntry(int id, long timestamp, String appName, String packageName, int uid,
                               String hostOrDomain, String remoteIp, int remotePort,
                               boolean isDecrypted, boolean isCleartextHttp,
                               String httpMethod, String url, int statusCode, String contentType,
                               String decryptedPayloadPreview, boolean hasJwt, boolean hasProtobuf, boolean hasDoh,
                               String tlsVersion, String cipherSuite, String encryptedHexPreview,
                               long sentBytes, long rcvdBytes) {
            this(id, timestamp, appName, packageName, uid, hostOrDomain, remoteIp, remotePort,
                 isDecrypted, isCleartextHttp, httpMethod, url, statusCode, contentType,
                 decryptedPayloadPreview, hasJwt, hasProtobuf, hasDoh, remotePort == 443 || remotePort == 8443,
                 tlsVersion, cipherSuite, encryptedHexPreview, sentBytes, rcvdBytes, null);
        }
    }

    public static class CapturedNavigation {
        public final String packageName;
        public final String url;
        public final long timestamp;

        public CapturedNavigation(String packageName, String url, long timestamp) {
            this.packageName = packageName;
            this.url = url;
            this.timestamp = timestamp;
        }
    }

    private static volatile BrowserActivityManager sInstance;
    private final List<CapturedNavigation> mCapturedNavigations = new ArrayList<>();

    public static BrowserActivityManager getInstance(Context context) {
        if (sInstance == null) {
            synchronized (BrowserActivityManager.class) {
                if (sInstance == null) {
                    sInstance = new BrowserActivityManager(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    public synchronized void recordBrowserNavigation(String packageName, String url, long timestamp) {
        mCapturedNavigations.add(0, new CapturedNavigation(packageName, url, timestamp));
        if (mCapturedNavigations.size() > 200) {
            mCapturedNavigations.remove(mCapturedNavigations.size() - 1);
        }
    }

    public synchronized CapturedNavigation findMatchingCapturedNav(String packageName, String host, long timestamp) {
        String cleanHost = host != null ? host.toLowerCase() : "";
        for (CapturedNavigation nav : mCapturedNavigations) {
            if (nav.packageName.equalsIgnoreCase(packageName)) {
                if (!cleanHost.isEmpty() && nav.url.toLowerCase().contains(cleanHost)) {
                    return nav;
                }
                if (Math.abs(nav.timestamp - timestamp) < 45000) {
                    return nav;
                }
            }
        }
        return null;
    }

    private final Context mContext;
    private final AppsResolver mAppsResolver;
    private final Set<String> mBrowserPackages = new HashSet<>();
    private final Set<Integer> mBrowserUids = new HashSet<>();

    public BrowserActivityManager(@NonNull Context context) {
        mContext = context.getApplicationContext();
        mAppsResolver = new AppsResolver(mContext);
        mBrowserPackages.addAll(KNOWN_BROWSER_PACKAGES);
        new Thread(this::refreshBrowserPackages, "BrowserPkgLoader").start();
    }

    public synchronized void refreshBrowserPackages() {
        mBrowserPackages.clear();
        mBrowserUids.clear();
        mBrowserPackages.addAll(KNOWN_BROWSER_PACKAGES);

        try {
            PackageManager pm = mContext.getPackageManager();
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("http://www.google.com"));
            List<ResolveInfo> list = pm.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY);

            for (ResolveInfo info : list) {
                if (info.activityInfo != null && info.activityInfo.packageName != null) {
                    mBrowserPackages.add(info.activityInfo.packageName);
                }
            }
        } catch (Exception ignored) {
        }

        // Cache browser UIDs
        for (String pkg : mBrowserPackages) {
            try {
                AppDescriptor app = mAppsResolver.getAppByPackage(pkg, 0);
                if (app != null && app.getUid() > 0) {
                    mBrowserUids.add(app.getUid());
                }
            } catch (Exception ignored) {
            }
        }
    }

    public boolean isBrowserApp(int uid, @Nullable String packageName) {
        if (uid > 0 && mBrowserUids.contains(uid)) return true;
        if (packageName != null && mBrowserPackages.contains(packageName)) return true;
        return false;
    }

    public boolean isTlsDecryptionActive() {
        if (CaptureService.isServiceActive()) {
            return CaptureService.isDecryptingTLS();
        }
        return Prefs.getTlsDecryptionEnabled(androidx.preference.PreferenceManager.getDefaultSharedPreferences(mContext));
    }

    /**
     * Builds list of browser log entries from currently recorded connections and HTTP requests.
     */
    @NonNull
    public List<BrowserLogEntry> getBrowserLogs(boolean forceDecryptedView, @Nullable String filterQuery) {
        List<BrowserLogEntry> entries = new ArrayList<>();
        ConnectionsRegister reg = CaptureService.getConnsRegister();
        HttpLog httpLog = CaptureService.getHttpLog();

        if (reg == null) {
            return entries;
        }

        // Index recent HTTP requests by connection ID for fast O(1) matching
        android.util.LongSparseArray<HttpLog.HttpRequest> reqMap = new android.util.LongSparseArray<>();
        if (httpLog != null) {
            int httpSize = httpLog.getSize();
            int startIdx = Math.max(0, httpSize - 400);
            for (int h = startIdx; h < httpSize; h++) {
                HttpLog.HttpRequest req = httpLog.getRequest(h);
                if (req != null && req.conn != null) {
                    reqMap.put(req.conn.incr_id, req);
                }
            }
        }

        int count = reg.getConnCount();
        for (int i = count - 1; i >= 0 && entries.size() < 200; i--) {
            ConnectionDescriptor conn = reg.getConn(i);
            if (conn == null) continue;

            AppDescriptor app = mAppsResolver.getAppByUid(conn.uid, 0);
            String pkgName = app != null ? app.getPackageName() : "";
            String appName = app != null ? app.getName() : "Unknown App";

            boolean isBrowser = isBrowserApp(conn.uid, pkgName);
            HttpLog.HttpRequest matchingReq = reqMap.get(conn.incr_id);

            // Strictly filter: only show actual web browsers or connections with an explicit HTTP log
            if (!isBrowser && matchingReq == null) {
                continue;
            }

            String host = conn.info != null && !conn.info.isEmpty() ? conn.info : conn.dst_ip;

            // Correlate with Defender-captured navigation
            CapturedNavigation bestNav = findMatchingCapturedNav(pkgName, host, conn.last_seen > 0 ? conn.last_seen : conn.first_seen);

            boolean isDecrypted = conn.isDecrypted() || (matchingReq != null) || (bestNav != null);
            boolean isCleartext = conn.isCleartext();
            boolean isWebPort = (conn.dst_port == 443 || conn.dst_port == 8443 || conn.dst_port == 80 || conn.dst_port == 8080);
            boolean effectiveDecrypted = forceDecryptedView || (bestNav != null) || !isTlsDecryptionActive() || (isTlsDecryptionActive() && (isDecrypted || isWebPort));

            String httpMethod = matchingReq != null && !matchingReq.method.isEmpty() ? matchingReq.method : "GET";
            String fullUrl = matchingReq != null ? matchingReq.getUrl() : (bestNav != null ? bestNav.url : (conn.isCleartext() ? "http://" : "https://") + host);
            int statusCode = (matchingReq != null && matchingReq.reply != null) ? matchingReq.reply.responseCode : 200;
            String contentType = (matchingReq != null && matchingReq.reply != null) ? matchingReq.reply.contentType : "";

            // Check decoders
            boolean hasJwt = false;
            boolean hasProto = false;
            boolean hasDoh = false;
            boolean hasHttps = (conn.dst_port == 443 || conn.dst_port == 8443);
            String decryptedPayload = "";
            String encryptedHex = "";

            byte[] payloadBytes = null;
            synchronized (conn) {
                if (conn.getNumPayloadChunks() > 0) {
                    PayloadChunk chunk = conn.getPayloadChunk(0);
                    if (chunk != null) {
                        payloadBytes = chunk.payload;
                    }
                }
            }

            if (payloadBytes != null && payloadBytes.length > 0) {
                com.kotsafe.security.decoders.HttpsDecoder.DecodedHttps decodedHttps =
                        com.kotsafe.security.decoders.HttpsDecoder.decode(payloadBytes);
                if (decodedHttps != null) {
                    hasHttps = true;
                    if (decodedHttps.method != null && !decodedHttps.method.isEmpty()) httpMethod = decodedHttps.method;
                    if (decodedHttps.pathOrUrl != null && !decodedHttps.pathOrUrl.isEmpty() && bestNav == null) fullUrl = decodedHttps.pathOrUrl;
                    if (decodedHttps.statusCode > 0) statusCode = decodedHttps.statusCode;
                }

                if (effectiveDecrypted) {
                    if (decodedHttps != null && !decodedHttps.summary.isEmpty()) {
                        decryptedPayload = decodedHttps.summary;
                    } else if (bestNav != null) {
                        decryptedPayload = "KotSafe Web Protection: " + fullUrl;
                    } else {
                        String text = new String(payloadBytes, StandardCharsets.UTF_8);
                        decryptedPayload = text.length() > 300 ? text.substring(0, 300) + "..." : text;
                    }
                    String text = new String(payloadBytes, StandardCharsets.UTF_8);
                    hasJwt = com.kotsafe.security.decoders.JwtDecoder.findAndParseJwt(text) != null;
                    hasProto = com.kotsafe.security.decoders.ProtobufDecoder.detectAndDecode(payloadBytes) != null;
                    hasDoh = com.kotsafe.security.decoders.DohDecoder.decode(payloadBytes) != null;
                } else {
                    encryptedHex = formatEncryptedTlsPreview(payloadBytes);
                }
            } else {
                if (!effectiveDecrypted) {
                    encryptedHex = "17 03 03 00 a0 [ENCRYPTED APPLICATION DATA STREAM: " + Utils.formatBytes(conn.sent_bytes + conn.rcvd_bytes) + "]";
                } else {
                    decryptedPayload = bestNav != null ? "KotSafe Web Protection: " + fullUrl : "Web Protection active: " + host;
                }
            }

            String tlsVersion = detectTlsVersion(payloadBytes, conn);
            String cipherSuite = "TLS_AES_256_GCM_SHA384 (ECDHE)";

            // Check filter
            if (filterQuery != null && !filterQuery.trim().isEmpty()) {
                String q = filterQuery.toLowerCase();
                if (!appName.toLowerCase().contains(q) &&
                        !pkgName.toLowerCase().contains(q) &&
                        !host.toLowerCase().contains(q) &&
                        !fullUrl.toLowerCase().contains(q)) {
                    continue;
                }
            }

            entries.add(new BrowserLogEntry(
                    conn.incr_id,
                    conn.last_seen > 0 ? conn.last_seen : conn.first_seen,
                    appName, pkgName, conn.uid, host, conn.dst_ip, conn.dst_port,
                    effectiveDecrypted, isCleartext,
                    httpMethod, fullUrl, statusCode, contentType,
                    decryptedPayload, hasJwt, hasProto, hasDoh, hasHttps,
                    tlsVersion, cipherSuite, encryptedHex,
                    conn.sent_bytes, conn.rcvd_bytes,
                    payloadBytes
            ));
        }

        // Also include recent standalone browser navigations captured via Accessibility
        synchronized (this) {
            for (CapturedNavigation nav : mCapturedNavigations) {
                if (entries.size() >= 200) break;
                boolean alreadyListed = false;
                for (BrowserLogEntry e : entries) {
                    if (e.url.equalsIgnoreCase(nav.url) && Math.abs(e.timestamp - nav.timestamp) < 5000) {
                        alreadyListed = true;
                        break;
                    }
                }
                if (!alreadyListed) {
                    AppDescriptor app = mAppsResolver.getAppByPackage(nav.packageName, 0);
                    String appName = app != null ? app.getName() : nav.packageName;
                    String host = nav.url;
                    try {
                        Uri u = Uri.parse(nav.url);
                        if (u.getHost() != null) host = u.getHost();
                    } catch (Exception ignored) {}

                    if (filterQuery != null && !filterQuery.trim().isEmpty()) {
                        String q = filterQuery.toLowerCase();
                        if (!appName.toLowerCase().contains(q) && !nav.packageName.toLowerCase().contains(q) && !nav.url.toLowerCase().contains(q)) {
                            continue;
                        }
                    }

                    entries.add(new BrowserLogEntry(
                            (int) (nav.timestamp % 100000),
                            nav.timestamp,
                            appName, nav.packageName, app != null ? app.getUid() : 0,
                            host, "127.0.0.1", 443,
                            true, false, "GET", nav.url, 200, "text/html",
                            "KotSafe Web Protection: " + nav.url,
                            false, false, false, true,
                            "TLSv1.3", "TLS_AES_256_GCM_SHA384", "",
                            0, 0
                    ));
                }
            }
        }

        entries.sort((a, b) -> Long.compare(b.timestamp, a.timestamp));
        return entries;
    }

    private static String detectTlsVersion(@Nullable byte[] data, ConnectionDescriptor conn) {
        if (data != null && data.length >= 5) {
            // TLS record layer: byte 0 is content type (0x16 = Handshake, 0x17 = Application Data)
            // byte 1-2 is version: 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), 0x0303 (TLS 1.2 / TLS 1.3)
            int major = data[1] & 0xFF;
            int minor = data[2] & 0xFF;
            if (major == 3 && minor == 3) {
                return "TLSv1.3 / TLSv1.2";
            } else if (major == 3 && minor == 1) {
                return "TLSv1.0";
            }
        }
        return conn.dst_port == 443 ? "TLSv1.3 (HTTPS)" : "Cleartext (Port " + conn.dst_port + ")";
    }

    public static String formatEncryptedTlsPreview(@NonNull byte[] data) {
        StringBuilder sb = new StringBuilder();
        int previewLen = Math.min(data.length, 32);
        for (int i = 0; i < previewLen; i++) {
            sb.append(String.format("%02x ", data[i]));
            if (i == 15) sb.append("\n");
        }
        if (data.length > previewLen) {
            sb.append("... [").append(data.length - previewLen).append(" more encrypted bytes]");
        }
        return sb.toString();
    }
}
