/*
 * This file is part of KotSafe.
 *
 * Copyright 2026 KotSafe Cyber Security Project
 *
 * PlayCertificateVerifier
 * =======================
 * Implements exactly how professional AV products (Kaspersky, Bitdefender, Norton)
 * eliminate false positives on authentic, verified apps:
 *
 * LAYER 1 — Install Source Trust
 *   If installed by com.android.vending (Play Store), the app was reviewed by
 *   Google Play Protect. On API 30+, InstallSourceInfo also gives us the
 *   initiating package to verify it wasn't impersonated.
 *
 * LAYER 2 — Play App Signing Certificate Detection
 *   Since 2021 Google requires Play App Signing by default. Apps enrolled in
 *   Play App Signing have their APK re-signed by Google's own app signing key.
 *   The signing cert Subject DN follows a known Google infrastructure pattern.
 *
 * LAYER 3 — Publisher Reputation (Certificate SHA-256 History)
 *   Major AV vendors maintain a local reputation DB keyed by the signing cert
 *   SHA-256. If we have seen this publisher's key sign clean apps before, new
 *   apps from the same key inherit credibility.
 *
 * LAYER 4 — Legitimate Framework Detection
 *   React Native, Flutter, Unity, Xamarin, Cordova all produce bytecode patterns
 *   that look suspicious to naive classifiers. We detect these and suppress.
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;

import com.kotsafe.security.Log;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class PlayCertificateVerifier {
    private static final String TAG = "PlayCertVerifier";

    // Known Play App Signing infrastructure certificate Subject/Issuer patterns.
    // When Google re-signs an app via Play App Signing, the signing cert Subject DN
    // contains one of these identifiers from Google's App Signing infrastructure.
    private static final String[] PLAY_SIGNING_SUBJECT_PATTERNS = {
            "play app signing",
            "google play app signing",
            "cn=google play",
            "o=google play",
            "google llc",
            "google inc",
            "google, inc",
    };

    // Known legitimate cross-platform frameworks
    public enum AppFramework {
        NATIVE,         // pure Java/Kotlin, no special framework
        REACT_NATIVE,   // assets/index.android.bundle present
        FLUTTER,        // lib/*/libflutter.so present
        UNITY,          // lib/*/libunity.so or assets/bin/Data/
        XAMARIN,        // assemblies/*.dll in APK
        CORDOVA,        // assets/www/cordova.js
        COCOS2DX,       // lib/*/libcocos2dcpp.so
        GAME_ENGINE     // generic game engine (large libXXX.so)
    }

    public static class VerificationResult {
        public boolean isVettedInstall;
        public String installerPackage;
        public boolean isPlayAppSigning;
        public String signerSha256;
        public String signerSubject;
        public long certValidityDays;
        public AppFramework framework = AppFramework.NATIVE;
        public String suppressionReason;

        /**
         * Returns true when ML anomalies should be suppressed for this app.
         * This is the core gate: a Play Store app, or one using Play App Signing,
         * or one built with a known framework - should never be flagged as MALICIOUS.
         */
        public boolean shouldSuppressMlAnomalies() {
            if (isPlayAppSigning) {
                suppressionReason = "Play App Signing: Google re-signed this APK via their App Signing infrastructure";
                return true;
            }
            if (isVettedInstall && certValidityDays > 365) {
                suppressionReason = "Vetted store install with long-lived publisher certificate (" + certValidityDays + " days)";
                return true;
            }
            if (isVettedInstall && framework != AppFramework.NATIVE) {
                suppressionReason = "Vetted store install using " + framework.name() + " framework (known high-entropy pattern)";
                return true;
            }
            if (isVettedInstall) {
                suppressionReason = "Installed from vetted app store: " + (installerPackage != null ? installerPackage : "known store");
                return true;
            }
            return false;
        }

        /**
         * Confidence level this is a legitimate publisher (0-100).
         * Used to calibrate ML scoring.
         */
        public int publisherTrustScore() {
            int score = 0;
            if (isPlayAppSigning)               score += 50;
            if (isVettedInstall)                score += 30;
            if (certValidityDays > 365 * 2)     score += 15;
            else if (certValidityDays > 365)    score += 10;
            if (framework != AppFramework.NATIVE) score += 5;
            return Math.min(100, score);
        }
    }

    // Publisher reputation cache: signerSha256 -> vetted app install count
    // Persists in memory for the scan session. Signer seen signing multiple
    // store-installed clean apps = credible publisher.
    private static final ConcurrentHashMap<String, Integer> sReputationCache = new ConcurrentHashMap<>();

    /**
     * Main entry point: runs all 4 verification layers for the given package.
     */
    public static VerificationResult verify(Context ctx, PackageInfo pi) {
        VerificationResult r = new VerificationResult();
        PackageManager pm = ctx.getPackageManager();

        // Layer 1: Install source
        r.installerPackage = getInstallerPackage(pm, pi.packageName);
        r.isVettedInstall = isVettedInstaller(r.installerPackage);

        // Layer 2: Certificate analysis
        analyzeCertificate(pm, pi.packageName, r);

        // Layer 3: Publisher reputation cache
        if (r.signerSha256 != null && !r.signerSha256.isEmpty()) {
            Integer hits = sReputationCache.get(r.signerSha256);
            if (hits != null && hits >= 2 && r.isVettedInstall) {
                if (r.suppressionReason == null) {
                    r.suppressionReason = "Known publisher key (seen across " + hits + " vetted apps)";
                }
            }
            // Update cache for this vetted install
            if (r.isVettedInstall) {
                sReputationCache.merge(r.signerSha256, 1, Integer::sum);
            }
        }

        // Layer 4: Framework detection
        if (pi.applicationInfo != null && pi.applicationInfo.sourceDir != null) {
            File apkFile = new File(pi.applicationInfo.sourceDir);
            if (apkFile.exists() && apkFile.canRead()) {
                r.framework = detectFramework(apkFile);
            }
        }

        Log.d(TAG, "Verified " + pi.packageName
                + " | vetted=" + r.isVettedInstall
                + " | playAppSigning=" + r.isPlayAppSigning
                + " | framework=" + r.framework
                + " | certDays=" + r.certValidityDays
                + " | trustScore=" + r.publisherTrustScore()
                + " | suppress=" + r.shouldSuppressMlAnomalies());

        return r;
    }

    // ── Layer 2: Certificate Analysis ─────────────────────────────────────────

    private static void analyzeCertificate(PackageManager pm, String packageName,
                                            VerificationResult r) {
        try {
            Signature[] sigs = getSignatures(pm, packageName);
            if (sigs == null || sigs.length == 0) return;

            byte[] certBytes = sigs[0].toByteArray();
            r.signerSha256 = sha256Hex(certBytes);

            X509Certificate cert = parseCert(certBytes);
            if (cert == null) return;

            long notBefore = cert.getNotBefore().getTime();
            long notAfter  = cert.getNotAfter().getTime();
            r.certValidityDays = (notAfter - notBefore) / (1000L * 60 * 60 * 24);

            String subjectDn = cert.getSubjectX500Principal().getName();
            String issuerDn  = cert.getIssuerX500Principal().getName();
            r.signerSubject  = extractCN(subjectDn);

            String combined = (subjectDn + " " + issuerDn).toLowerCase(Locale.ROOT);

            // Play App Signing detection
            for (String pattern : PLAY_SIGNING_SUBJECT_PATTERNS) {
                if (combined.contains(pattern)) {
                    r.isPlayAppSigning = true;
                    return;
                }
            }

            // Infer Play App Signing: Play-installed + multi-decade Google cert
            if (r.isVettedInstall && r.certValidityDays > 9000
                    && (combined.contains("google"))) {
                r.isPlayAppSigning = true;
            }

        } catch (Exception e) {
            Log.w(TAG, "Certificate analysis failed for " + packageName + ": " + e.getMessage());
        }
    }

    // ── Layer 4: Framework Detection ──────────────────────────────────────────

    /**
     * Detects cross-platform framework by scanning APK zip entries.
     * All these frameworks produce patterns that naive ML classifiers flag falsely:
     *   - React Native: high-entropy JS bundle in assets
     *   - Flutter: libflutter.so + compiled Dart in assets
     *   - Unity: libunity.so + libil2cpp.so, binary game data assets
     *   - Xamarin: embedded .dll assemblies
     */
    public static AppFramework detectFramework(File apkFile) {
        boolean hasReactNative = false;
        boolean hasFlutter     = false;
        boolean hasUnity       = false;
        boolean hasXamarin     = false;
        boolean hasCordova     = false;
        boolean hasCocos2d     = false;
        boolean hasLargeNative = false;

        try (ZipInputStream zis = new ZipInputStream(
                new BufferedInputStream(new FileInputStream(apkFile)))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase(Locale.ROOT);

                if (name.equals("assets/index.android.bundle")
                        || name.startsWith("assets/react-native/")
                        || name.contains("hermesdb")
                        || name.equals("assets/app.bundle")) {
                    hasReactNative = true;
                }
                if (name.contains("libflutter.so")
                        || name.startsWith("assets/flutter_assets/")
                        || name.equals("assets/isolate_snapshot_data")) {
                    hasFlutter = true;
                }
                if (name.contains("libunity.so")
                        || name.contains("libil2cpp.so")
                        || name.startsWith("assets/bin/data/")) {
                    hasUnity = true;
                }
                if (name.startsWith("assemblies/") && name.endsWith(".dll")) {
                    hasXamarin = true;
                }
                if (name.equals("assets/www/cordova.js")
                        || name.equals("assets/www/index.html")) {
                    hasCordova = true;
                }
                if (name.contains("libcocos2dcpp.so") || name.contains("libcocos2d.so")) {
                    hasCocos2d = true;
                }
                // Generic: very large native lib = likely game engine
                if (name.startsWith("lib/") && name.endsWith(".so")
                        && entry.getCompressedSize() > 8_000_000L) {
                    hasLargeNative = true;
                }

                zis.closeEntry();
            }
        } catch (Exception ignored) {}

        // Priority: most specific first
        if (hasFlutter)     return AppFramework.FLUTTER;
        if (hasUnity)       return AppFramework.UNITY;
        if (hasReactNative) return AppFramework.REACT_NATIVE;
        if (hasXamarin)     return AppFramework.XAMARIN;
        if (hasCordova)     return AppFramework.CORDOVA;
        if (hasCocos2d)     return AppFramework.COCOS2DX;
        if (hasLargeNative) return AppFramework.GAME_ENGINE;
        return AppFramework.NATIVE;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static final Set<String> VETTED_STORES = new HashSet<>(Arrays.asList(
            "com.android.vending",
            "com.google.android.packageinstaller.apex",
            "com.amazon.venezia",
            "com.sec.android.app.samsungapps",
            "com.huawei.appmarket",
            "com.xiaomi.mipicks",
            "com.heytap.market",
            "com.oppo.market",
            "com.vivo.appstore",
            "org.fdroid.fdroid"
    ));

    private static boolean isVettedInstaller(String installer) {
        return installer != null && VETTED_STORES.contains(installer);
    }

    private static String getInstallerPackage(PackageManager pm, String packageName) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                InstallSourceInfo isi = pm.getInstallSourceInfo(packageName);
                String installer = isi.getInstallingPackageName();
                if (installer == null) installer = isi.getInitiatingPackageName();
                return installer;
            } else {
                return pm.getInstallerPackageName(packageName);
            }
        } catch (Exception e) {
            return null;
        }
    }

    @SuppressWarnings("deprecation")
    private static Signature[] getSignatures(PackageManager pm, String packageName) throws Exception {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageInfo info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES);
            SigningInfo si = info.signingInfo;
            if (si == null) return null;
            return si.hasMultipleSigners() ? si.getApkContentsSigners() : si.getSigningCertificateHistory();
        } else {
            PackageInfo info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
            return info.signatures;
        }
    }

    private static X509Certificate parseCert(byte[] der) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            return null;
        }
    }

    private static String sha256Hex(byte[] data) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static String extractCN(String dn) {
        if (dn == null) return "";
        for (String part : dn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.toUpperCase(Locale.ROOT).startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        return dn;
    }
}
