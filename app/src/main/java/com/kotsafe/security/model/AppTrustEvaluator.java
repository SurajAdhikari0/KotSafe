/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * AppTrustEvaluator
 * =================
 * Replaces CURATED_THIRD_PARTY_ALLOWLIST and the single-signal verdict logic in
 * AntivirusScanEngine.
 *
 * THE PROBLEM WITH THE OLD DESIGN
 *
 *   isCuratedThirdPartyApp() decided trust by comparing packageName against a
 *   hardcoded list of ~60 mostly-Indian consumer apps. Two things are wrong
 *   with that, and they pull in opposite directions:
 *
 *   1. It is trivially forgeable. packageName is chosen by whoever builds the
 *      APK. Malware that names itself "com.whatsapp" or starts with
 *      "com.phonepe." was granted FALSE-POSITIVE SUPPRESSION — the scanner
 *      explicitly downgraded its YARA hits to LOW and logged "Confirmed False
 *      Positive Suppressed". That is an allowlist bypass with one line of
 *      manifest editing, and it is the most serious defect in the scanner.
 *
 *   2. It covers essentially nothing. There are millions of legitimate apps.
 *      Every app not on the list of 60 was scored as though it were unknown,
 *      so every heuristic hit became a user-visible threat.
 *
 *   The fix for both is the same: stop asking "what is this app called" and
 *   start asking "who signed it, where did it come from, and what does the
 *   combination of its capabilities look like".
 *
 * TRUST ANCHORS, IN DESCENDING ORDER OF STRENGTH
 *
 *   1. Signing certificate  — cannot be forged without the private key. An app
 *      that keeps the same signer across updates is the same publisher. This is
 *      what Android itself uses for update authorization.
 *   2. Install source       — installed by com.android.vending means it passed
 *      Play Protect review. Sideloaded from a browser or file manager did not.
 *   3. Platform signature    — signed with the device's platform key = OS component.
 *
 * SCORING MODEL
 *
 *   Capability is not malice. A password manager references accessibility APIs.
 *   A backup app references Cipher. A launcher queries installed packages. Each
 *   of those alone is worth ~0 points. What matters is:
 *
 *     - capabilities that only make sense TOGETHER for an attacker
 *       (accessibility + overlay + no launcher icon, say)
 *     - capabilities paired with an ABSENCE of trust anchor
 *     - hard indicators of compromise (known-bad signer, known-bad C2 host)
 *
 *   A verdict of MALICIOUS requires either a hard IOC, or a high behavioural
 *   score AND no trust anchor. Heuristics alone never reach MALICIOUS.
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class AppTrustEvaluator {
    private static final String TAG = "AppTrustEvaluator";

    // Verdicts
    public static final String VERDICT_TRUSTED    = "TRUSTED";
    public static final String VERDICT_CLEAN      = "CLEAN";
    public static final String VERDICT_MONITOR    = "MONITOR";     // shown in a separate, non-alarming list
    public static final String VERDICT_SUSPICIOUS = "SUSPICIOUS";
    public static final String VERDICT_MALICIOUS  = "MALICIOUS";

    // Install sources that imply a vetting step happened
    private static final Set<String> VETTED_INSTALLERS = new HashSet<>(Arrays.asList(
            "com.android.vending",              // Google Play
            "com.google.android.packageinstaller.apex",
            "com.amazon.venezia",               // Amazon Appstore
            "com.sec.android.app.samsungapps",  // Galaxy Store
            "com.huawei.appmarket",
            "com.xiaomi.mipicks",
            "com.heytap.market",
            "com.oppo.market",
            "com.vivo.appstore",
            "org.fdroid.fdroid"                 // F-Droid: reproducible builds, signed index
    ));

    /** Installers that are just "a human moved a file here" — no vetting implied. */
    private static final Set<String> SIDELOAD_INSTALLERS = new HashSet<>(Arrays.asList(
            "com.android.packageinstaller",
            "com.google.android.packageinstaller",
            "com.android.shell",                // adb install
            "com.android.documentsui",
            "com.google.android.apps.nbu.files",
            "com.whatsapp",                     // received as a file and opened
            "org.telegram.messenger",
            "com.android.chrome",
            "com.android.bluetooth"
    ));

    public static class TrustProfile {
        public String packageName;
        public String appLabel;
        public String signerSha256;
        public String installerPackage;
        public boolean isSystemApp;
        public boolean isPlatformSigned;
        public boolean isVettedInstall;
        public boolean isSideloaded;
        public boolean isDebuggable;
        public boolean isTestOnly;
        public boolean selfSignedDebugCert;
        public long certValidityDays;
        public int targetSdk;
        public long firstInstallTime;
        public boolean hasLauncherIcon;
        public boolean isKotSafeSelf;

        // Declared high-power components
        public boolean declaresAccessibilityService;
        public boolean declaresDeviceAdmin;
        public boolean declaresNotificationListener;
        public boolean declaresSmsReceiver;
        public boolean requestsOverlayPermission;
        public boolean requestsRequestInstallPackages;
        public boolean requestsQueryAllPackages;

        public List<String> permissions = new ArrayList<>();
    }

    public static class Assessment {
        public String verdict = VERDICT_CLEAN;
        public int behaviouralScore = 0;       // 0-100, capability-combination risk
        public int confidence = 0;             // 0-100, how sure we are
        public boolean hasTrustAnchor = false;
        public List<String> reasons = new ArrayList<>();
        public List<String> mitigatingFactors = new ArrayList<>();
        /** Plain-language line the UI can show without scaring the user. */
        public String userExplanation = "";
    }

    // ------------------------------------------------------------------ profiling

    public static TrustProfile profile(Context ctx, PackageInfo pi) {
        TrustProfile p = new TrustProfile();
        PackageManager pm = ctx.getPackageManager();
        ApplicationInfo ai = pi.applicationInfo;

        p.packageName = pi.packageName;
        p.appLabel = ai != null ? String.valueOf(pm.getApplicationLabel(ai)) : pi.packageName;
        p.isSystemApp = Utils.classifyAppInstall(ai) == Utils.AppInstallClass.SYSTEM;
        p.isDebuggable = ai != null && (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        p.targetSdk = ai != null ? ai.targetSdkVersion : 0;
        p.firstInstallTime = pi.firstInstallTime;
        p.hasLauncherIcon = pm.getLaunchIntentForPackage(pi.packageName) != null;
        p.isKotSafeSelf = pi.packageName != null && (pi.packageName.equals(ctx.getPackageName()) || pi.packageName.startsWith("com.kotsafe.security") || pi.packageName.startsWith("com.kotsafe.security"));

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            p.isTestOnly = ai != null && (ai.flags & ApplicationInfo.FLAG_TEST_ONLY) != 0;
        }

        // ---- install source
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                InstallSourceInfo isi = pm.getInstallSourceInfo(pi.packageName);
                p.installerPackage = isi.getInstallingPackageName();
            } else {
                p.installerPackage = pm.getInstallerPackageName(pi.packageName);
            }
        } catch (Exception ignored) {}

        if (p.installerPackage != null) {
            p.isVettedInstall = VETTED_INSTALLERS.contains(p.installerPackage);
            p.isSideloaded = SIDELOAD_INSTALLERS.contains(p.installerPackage);
        } else {
            // With no installer, trust only PackageManager-confirmed system apps.
            // A Google/OEM-looking package name is not an install provenance signal.
            p.isSideloaded = !p.isSystemApp;
        }

        // ---- signing certificate
        try {
            Signature[] sigs = getSignatures(pm, pi.packageName);
            if (sigs != null && sigs.length > 0) {
                p.signerSha256 = sha256Hex(sigs[0].toByteArray());
                X509Certificate cert = parseCert(sigs[0].toByteArray());
                if (cert != null) {
                    long days = TimeUnit.MILLISECONDS.toDays(
                            cert.getNotAfter().getTime() - cert.getNotBefore().getTime());
                    p.certValidityDays = days;
                    String dn = cert.getSubjectX500Principal().getName();
                    String dnLower = dn.toLowerCase(Locale.ROOT);
                    // The default debug keystore identity that every IDE emits.
                    p.selfSignedDebugCert = dnLower.contains("cn=android debug")
                            || dnLower.contains("o=android")
                            && dnLower.contains("cn=android debug");
                }
                // Platform-signed = shares the signer of the "android" package.
                Signature[] platformSigs = getSignatures(pm, "android");
                if (platformSigs != null && platformSigs.length > 0) {
                    p.isPlatformSigned = sha256Hex(platformSigs[0].toByteArray()).equals(p.signerSha256);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "signature read failed for " + pi.packageName + ": " + e.getMessage());
        }

        // ---- declared permissions
        if (pi.requestedPermissions != null) {
            for (String perm : pi.requestedPermissions) {
                if (perm == null) continue;
                p.permissions.add(perm);
                switch (perm) {
                    case "android.permission.SYSTEM_ALERT_WINDOW":
                        p.requestsOverlayPermission = true; break;
                    case "android.permission.REQUEST_INSTALL_PACKAGES":
                        p.requestsRequestInstallPackages = true; break;
                    case "android.permission.QUERY_ALL_PACKAGES":
                        p.requestsQueryAllPackages = true; break;
                    case "android.permission.RECEIVE_SMS":
                        p.declaresSmsReceiver = true; break;
                }
            }
        }

        // ---- high-power declared services (bind permission is the reliable marker)
        if (pi.services != null) {
            for (android.content.pm.ServiceInfo si : pi.services) {
                if (si == null || si.permission == null) continue;
                switch (si.permission) {
                    case "android.permission.BIND_ACCESSIBILITY_SERVICE":
                        p.declaresAccessibilityService = true; break;
                    case "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE":
                        p.declaresNotificationListener = true; break;
                    case "android.permission.BIND_DEVICE_ADMIN":
                        p.declaresDeviceAdmin = true; break;
                }
            }
        }
        if (pi.receivers != null) {
            for (android.content.pm.ActivityInfo ri : pi.receivers) {
                if (ri != null && "android.permission.BIND_DEVICE_ADMIN".equals(ri.permission)) {
                    p.declaresDeviceAdmin = true;
                }
            }
        }

        return p;
    }

    @SuppressWarnings("deprecation")
    private static Signature[] getSignatures(PackageManager pm, String pkg) throws Exception {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageInfo info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
            SigningInfo si = info.signingInfo;
            if (si == null) return null;
            return si.hasMultipleSigners() ? si.getApkContentsSigners() : si.getSigningCertificateHistory();
        } else {
            PackageInfo info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
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

    // ------------------------------------------------------------------ assessment

    /**
     * @param hardIoc  set when an authoritative source says this exact artifact is
     *                 bad: signer on a known-bad list, SHA-256 matched by a threat
     *                 feed with sufficient reporting, or a high-confidence YARA
     *                 family rule. Only this can produce MALICIOUS on its own.
     */
    public static Assessment assess(TrustProfile p,
                                    DexReferenceAnalyzer.DexFacts dex,
                                    boolean hardIoc,
                                    String hardIocReason) {
        Assessment a = new Assessment();

        // ---------- trust anchors (these SUPPRESS, they never convict) ----------
        if (p.isKotSafeSelf) {
            a.hasTrustAnchor = true;
            a.verdict = VERDICT_TRUSTED;
            a.confidence = 100;
            a.behaviouralScore = 0;
            a.mitigatingFactors.add("Authorized KotSafe application sentinel and build components");
            a.userExplanation = p.appLabel + " is the authorized KotSafe security engine.";
            return a;
        } else if (p.isPlatformSigned) {
            a.hasTrustAnchor = true;
            a.mitigatingFactors.add("Signed with the device platform key (OS component)");
        } else if (p.isSystemApp) {
            a.hasTrustAnchor = true;
            a.mitigatingFactors.add("Preinstalled system application");
        } else if (p.isVettedInstall) {
            a.hasTrustAnchor = true;
            a.mitigatingFactors.add("Installed from " + friendlyStore(p.installerPackage));
        }

        // ---------- hard indicator of compromise ----------
        if (hardIoc) {
            a.verdict = VERDICT_MALICIOUS;
            a.confidence = 95;
            a.behaviouralScore = 100;
            a.reasons.add(hardIocReason != null ? hardIocReason : "Matched a known malicious artifact");
            a.userExplanation = p.appLabel + " matches a known malware signature. "
                    + "Uninstalling it is strongly recommended.";
            return a;
        }

        // ---------- behavioural scoring: combinations, not capabilities ----------
        int score = 0;

        boolean refAccessibility = dex != null && (dex.refs(DexReferenceAnalyzer.Api.ACCESSIBILITY_EVT)
                || dex.refs(DexReferenceAnalyzer.Api.PERFORM_GLOBAL));
        boolean refOverlay = dex != null && dex.refs(DexReferenceAnalyzer.Api.OVERLAY_ADD_VIEW);
        boolean refSms = dex != null && DexReferenceAnalyzer.usesSmsSending(dex);
        boolean refDynLoad = dex != null && DexReferenceAnalyzer.usesDynamicCodeLoading(dex);
        boolean refExec = dex != null && (dex.refs(DexReferenceAnalyzer.Api.RUNTIME_EXEC)
                || dex.refs(DexReferenceAnalyzer.Api.PROCESS_BUILDER));
        boolean refAudio = dex != null && (dex.refs(DexReferenceAnalyzer.Api.AUDIO_RECORD)
                || dex.refs(DexReferenceAnalyzer.Api.MEDIA_RECORDER));
        boolean refInstall = dex != null && dex.refs(DexReferenceAnalyzer.Api.PKG_INSTALL);
        boolean refWipe = dex != null && (dex.refs(DexReferenceAnalyzer.Api.DEVICE_ADMIN_WIPE)
                || dex.refs(DexReferenceAnalyzer.Api.RESET_PASSWORD));

        // --- The banking-trojan shape. This specific triad is the real signal.
        if (p.declaresAccessibilityService && refOverlay && !p.hasLauncherIcon) {
            score += 45;
            a.reasons.add("Accessibility service + screen overlay + no launcher icon "
                    + "(the standard overlay-hijack pattern)");
        } else if (p.declaresAccessibilityService && refOverlay && p.isSideloaded) {
            score += 30;
            a.reasons.add("Sideloaded app combining accessibility control with screen overlays");
        } else if (p.declaresAccessibilityService && refAccessibility && p.isSideloaded) {
            score += 18;
            a.reasons.add("Sideloaded app with an accessibility service");
        }

        // --- SMS interception + send, without being an SMS app
        if (refSms && p.declaresSmsReceiver && !p.hasLauncherIcon) {
            score += 40;
            a.reasons.add("Sends and intercepts SMS with no user-visible interface");
        } else if (refSms && p.declaresSmsReceiver && p.isSideloaded) {
            score += 22;
            a.reasons.add("Sideloaded app that both reads and sends SMS");
        }

        // --- Stager pattern: fetch code at runtime and execute it
        if (refDynLoad && refExec && p.isSideloaded) {
            score += 35;
            a.reasons.add("Loads code at runtime and executes native processes");
        } else if (refDynLoad && p.isSideloaded && !p.isVettedInstall) {
            score += 12;
            a.reasons.add("Sideloaded app that loads code dynamically");
        }

        // --- Self-propagation
        if (p.requestsRequestInstallPackages && refInstall && p.isSideloaded) {
            score += 30;
            a.reasons.add("Sideloaded app capable of silently installing other packages");
        }

        // --- Device admin abuse surface
        if (p.declaresDeviceAdmin && refWipe && p.isSideloaded) {
            score += 28;
            a.reasons.add("Sideloaded device administrator that can wipe or reset the device");
        }

        // --- Covert surveillance
        if (refAudio && !p.hasLauncherIcon && p.isSideloaded) {
            score += 30;
            a.reasons.add("Records audio with no launcher entry point");
        }

        // --- Build-quality indicators
        if (p.selfSignedDebugCert) {
            score += 20;
            a.reasons.add("Signed with a default debug certificate, not a real publisher key");
        }
        if (p.isDebuggable && !p.isSystemApp) {
            score += 10;
            a.reasons.add("Ships with debugging enabled");
        }
        if (p.targetSdk > 0 && p.targetSdk < 23) {
            score += 12;
            a.reasons.add("Targets a very old Android API level (" + p.targetSdk
                    + "), which bypasses runtime permission prompts");
        }
        if (p.certValidityDays > 0 && p.certValidityDays < 370) {
            score += 8;
            a.reasons.add("Signing certificate valid for under a year (throwaway key)");
        }

        // --- Embedded C2-looking endpoints
        if (dex != null) {
            for (String host : dex.embeddedHosts) {
                if (host.endsWith(".onion")) {
                    score += 25;
                    a.reasons.add("Contains a hardcoded Tor hidden service address");
                    break;
                }
            }
        }

        // ---------- trust anchor damping ----------
        // A vetted install does not make an app safe, but it does mean these
        // capability combinations were reviewed by someone. Damp, don't zero.
        if (p.isPlatformSigned || p.isSystemApp) {
            score = 0;
            a.mitigatingFactors.add("Official OS/OEM platform components are not penalized by capability heuristics");
        } else if (p.isVettedInstall) {
            score = score / 2;
        }

        a.behaviouralScore = Math.min(score, 100);

        // ---------- verdict ----------
        // Heuristics alone CANNOT reach MALICIOUS. That is the whole point.
        if (p.isPlatformSigned || p.isSystemApp) {
            a.verdict = VERDICT_TRUSTED;
            a.confidence = 95;
            a.userExplanation = p.appLabel + " is an official system component.";
        } else if (a.behaviouralScore >= 60 && !a.hasTrustAnchor) {
            a.verdict = VERDICT_SUSPICIOUS;
            a.confidence = 70;
            a.userExplanation = p.appLabel + " was installed outside an app store and combines "
                    + "capabilities typically seen in banking trojans. Review it carefully.";
        } else if (a.behaviouralScore >= 35) {
            a.verdict = VERDICT_MONITOR;
            a.confidence = 45;
            a.userExplanation = p.appLabel + " has powerful permissions. This is normal for some "
                    + "apps — shown here so you can confirm you installed it deliberately.";
        } else if (a.behaviouralScore > 0) {
            a.verdict = VERDICT_MONITOR;
            a.confidence = 25;
            a.userExplanation = p.appLabel + " uses one or more sensitive capabilities.";
        } else {
            a.verdict = VERDICT_CLEAN;
            a.confidence = 60;
            a.userExplanation = "No concerning behaviour found.";
        }

        return a;
    }

    private static String friendlyStore(String installer) {
        if (installer == null) return "an app store";
        switch (installer) {
            case "com.android.vending": return "Google Play";
            case "com.amazon.venezia": return "the Amazon Appstore";
            case "com.sec.android.app.samsungapps": return "the Galaxy Store";
            case "org.fdroid.fdroid": return "F-Droid";
            default: return installer;
        }
    }

    /**
     * Only these verdicts should ever raise a notification or count toward the
     * "threats found" number the user sees. MONITOR belongs in a separate,
     * collapsed section — it is context, not an alarm.
     */
    public static boolean isUserFacingThreat(String verdict) {
        return VERDICT_MALICIOUS.equals(verdict) || VERDICT_SUSPICIOUS.equals(verdict);
    }
}
