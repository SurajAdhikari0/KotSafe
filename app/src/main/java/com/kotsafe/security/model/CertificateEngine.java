/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * CertificateEngine
 * =================
 * Analyzes APK signing certificates to establish authentic publisher identity
 * and detect certificate anomalies (e.g. debug certs, platform signature spoofing,
 * expired certificates, self-signed untrusted publishers).
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;

import com.kotsafe.security.Log;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

public class CertificateEngine {
    private static final String TAG = "CertificateEngine";

    public static class CertificateProfile {
        public String sha256Fingerprint = "";
        public String sha1Fingerprint = "";
        public String subjectDn = "";
        public String issuerDn = "";
        public long validityDays = 0;
        public long validFromMs = 0;
        public long validToMs = 0;
        public boolean isExpired = false;
        public boolean isNotYetValid = false;
        public boolean isSelfSigned = false;
        public boolean isDebugKeystore = false;
        public boolean isPlatformSigned = false;
        public int signingSchemeVersion = 1; // v1=1, v2=2, v3=3+
        public List<String> anomalyFlags = new ArrayList<>();
    }

    public static class UpdateSafetyCheck {
        public boolean isInstalled = false;
        public boolean isSignatureMatch = true;
        public boolean isDowngrade = false;
        public String installedVersionName = "";
        public int installedVersionCode = 0;
        public String installedCertSha256 = "";
        public String apkCertSha256 = "";
        public String safetyVerdict = "FRESH_INSTALL"; // FRESH_INSTALL, SAFE_UPDATE, SIGNATURE_MISMATCH, DOWNGRADE_ATTACK
        public String warningMessage = "";
    }

    public static CertificateProfile analyze(Context context, String packageName) {
        CertificateProfile profile = new CertificateProfile();
        if (context == null || packageName == null || packageName.isEmpty()) {
            return profile;
        }

        PackageManager pm = context.getPackageManager();
        try {
            Signature[] signatures = getSignatures(pm, packageName);
            if (signatures != null && signatures.length > 0) {
                populateProfileFromSignature(context, profile, signatures[0]);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    try {
                        PackageInfo pi = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES);
                        if (pi.signingInfo != null) {
                            profile.signingSchemeVersion = pi.signingInfo.hasMultipleSigners() ? 2 : 3;
                        }
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Error analyzing certificate for " + packageName + ": " + e.getMessage());
        }

        return profile;
    }

    public static CertificateProfile analyzeApkFile(Context context, File apkFile) {
        CertificateProfile profile = new CertificateProfile();
        if (context == null || apkFile == null || !apkFile.exists()) {
            return profile;
        }

        PackageManager pm = context.getPackageManager();
        try {
            Signature[] signatures = getApkSignatures(pm, apkFile.getAbsolutePath());
            if (signatures != null && signatures.length > 0) {
                populateProfileFromSignature(context, profile, signatures[0]);
            }
        } catch (Exception e) {
            Log.w(TAG, "Error analyzing APK certificate: " + e.getMessage());
        }
        return profile;
    }

    private static void populateProfileFromSignature(Context context, CertificateProfile profile, Signature signature) {
        byte[] rawCert = signature.toByteArray();
        profile.sha256Fingerprint = computeFingerprint(rawCert, "SHA-256");
        profile.sha1Fingerprint = computeFingerprint(rawCert, "SHA-1");

        X509Certificate x509 = parseCert(rawCert);
        if (x509 != null) {
            profile.subjectDn = x509.getSubjectX500Principal().getName();
            profile.issuerDn = x509.getIssuerX500Principal().getName();
            profile.validFromMs = x509.getNotBefore().getTime();
            profile.validToMs = x509.getNotAfter().getTime();
            profile.validityDays = TimeUnit.MILLISECONDS.toDays(profile.validToMs - profile.validFromMs);

            long now = System.currentTimeMillis();
            if (now > profile.validToMs) {
                profile.isExpired = true;
                profile.anomalyFlags.add("Certificate Expired");
            }
            if (now < profile.validFromMs) {
                profile.isNotYetValid = true;
                profile.anomalyFlags.add("Certificate Not Yet Valid");
            }

            profile.isSelfSigned = profile.subjectDn.equals(profile.issuerDn);

            String dnLower = profile.subjectDn.toLowerCase(Locale.ROOT);
            if (dnLower.contains("cn=android debug") || (dnLower.contains("o=android") && dnLower.contains("cn=android debug"))) {
                profile.isDebugKeystore = true;
                profile.anomalyFlags.add("Signed by Android Debug Key");
            }
        }

        // Check platform signature match with system framework package "android"
        try {
            Signature[] platformSigs = getSignatures(context.getPackageManager(), "android");
            if (platformSigs != null && platformSigs.length > 0) {
                String platformSha256 = computeFingerprint(platformSigs[0].toByteArray(), "SHA-256");
                if (profile.sha256Fingerprint.equalsIgnoreCase(platformSha256)) {
                    profile.isPlatformSigned = true;
                }
            }
        } catch (Exception ignored) {}
    }

    /**
     * Compares an incoming APK's signature and version code against the currently installed app (if any).
     */
    public static UpdateSafetyCheck checkUpdateSafety(Context context, String packageName, Signature[] apkSignatures, int apkVersionCode) {
        UpdateSafetyCheck check = new UpdateSafetyCheck();
        if (context == null || packageName == null || packageName.isEmpty()) {
            return check;
        }
        PackageManager pm = context.getPackageManager();
        PackageInfo installedPi = null;
        try {
            installedPi = pm.getPackageInfo(packageName, 0);
        } catch (PackageManager.NameNotFoundException e) {
            check.isInstalled = false;
            check.safetyVerdict = "FRESH_INSTALL";
            return check;
        } catch (Exception ignored) {}

        if (installedPi != null) {
            check.isInstalled = true;
            check.installedVersionName = installedPi.versionName != null ? installedPi.versionName : "";
            check.installedVersionCode = installedPi.versionCode;

            // Check version downgrade
            if (apkVersionCode > 0 && apkVersionCode < installedPi.versionCode) {
                check.isDowngrade = true;
                check.safetyVerdict = "DOWNGRADE_ATTACK";
                check.warningMessage = "Incoming version (" + apkVersionCode + ") is older than installed version (" + installedPi.versionCode + "). Potential downgrade attack!";
            }

            // Check signature match
            Signature[] installedSigs = getSignatures(pm, packageName);
            if (installedSigs != null && installedSigs.length > 0 && apkSignatures != null && apkSignatures.length > 0) {
                String installedSha256 = computeFingerprint(installedSigs[0].toByteArray(), "SHA-256");
                String apkSha256 = computeFingerprint(apkSignatures[0].toByteArray(), "SHA-256");
                check.installedCertSha256 = installedSha256;
                check.apkCertSha256 = apkSha256;

                if (!installedSha256.equalsIgnoreCase(apkSha256)) {
                    check.isSignatureMatch = false;
                    check.safetyVerdict = "SIGNATURE_MISMATCH";
                    check.warningMessage = "SIGNATURE MISMATCH! The APK is signed with a different key than the installed app. Possible Trojan clone or hijacked update!";
                } else if (!check.isDowngrade) {
                    check.isSignatureMatch = true;
                    check.safetyVerdict = "SAFE_UPDATE";
                }
            }
        }
        return check;
    }

    @SuppressWarnings("deprecation")
    public static Signature[] getApkSignatures(PackageManager pm, String apkPath) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo pi = pm.getPackageArchiveInfo(apkPath, PackageManager.GET_SIGNING_CERTIFICATES);
                if (pi != null && pi.signingInfo != null) {
                    SigningInfo si = pi.signingInfo;
                    return si.hasMultipleSigners() ? si.getApkContentsSigners() : si.getSigningCertificateHistory();
                }
            }
            PackageInfo pi = pm.getPackageArchiveInfo(apkPath, PackageManager.GET_SIGNATURES);
            if (pi != null) {
                return pi.signatures;
            }
        } catch (Exception e) {
            Log.w(TAG, "Error getting APK signatures: " + e.getMessage());
        }
        return null;
    }

    @SuppressWarnings("deprecation")
    public static Signature[] getSignatures(PackageManager pm, String packageName) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo pi = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES);
                if (pi != null && pi.signingInfo != null) {
                    SigningInfo si = pi.signingInfo;
                    return si.hasMultipleSigners() ? si.getApkContentsSigners() : si.getSigningCertificateHistory();
                }
            }
            PackageInfo pi = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
            return pi != null ? pi.signatures : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static X509Certificate parseCert(byte[] certBytes) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        } catch (Exception e) {
            return null;
        }
    }

    public static String computeFingerprint(byte[] bytes, String algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] digest = md.digest(bytes);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02X", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
