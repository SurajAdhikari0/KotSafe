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
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Parcel;
import android.os.Parcelable;

import com.kotsafe.security.Log;
import com.kotsafe.security.ThreatIntelApiClient;

import android.content.pm.Signature;
import com.kotsafe.security.security.event.EventTypes;
import com.kotsafe.security.security.event.SecurityEvent;
import com.kotsafe.security.security.event.SecurityEventBus;
import com.kotsafe.security.security.mitre.MitreMapper;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import com.kotsafe.security.ai.ThreatContextBuilder;
import com.kotsafe.security.ai.ml.MlMalwareClassifier;

/**
 * Pre-install APK scanner — runs the full antivirus & EDR pipeline on an arbitrary APK file
 * before the system installer is invoked. Reuses all existing infrastructure:
 *   • FileHashScanner.computeHash  (SHA-256)
 *   • CertificateEngine.analyzeApkFile / checkUpdateSafety (Signature hijack & downgrade check)
 *   • DexStructuralParser.analyzeApk (DEX structural analysis)
 *   • IOCExtractor.extractFromApk (C2 domains, URLs, hardcoded webhooks)
 *   • PermissionRiskEngine.analyze (ATS Banking, Spyware, Dropper clusters)
 *   • ThreatIntelRouter.queryHash (OTX / MalwareBazaar / VirusTotal via VtRateLimitedQueue)
 *   • SecurityEventBus (Cross-domain endpoint awareness)
 *
 * Usage (off main thread):
 *   ApkPreInstallScanner.PreInstallReport report =
 *       ApkPreInstallScanner.scan(context, apkFile, listener);
 */
public class ApkPreInstallScanner {

    private static final String TAG = "ApkPreInstallScanner";

    // ─── Verdict constants ────────────────────────────────────────────────────
    public static final String VERDICT_CLEAN      = "CLEAN";
    public static final String VERDICT_SUSPICIOUS = "SUSPICIOUS";
    public static final String VERDICT_THREAT     = "THREAT";

    // ─── Scan phase listener ─────────────────────────────────────────────────
    public interface ScanPhaseListener {
        void onPhase(String phaseLabel, int progressPercent);
    }

    // ─── Result Parcelable ────────────────────────────────────────────────────
    public static class PreInstallReport implements Parcelable {
        public String apkPath      = "";
        public String appName      = "Unknown";
        public String packageName  = "";
        public String versionName  = "";
        public int    versionCode  = 0;
        public long   apkSizeBytes = 0;

        // Analysis outputs
        public String sha256       = "";
        public int    riskScore    = 0;   // 0–100
        public String verdict      = VERDICT_CLEAN;

        // Update safety & certificate
        public boolean isInstalled = false;
        public String  installedVersionName = "";
        public int     installedVersionCode = 0;
        public String  updateSafetyVerdict = "FRESH_INSTALL"; // FRESH_INSTALL, SAFE_UPDATE, SIGNATURE_MISMATCH, DOWNGRADE_ATTACK
        public String  updateWarningMessage = "";
        public String  certSubjectDn = "";
        public String  certSha256 = "";
        public boolean isDebugKey = false;
        public boolean isCertExpired = false;

        // DEX analysis
        public boolean hasDynamicLoading  = false;
        public boolean hasDangerousExec   = false;
        public boolean hasSmsAbuse        = false;
        public boolean hasPackerStub      = false;
        public int     dexConfidenceScore = 0;
        public List<String> dexFeatures   = new ArrayList<>();

        // Capabilities & Permissions
        public int permissionRiskScore = 0;
        public List<String> flaggedClusters = new ArrayList<>();
        public List<String> criticalCapabilities = new ArrayList<>();

        // Extracted IOCs
        public int extractedIpv4Count = 0;
        public int extractedUrlsCount = 0;
        public int extractedDomainsCount = 0;
        public List<String> extractedSuspiciousStrings = new ArrayList<>();

        // MITRE ATT&CK
        public List<String> mitreTechniques = new ArrayList<>();

        // YARA analysis
        public boolean hasYaraMalicious   = false;
        public boolean hasYaraSuspicious  = false;
        public int     yaraHitsCount      = 0;

        // TI result
        public boolean tiQueried        = false;
        public boolean tiMalicious      = false;
        public boolean tiSuspicious     = false;
        public int     tiRiskScore      = 0;
        public String  tiProvider       = "";
        public String  tiDetails        = "";
        public String  tiMalwareFamily  = "";

        // On-Device ML & AI Threat Explainer (Phase 1 & Phase 2)
        public int     mlRiskScore = 0;
        public String  mlThreatCategory = "";
        public String  aiExplanation = "";
        public String  aiActionPlan = "";
        public String  aiConversationalPrompt = "";

        // Evidence list for display (serialized as String pairs for Parcel simplicity)
        public List<String> evidenceTitles   = new ArrayList<>();
        public List<String> evidenceDetails  = new ArrayList<>();
        public List<String> evidenceSeverity = new ArrayList<>();

        public long scanDurationMs = 0;
        public String errorMessage = "";

        public PreInstallReport() {}

        protected PreInstallReport(Parcel in) {
            apkPath         = in.readString();
            appName         = in.readString();
            packageName     = in.readString();
            versionName     = in.readString();
            versionCode     = in.readInt();
            apkSizeBytes    = in.readLong();
            sha256          = in.readString();
            riskScore       = in.readInt();
            verdict         = in.readString();

            isInstalled          = in.readByte() != 0;
            installedVersionName = in.readString();
            installedVersionCode = in.readInt();
            updateSafetyVerdict  = in.readString();
            updateWarningMessage = in.readString();
            certSubjectDn        = in.readString();
            certSha256           = in.readString();
            isDebugKey           = in.readByte() != 0;
            isCertExpired        = in.readByte() != 0;

            hasDynamicLoading  = in.readByte() != 0;
            hasDangerousExec   = in.readByte() != 0;
            hasSmsAbuse        = in.readByte() != 0;
            hasPackerStub      = in.readByte() != 0;
            dexConfidenceScore = in.readInt();
            dexFeatures        = in.createStringArrayList();

            permissionRiskScore  = in.readInt();
            flaggedClusters      = in.createStringArrayList();
            criticalCapabilities = in.createStringArrayList();

            extractedIpv4Count         = in.readInt();
            extractedUrlsCount         = in.readInt();
            extractedDomainsCount      = in.readInt();
            extractedSuspiciousStrings = in.createStringArrayList();
            mitreTechniques            = in.createStringArrayList();

            hasYaraMalicious   = in.readByte() != 0;
            hasYaraSuspicious  = in.readByte() != 0;
            yaraHitsCount      = in.readInt();
            tiQueried          = in.readByte() != 0;
            tiMalicious        = in.readByte() != 0;
            tiSuspicious       = in.readByte() != 0;
            tiRiskScore        = in.readInt();
            tiProvider         = in.readString();
            tiDetails          = in.readString();
            tiMalwareFamily    = in.readString();
            mlRiskScore        = in.readInt();
            mlThreatCategory   = in.readString();
            aiExplanation      = in.readString();
            aiActionPlan       = in.readString();
            aiConversationalPrompt = in.readString();
            evidenceTitles     = in.createStringArrayList();
            evidenceDetails    = in.createStringArrayList();
            evidenceSeverity   = in.createStringArrayList();
            scanDurationMs     = in.readLong();
            errorMessage       = in.readString();
        }

        @Override
        public void writeToParcel(Parcel dest, int flags) {
            dest.writeString(apkPath);
            dest.writeString(appName);
            dest.writeString(packageName);
            dest.writeString(versionName);
            dest.writeInt(versionCode);
            dest.writeLong(apkSizeBytes);
            dest.writeString(sha256);
            dest.writeInt(riskScore);
            dest.writeString(verdict);

            dest.writeByte((byte) (isInstalled ? 1 : 0));
            dest.writeString(installedVersionName);
            dest.writeInt(installedVersionCode);
            dest.writeString(updateSafetyVerdict);
            dest.writeString(updateWarningMessage);
            dest.writeString(certSubjectDn);
            dest.writeString(certSha256);
            dest.writeByte((byte) (isDebugKey ? 1 : 0));
            dest.writeByte((byte) (isCertExpired ? 1 : 0));

            dest.writeByte((byte) (hasDynamicLoading  ? 1 : 0));
            dest.writeByte((byte) (hasDangerousExec   ? 1 : 0));
            dest.writeByte((byte) (hasSmsAbuse        ? 1 : 0));
            dest.writeByte((byte) (hasPackerStub      ? 1 : 0));
            dest.writeInt(dexConfidenceScore);
            dest.writeStringList(dexFeatures);

            dest.writeInt(permissionRiskScore);
            dest.writeStringList(flaggedClusters);
            dest.writeStringList(criticalCapabilities);

            dest.writeInt(extractedIpv4Count);
            dest.writeInt(extractedUrlsCount);
            dest.writeInt(extractedDomainsCount);
            dest.writeStringList(extractedSuspiciousStrings);
            dest.writeStringList(mitreTechniques);

            dest.writeByte((byte) (hasYaraMalicious   ? 1 : 0));
            dest.writeByte((byte) (hasYaraSuspicious  ? 1 : 0));
            dest.writeInt(yaraHitsCount);
            dest.writeByte((byte) (tiQueried   ? 1 : 0));
            dest.writeByte((byte) (tiMalicious ? 1 : 0));
            dest.writeByte((byte) (tiSuspicious? 1 : 0));
            dest.writeInt(tiRiskScore);
            dest.writeString(tiProvider);
            dest.writeString(tiDetails);
            dest.writeString(tiMalwareFamily);
            dest.writeInt(mlRiskScore);
            dest.writeString(mlThreatCategory);
            dest.writeString(aiExplanation);
            dest.writeString(aiActionPlan);
            dest.writeString(aiConversationalPrompt);
            dest.writeStringList(evidenceTitles);
            dest.writeStringList(evidenceDetails);
            dest.writeStringList(evidenceSeverity);
            dest.writeLong(scanDurationMs);
            dest.writeString(errorMessage);
        }

        @Override public int describeContents() { return 0; }

        public static final Creator<PreInstallReport> CREATOR = new Creator<PreInstallReport>() {
            @Override public PreInstallReport createFromParcel(Parcel in) { return new PreInstallReport(in); }
            @Override public PreInstallReport[] newArray(int size) { return new PreInstallReport[size]; }
        };
    }

    // ─── Main scan entry point ────────────────────────────────────────────────

    /**
     * Performs a full pre-install scan on the given APK file.
     * MUST be called off the main thread.
     */
    public static PreInstallReport scan(Context context, File apkFile, ScanPhaseListener listener) {
        PreInstallReport report = new PreInstallReport();
        long startMs = System.currentTimeMillis();

        if (apkFile == null || !apkFile.exists() || !apkFile.canRead()) {
            report.errorMessage = "APK file not found or not readable";
            report.verdict = VERDICT_SUSPICIOUS;
            return report;
        }

        report.apkPath     = apkFile.getAbsolutePath();
        report.apkSizeBytes= apkFile.length();

        try {
            // ── Phase 1: Extract APK metadata & components ─────────────────────
            notifyPhase(listener, "Reading APK metadata & permissions…", 5);
            PackageManager pm = context.getPackageManager();
            PackageInfo pkgInfo = pm.getPackageArchiveInfo(apkFile.getAbsolutePath(),
                    PackageManager.GET_ACTIVITIES | PackageManager.GET_PERMISSIONS | PackageManager.GET_SERVICES);
            if (pkgInfo != null && pkgInfo.applicationInfo != null) {
                pkgInfo.applicationInfo.sourceDir        = apkFile.getAbsolutePath();
                pkgInfo.applicationInfo.publicSourceDir  = apkFile.getAbsolutePath();
                CharSequence label = pm.getApplicationLabel(pkgInfo.applicationInfo);
                report.appName     = (label != null) ? label.toString() : apkFile.getName();
                report.packageName = pkgInfo.packageName != null ? pkgInfo.packageName : "";
                report.versionName = pkgInfo.versionName  != null ? pkgInfo.versionName  : "";
                report.versionCode = pkgInfo.versionCode;
            } else {
                report.appName = apkFile.getName().replace(".apk", "");
            }

            // Compute SHA-256 hash for forensic records
            report.sha256 = FileHashScanner.computeHash(apkFile, "SHA-256");

            // Immediately whitelist KotSafe self package
            if (report.packageName != null && (report.packageName.equals(context.getPackageName()) || report.packageName.startsWith("com.kotsafe.security") || report.packageName.startsWith("com.kotsafe.security"))) {
                report.verdict = VERDICT_CLEAN;
                report.riskScore = 0;
                addEvidence(report, "✓ Authorized KotSafe Application",
                        "Official built-in security application and authorized build package.",
                        AntivirusEvidenceItem.SEVERITY_CLEAN);
                notifyPhase(listener, "Done", 100);
                report.scanDurationMs = System.currentTimeMillis() - startMs;
                return report;
            }

            // ── Phase 1b: Certificate & Update Safety Analysis ───────────────
            notifyPhase(listener, "Validating signing key & update safety…", 15);
            try {
                CertificateEngine.CertificateProfile certProfile = CertificateEngine.analyzeApkFile(context, apkFile);
                report.certSubjectDn = certProfile.subjectDn;
                report.certSha256 = certProfile.sha256Fingerprint;
                report.isDebugKey = certProfile.isDebugKeystore;
                report.isCertExpired = certProfile.isExpired;

                if (certProfile.isDebugKeystore) {
                    addEvidence(report, "⚠ Signed by Android Debug Key",
                            "APK was signed with an untrusted developer debug key, not a genuine publisher release key.",
                            AntivirusEvidenceItem.SEVERITY_SUSPICIOUS);
                }
                if (certProfile.isExpired) {
                    addEvidence(report, "⚠ Expired Signing Certificate",
                            "Signing certificate expired on " + new java.util.Date(certProfile.validToMs),
                            AntivirusEvidenceItem.SEVERITY_LOW);
                }

                Signature[] apkSigs = CertificateEngine.getApkSignatures(pm, apkFile.getAbsolutePath());
                CertificateEngine.UpdateSafetyCheck safety = CertificateEngine.checkUpdateSafety(
                        context, report.packageName, apkSigs, report.versionCode);
                report.isInstalled = safety.isInstalled;
                report.installedVersionName = safety.installedVersionName;
                report.installedVersionCode = safety.installedVersionCode;
                report.updateSafetyVerdict = safety.safetyVerdict;
                report.updateWarningMessage = safety.warningMessage;

                if ("SIGNATURE_MISMATCH".equals(safety.safetyVerdict)) {
                    report.verdict = VERDICT_THREAT;
                    report.riskScore = 100;
                    addEvidence(report, "🚨 Signature Hijack / Fake Update",
                            safety.warningMessage,
                            AntivirusEvidenceItem.SEVERITY_MALICIOUS);
                    report.mitreTechniques.add("T1458 - Exploitation for Privilege Escalation / Hijack");
                } else if ("DOWNGRADE_ATTACK".equals(safety.safetyVerdict)) {
                    addEvidence(report, "⚠ Version Downgrade Attempt",
                            safety.warningMessage,
                            AntivirusEvidenceItem.SEVERITY_SUSPICIOUS);
                    report.mitreTechniques.add("T1458 - Software Downgrade");
                } else if ("SAFE_UPDATE".equals(safety.safetyVerdict)) {
                    addEvidence(report, "✓ Verified Publisher Update",
                            "Cryptographic signature matches installed version " + safety.installedVersionName + " (Build " + safety.installedVersionCode + ").",
                            AntivirusEvidenceItem.SEVERITY_CLEAN);
                }
            } catch (Exception e) {
                Log.w(TAG, "Signature check error: " + e.getMessage());
            }

            // ── Phase 2: SHA-256 hash & Firewall Blocklist check ───────────────
            notifyPhase(listener, "Computing SHA-256 hash…", 25);
            report.sha256 = FileHashScanner.computeHash(apkFile, "SHA-256");
            Log.d(TAG, "APK sha256=" + report.sha256 + " pkg=" + report.packageName);

            SecurityBlocklistManager blMgr = SecurityBlocklistManager.getInstance(context);
            if (!report.sha256.isEmpty() && blMgr.isHashBlocked(report.sha256)) {
                SecurityRulesDb.SecurityRule rule = blMgr.findBlockRule(report.sha256);
                report.verdict = VERDICT_THREAT;
                report.riskScore = 100;
                String ruleReason = (rule != null && rule.reason != null) ? rule.reason : "Action Center Block";
                addEvidence(report, "🛑 Blocked File Hash",
                        "File SHA-256 is blocked by Firewall Security Policy (" + ruleReason + ")",
                        AntivirusEvidenceItem.SEVERITY_MALICIOUS);

                try {
                    SmartScreenManager.getInstance(context).showFirewallBlockPage(
                            apkFile.getName() + " [SHA-256: " + (report.sha256.length() > 16 ? report.sha256.substring(0, 16) + "…" : report.sha256) + "]",
                            "HASH",
                            ruleReason,
                            report.appName != null ? report.appName : "APK Installer",
                            report.packageName != null ? report.packageName : ""
                    );
                } catch (Exception ignored) {}
            }
            if (report.packageName != null && !report.packageName.isEmpty() && blMgr.isBlocked(report.packageName)) {
                SecurityRulesDb.SecurityRule rule = blMgr.findBlockRule(report.packageName);
                report.verdict = VERDICT_THREAT;
                report.riskScore = 100;
                String ruleReason = (rule != null && rule.reason != null) ? rule.reason : "Action Center Block";
                addEvidence(report, "🛑 Blocked Application Package",
                        "Package is blocked by Firewall Policy (" + ruleReason + ")",
                        AntivirusEvidenceItem.SEVERITY_MALICIOUS);

                try {
                    SmartScreenManager.getInstance(context).showFirewallBlockPage(
                            report.packageName,
                            "APP",
                            ruleReason,
                            report.appName != null ? report.appName : report.packageName,
                            report.packageName
                    );
                } catch (Exception ignored) {}
            }

            // ── Phase 3: DEX structural analysis ─────────────────────────────
            notifyPhase(listener, "DEX structural analysis…", 40);
            DexStructuralParser.DexAnalysisResult dexResult =
                    DexStructuralParser.analyzeApk(apkFile);
            report.hasDynamicLoading  = dexResult.hasDynamicLoading;
            report.hasDangerousExec   = dexResult.hasDangerousExec;
            report.hasSmsAbuse        = dexResult.hasSmsAbuse;
            report.hasPackerStub      = dexResult.hasPackerStub;
            report.dexConfidenceScore = dexResult.heuristicConfidenceScore;
            report.dexFeatures        = new ArrayList<>(dexResult.detectedFeatures);

            if (dexResult.hasDynamicLoading) {
                addEvidence(report, "Dynamic Class Loading", "App loads code at runtime — common in malware loaders", AntivirusEvidenceItem.SEVERITY_SUSPICIOUS);
                report.mitreTechniques.add("T1407 - Download New Code at Runtime");
            }
            if (dexResult.hasDangerousExec) {
                addEvidence(report, "Shell Execution Stub", "App contains Runtime.exec() — potential command injection", AntivirusEvidenceItem.SEVERITY_SUSPICIOUS);
            }
            if (dexResult.hasSmsAbuse) {
                addEvidence(report, "SMS Abuse Pattern", "App references SMS sending APIs suspicious of premium-rate abuse", AntivirusEvidenceItem.SEVERITY_SUSPICIOUS);
            }
            if (dexResult.hasPackerStub) {
                String desc = (dexResult.detectedPackerName != null && !dexResult.detectedPackerName.isEmpty())
                        ? "Packed with " + dexResult.detectedPackerName + " — evading static analysis"
                        : "DEX structure matches known packer signatures — evading static analysis";
                addEvidence(report, "Packer / Obfuscation Detected", desc, AntivirusEvidenceItem.SEVERITY_MALICIOUS);
            }

            // ── Phase 3b: On-Device ML Malware Classifier & Semantic Explainer ──
            if (dexResult.featureVector != null) {
                MlMalwareClassifier.ClassificationResult mlRes =
                        MlMalwareClassifier.getInstance().classify(dexResult.featureVector);
                report.mlRiskScore = mlRes.threatScore;
                report.mlThreatCategory = mlRes.threatCategory;

                if (mlRes.isMalicious || mlRes.isSuspicious) {
                    ThreatContextBuilder.ThreatExplanationReport expReport =
                            ThreatContextBuilder.buildReport(report.appName, report.packageName, mlRes, dexResult.detectedFeatures);
                    report.aiExplanation = expReport.plainEnglishRisk;
                    report.aiActionPlan = expReport.actionPlan;
                    report.aiConversationalPrompt = expReport.conversationalPrompt;

                    for (String tech : expReport.mitreTechniqueLabels) {
                        if (!report.mitreTechniques.contains(tech)) {
                            report.mitreTechniques.add(tech);
                        }
                    }

                    String severity = mlRes.isMalicious ? AntivirusEvidenceItem.SEVERITY_MALICIOUS : AntivirusEvidenceItem.SEVERITY_SUSPICIOUS;
                    String evidenceTitle = "AI Threat Classification: " + mlRes.threatCategory;
                    String evidenceDetail = expReport.headline + " (ML Risk: " + mlRes.threatScore + "/100). "
                            + (mlRes.contributingFeatures.isEmpty() ? "" : "Identified: " + String.join(", ", mlRes.contributingFeatures));
                    addEvidence(report, evidenceTitle, evidenceDetail, severity);
                }
            }

            // ── Phase 3c: Static binary & DEX IOC extraction ─────────────────
            notifyPhase(listener, "Extracting binary IOCs & C2 endpoints…", 50);
            try {
                IOCExtractor.ExtractedIocs iocs = IOCExtractor.extractFromApk(apkFile);
                if (iocs != null) {
                    report.extractedIpv4Count = iocs.ipv4Addresses.size();
                    report.extractedUrlsCount = iocs.urls.size();
                    report.extractedDomainsCount = iocs.suspiciousDomains.size();
                    report.extractedSuspiciousStrings = new ArrayList<>(iocs.suspiciousStringMatches);

                    if (!iocs.suspiciousDomains.isEmpty()) {
                        addEvidence(report, "Suspicious C2 Domain Patterns",
                                "Detected dynamic DNS or suspicious TLDs: " + String.join(", ", iocs.suspiciousDomains),
                                AntivirusEvidenceItem.SEVERITY_SUSPICIOUS);
                        report.mitreTechniques.add("T1437 - Application Layer Protocol C2");
                    }
                    if (!iocs.suspiciousStringMatches.isEmpty()) {
                        addEvidence(report, "High-Risk Strings / Webhooks",
                                "Detected indicators: " + String.join(", ", iocs.suspiciousStringMatches),
                                AntivirusEvidenceItem.SEVERITY_SUSPICIOUS);
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "IOC pre-install extraction error: " + e.getMessage());
            }

            // ── Phase 3d: Permission Capability Evaluation ───────────────────
            notifyPhase(listener, "Analyzing permission capability clusters…", 60);
            try {
                if (pkgInfo != null) {
                    PermissionRiskEngine.PermissionAnalysis permAnalysis =
                            PermissionRiskEngine.analyze(context, pkgInfo, true);
                    report.permissionRiskScore = permAnalysis.riskScore;
                    report.flaggedClusters = new ArrayList<>(permAnalysis.flaggedClusters);
                    report.criticalCapabilities = new ArrayList<>(permAnalysis.criticalCapabilities);

                    for (String cluster : permAnalysis.flaggedClusters) {
                        String sev = AntivirusEvidenceItem.SEVERITY_SUSPICIOUS;
                        if (cluster.contains("Banking Trojan") || cluster.contains("Silent Dropper")) {
                            sev = AntivirusEvidenceItem.SEVERITY_MALICIOUS;
                        }
                        addEvidence(report, "Capability Cluster: " + cluster,
                                "Dangerous capability combination detected in sideloaded package",
                                sev);

                        if (cluster.contains("Banking Trojan")) {
                            MitreMapper.TechniqueInfo ti = MitreMapper.mapPattern("BANKING_TROJAN");
                            if (ti != null) report.mitreTechniques.add(ti.techniqueId + " - " + ti.name);
                        } else if (cluster.contains("Spyware") || cluster.contains("Surveillance")) {
                            MitreMapper.TechniqueInfo ti = MitreMapper.mapPattern("SURVEILLANCE_SPYWARE");
                            if (ti != null) report.mitreTechniques.add(ti.techniqueId + " - " + ti.name);
                        } else if (cluster.contains("Dropper")) {
                            MitreMapper.TechniqueInfo ti = MitreMapper.mapPattern("SLEEPER_DROPPER");
                            if (ti != null) report.mitreTechniques.add(ti.techniqueId + " - " + ti.name);
                        }
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "Permission risk analysis error: " + e.getMessage());
            }

            // ── Phase 3e: YARA rule engine pattern matching ──────────────────
            notifyPhase(listener, "Scanning with YARA rules…", 70);
            try {
                YaraRuleEngine yaraEngine = YaraRuleEngine.getInstance(context);
                List<YaraRuleEngine.YaraMatch> yaraMatches = yaraEngine.scanApk(apkFile, report.packageName);
                if (yaraMatches != null && !yaraMatches.isEmpty()) {
                    report.yaraHitsCount = yaraMatches.size();
                    for (YaraRuleEngine.YaraMatch match : yaraMatches) {
                        String sev = match.severity != null ? match.severity : AntivirusEvidenceItem.SEVERITY_SUSPICIOUS;
                        String detail = match.description != null ? match.description : "YARA rule match";
                        if (match.matchedStrings != null && !match.matchedStrings.isEmpty()) {
                            detail += " (Matches: " + String.join(", ", match.matchedStrings) + ")";
                        }
                        addEvidence(report, "YARA: " + match.ruleName, detail, sev);
                        if (AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(sev)) {
                            report.hasYaraMalicious = true;
                        } else {
                            report.hasYaraSuspicious = true;
                        }
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "YARA pre-install scan error: " + e.getMessage());
            }

            // ── Phase 4: Threat Intelligence lookup (privacy-gated) ───────────
            notifyPhase(listener, "Threat Intelligence lookup…", 80);
            ThreatIntelApiClient apiClient = ThreatIntelApiClient.getInstance(context);
            if (!report.sha256.isEmpty()
                    && apiClient.hasAnyApiKey()
                    && apiClient.isAutoThreatQueryEnabled()) {

                report.tiQueried = true;
                ThreatIntelRouter router = ThreatIntelRouter.getInstance(context);
                ThreatIntelProvider.ThreatReport tiReport = router.queryHash(report.sha256);

                if (tiReport != null) {
                    report.tiMalicious     = tiReport.isMalicious;
                    report.tiSuspicious    = tiReport.isSuspicious;
                    report.tiRiskScore     = tiReport.riskScore;
                    report.tiProvider      = tiReport.provider != null ? tiReport.provider : "";
                    report.tiDetails       = tiReport.details != null ? tiReport.details : "";
                    report.tiMalwareFamily = tiReport.malwareFamily != null ? tiReport.malwareFamily : "";

                    if (tiReport.isMalicious) {
                        String detail = tiReport.details != null ? tiReport.details
                                : "Confirmed malicious by " + tiReport.provider;
                        addEvidence(report, "⛔ Threat Intel: MALICIOUS",
                                "[" + tiReport.provider + "] " + detail,
                                AntivirusEvidenceItem.SEVERITY_MALICIOUS);
                    } else if (tiReport.isSuspicious) {
                        addEvidence(report, "⚠ Threat Intel: SUSPICIOUS",
                                "[" + tiReport.provider + "] " + tiReport.details,
                                AntivirusEvidenceItem.SEVERITY_SUSPICIOUS);
                    } else {
                        addEvidence(report, "✓ Threat Intel: Clean",
                                "Checked by " + tiReport.provider + " — no known threats",
                                AntivirusEvidenceItem.SEVERITY_CLEAN);
                    }
                }
            } else {
                addEvidence(report, "TI Lookup: Offline / Skipped",
                        report.sha256.isEmpty()
                                ? "Could not compute hash"
                                : "No API keys configured — offline mode only",
                        AntivirusEvidenceItem.SEVERITY_LOW);
            }

            // ── Phase 5: Compute final risk score & verdict ───────────────────
            notifyPhase(listener, "Computing verdict & MITRE alignment…", 90);
            boolean tiVerifiedClean = report.tiQueried && !report.tiMalicious && !report.tiSuspicious && report.tiRiskScore == 0;
            report.verdict   = scoreToVerdict(report.riskScore, report.tiMalicious, report.hasYaraMalicious, report.updateSafetyVerdict, tiVerifiedClean);

            // ── Phase 6: Persist hash to FileHashDbHelper ─────────────────────
            if (!report.sha256.isEmpty()) {
                try {
                    FileHashDbHelper hashDb = FileHashDbHelper.getInstance(context);
                    FileHashEntry entry = new FileHashEntry();
                    entry.fileName         = apkFile.getName();
                    entry.filePath         = apkFile.getAbsolutePath();
                    entry.packageName      = report.packageName;
                    entry.appName          = report.appName;
                    entry.sha256           = report.sha256;
                    entry.fileSize         = apkFile.length();
                    entry.fileLastModified = apkFile.lastModified();
                    entry.fileClass        = FileHashEntry.FILE_CLASS_APK;
                    entry.scanType         = FileHashEntry.SCAN_TYPE_APP;
                    entry.scanPriority     = FileHashEntry.PRIORITY_CRITICAL;
                    entry.scanStatus       = FileHashEntry.SCAN_STATUS_DONE;
                    entry.isSystemApp      = false;
                    entry.threatStatus     = report.tiMalicious ? FileHashEntry.THREAT_MALICIOUS
                            : report.tiSuspicious ? FileHashEntry.THREAT_SUSPICIOUS
                            : FileHashEntry.THREAT_CLEAN;
                    hashDb.upsertFileHash(entry);
                } catch (Exception e) {
                    Log.w(TAG, "Could not persist hash to DB: " + e.getMessage());
                }
            }

            // ── Phase 7: Publish to SecurityEventBus ──────────────────────────
            try {
                SecurityEventBus bus = SecurityEventBus.getInstance();
                String eventType = VERDICT_THREAT.equals(report.verdict) ? EventTypes.FILE_THREAT
                        : VERDICT_SUSPICIOUS.equals(report.verdict) ? EventTypes.SUSPICIOUS_PERMISSIONS
                        : EventTypes.APK_DETECTED;
                SecurityEvent.Severity severity = VERDICT_THREAT.equals(report.verdict) ? SecurityEvent.Severity.CRITICAL
                        : VERDICT_SUSPICIOUS.equals(report.verdict) ? SecurityEvent.Severity.HIGH
                        : SecurityEvent.Severity.INFO;

                bus.publish(new SecurityEvent.Builder(SecurityEvent.Domain.ANTIVIRUS, eventType)
                        .severity(severity)
                        .title("Sideload Scan: " + (report.appName.isEmpty() ? apkFile.getName() : report.appName))
                        .description("Verdict=" + report.verdict + " Risk=" + report.riskScore + "/100 Safety=" + report.updateSafetyVerdict)
                        .subject(report.packageName, -1)
                        .attribute("riskScore", report.riskScore)
                        .attribute("sha256", report.sha256)
                        .attribute("verdict", report.verdict)
                        .attribute("updateSafety", report.updateSafetyVerdict)
                        .attribute("mitreTechniques", report.mitreTechniques)
                        .build());
            } catch (Exception e) {
                Log.w(TAG, "EventBus publication error: " + e.getMessage());
            }

        } catch (Exception e) {
            Log.e(TAG, "Pre-install scan failed: " + e.getMessage());
            report.errorMessage = e.getMessage();
            if (report.verdict.equals(VERDICT_CLEAN)) {
                report.verdict = VERDICT_SUSPICIOUS; // err on side of caution
            }
        }

        notifyPhase(listener, "Done", 100);
        report.scanDurationMs = System.currentTimeMillis() - startMs;
        return report;
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private static void addEvidence(PreInstallReport r, String title, String detail, String severity) {
        r.evidenceTitles.add(title);
        r.evidenceDetails.add(detail);
        r.evidenceSeverity.add(severity);
    }

    private static void notifyPhase(ScanPhaseListener l, String label, int pct) {
        if (l != null) l.onPhase(label, pct);
    }

    /**
     * Weighted risk score combining DEX heuristic, capability analysis, IOCs, and TI scores.
     */
    private static int computeFinalRiskScore(PreInstallReport r) {
        // Signature mismatch is a critical compromise
        if ("SIGNATURE_MISMATCH".equals(r.updateSafetyVerdict)) {
            return 100;
        }

        int score = 0;

        // TI score carries the most weight
        if (r.tiQueried && r.tiRiskScore > 0) {
            score += (int)(r.tiRiskScore * 0.5f);
        }

        // If Threat Intelligence verified this hash as clean (0 pulses / risk score 0),
        // apply anti-false-positive damping to capability and string heuristics
        boolean tiVerifiedClean = r.tiQueried && !r.tiMalicious && !r.tiSuspicious && r.tiRiskScore == 0;
        float heuristicDamping = tiVerifiedClean ? 0.5f : 1.0f;

        // DEX heuristic adds up to 30 points
        score += (int)(r.dexConfidenceScore * 0.3f * heuristicDamping);

        // Permission capability clustering
        if (r.permissionRiskScore > 0) {
            score += (int)(r.permissionRiskScore * 0.35f * heuristicDamping);
        }

        // Extracted IOCs
        if (r.extractedDomainsCount > 0) {
            score += (int)(25 * heuristicDamping);
        }
        if (!r.extractedSuspiciousStrings.isEmpty()) {
            score += (int)(20 * heuristicDamping);
        }

        // Debug key
        if (r.isDebugKey) {
            score += (int)(20 * heuristicDamping);
        }

        // YARA rules
        if (r.hasYaraMalicious) {
            score = Math.max(score, 85);
        } else if (r.hasYaraSuspicious) {
            score = Math.max(score, 55);
        }

        // Hard escalations
        if (r.tiMalicious)    score = Math.max(score, 85);
        if (r.hasPackerStub)  score = Math.max(score, 50);
        if (r.tiSuspicious && r.hasPackerStub) score = Math.max(score, 70);

        // Dynamic Dalvik Dropper Escalation (pre-empting /data/data/ evasion)
        if (r.hasDynamicLoading && (r.hasPackerStub || r.permissionRiskScore >= 35 || r.hasDangerousExec)) {
            score = Math.max(score, 75);
            addEvidence(r, "Suspicious Dynamic Dropper Profile",
                    "App combines dynamic Dalvik class loading with high-risk permissions or packed stubs (T1027.002 / T1407)",
                    AntivirusEvidenceItem.SEVERITY_MALICIOUS);
            if (!r.mitreTechniques.contains("T1027.002 - Software Packing / Dynamic Dropper")) {
                r.mitreTechniques.add("T1027.002 - Software Packing / Dynamic Dropper");
            }
        }

        // On-Device ML Classifier Evaluation
        if (r.mlRiskScore > 0) {
            if (r.mlRiskScore >= 70) {
                score = Math.max(score, r.mlRiskScore);
            } else if (r.mlRiskScore >= 40) {
                score = Math.max(score, (int)(r.mlRiskScore * 0.85f));
            }
        }

        return Math.min(score, 100);
    }

    private static String scoreToVerdict(int score, boolean tiConfirmedMalicious, boolean hasYaraMalicious, String updateVerdict, boolean tiVerifiedClean) {
        if ("SIGNATURE_MISMATCH".equals(updateVerdict)) return VERDICT_THREAT;
        if (tiConfirmedMalicious || hasYaraMalicious) return VERDICT_THREAT;
        // Clean Threat Intelligence prevents heuristics alone from declaring THREAT (caps at SUSPICIOUS)
        if (score >= 70 && !tiVerifiedClean) return VERDICT_THREAT;
        if (score >= 30)                         return VERDICT_SUSPICIOUS;
        return VERDICT_CLEAN;
    }

    /**
     * Attempts to extract the APK icon. Returns null on failure (caller shows placeholder).
     * Must be called on a thread where PackageManager is available.
     */
    public static Drawable extractApkIcon(Context context, String apkPath) {
        try {
            PackageManager pm = context.getPackageManager();
            PackageInfo pi = pm.getPackageArchiveInfo(apkPath, 0);
            if (pi != null && pi.applicationInfo != null) {
                pi.applicationInfo.sourceDir       = apkPath;
                pi.applicationInfo.publicSourceDir = apkPath;
                return pm.getApplicationIcon(pi.applicationInfo);
            }
        } catch (Exception e) {
            Log.w(TAG, "Could not extract APK icon: " + e.getMessage());
        }
        return null;
    }
}
