/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * RiskEngine
 * ==========
 * Central multi-factor decision engine for Antivirus & Endpoint Detection.
 * Decouples assessment into three distinct dimensions:
 *   1. Verdict:    UNKNOWN | TRUSTED | CLEAN | MONITOR | SUSPICIOUS | MALICIOUS
 *   2. Severity:   INFO | LOW | MEDIUM | HIGH | CRITICAL
 *   3. Confidence: LOW | MEDIUM | HIGH
 * Accompanied by explainable forensic reasons.
 */

package com.kotsafe.security.model;

import java.util.ArrayList;
import java.util.List;

public class RiskEngine {
    private static final String TAG = "RiskEngine";

    public enum Verdict {
        UNKNOWN,
        TRUSTED,
        CLEAN,
        MONITOR,
        SUSPICIOUS,
        MALICIOUS
    }

    public enum Severity {
        INFO,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    public enum Confidence {
        LOW,
        MEDIUM,
        HIGH
    }

    public static class RiskAssessment {
        public Verdict verdict = Verdict.UNKNOWN;
        public Severity severity = Severity.INFO;
        public Confidence confidence = Confidence.LOW;
        public int riskScore = 0; // 0-100
        public List<String> forensicReasons = new ArrayList<>();
        public String humanSummary = "";
    }

    public static RiskAssessment evaluateApp(AppIntelligenceEngine.AppSecurityProfile profile,
                                             IOCExtractor.ExtractedIocs iocs,
                                             boolean isHashBlacklisted,
                                             boolean hasYaraMatches) {
        RiskAssessment assessment = new RiskAssessment();
        if (profile == null) return assessment;

        // 1. Authorized KotSafe Self & Core Android System Components
        if (profile.isSelfKotSafe) {
            assessment.verdict = Verdict.TRUSTED;
            assessment.severity = Severity.INFO;
            assessment.confidence = Confidence.HIGH;
            assessment.riskScore = 0;
            assessment.humanSummary = "KotSafe Sentinel Engine Component";
            return assessment;
        }

        if (profile.isSystemApp) {
            assessment.verdict = Verdict.TRUSTED;
            assessment.severity = Severity.INFO;
            assessment.confidence = Confidence.HIGH;
            assessment.riskScore = 5;
            assessment.humanSummary = "Protected Android OS System Package";
            return assessment;
        }

        int score = 0;

        // 2. Known Malicious Hash Signature
        if (isHashBlacklisted) {
            assessment.verdict = Verdict.MALICIOUS;
            assessment.severity = Severity.CRITICAL;
            assessment.confidence = Confidence.HIGH;
            assessment.riskScore = 100;
            assessment.forensicReasons.add("SHA-256 matched threat intelligence blacklist");
            assessment.humanSummary = "Known Malicious Threat Signature";
            return assessment;
        }

        // 3. YARA Rule Match
        if (hasYaraMatches) {
            score += 50;
            assessment.forensicReasons.add("Matched malware binary signature pattern (YARA)");
        }

        // 4. Certificate Inconsistencies
        if (profile.certificateProfile != null) {
            if (profile.certificateProfile.isDebugKeystore) {
                score += profile.isSideloaded ? 35 : 20;
                assessment.forensicReasons.add("Signed by public Android Debug Key");
            }
            if (profile.certificateProfile.isExpired) {
                score += 15;
                assessment.forensicReasons.add("Signing certificate is expired");
            }
        }

        // 5. Contextual Combinatorial Permissions
        if (profile.permissionAnalysis != null) {
            score += (int) (profile.permissionAnalysis.riskScore * 0.45);
            for (String cluster : profile.permissionAnalysis.flaggedClusters) {
                assessment.forensicReasons.add(cluster);
            }
        }

        // 6. Extracted IOCs (Embedded C2, dynamic code loaders)
        if (iocs != null) {
            if (!iocs.suspiciousDomains.isEmpty()) {
                score += 25;
                assessment.forensicReasons.add("Embedded dynamic/suspicious domain in binary: " + String.join(", ", iocs.suspiciousDomains));
            }
            if (!iocs.suspiciousStringMatches.isEmpty()) {
                score += 20;
                assessment.forensicReasons.add("Suspicious executable references: " + String.join(", ", iocs.suspiciousStringMatches));
            }
        }

        // 7. Install Source & Trust Anchor
        if (profile.isVettedStoreInstall) {
            score = (int) (score * 0.6); // 40% reduction for vetted store installs
        } else if (profile.isSideloaded) {
            score += 15;
            assessment.forensicReasons.add("Installed via sideloading / non-store source");
        }

        assessment.riskScore = Math.min(100, Math.max(0, score));

        // Triage Mapping
        if (assessment.riskScore >= 75) {
            assessment.verdict = Verdict.MALICIOUS;
            assessment.severity = Severity.CRITICAL;
            assessment.confidence = Confidence.HIGH;
            assessment.humanSummary = "High-confidence malicious payload detected";
        } else if (assessment.riskScore >= 50) {
            assessment.verdict = Verdict.SUSPICIOUS;
            assessment.severity = Severity.HIGH;
            assessment.confidence = Confidence.HIGH;
            assessment.humanSummary = "Suspicious capability combination and provenance";
        } else if (assessment.riskScore >= 30) {
            assessment.verdict = Verdict.MONITOR;
            assessment.severity = Severity.MEDIUM;
            assessment.confidence = Confidence.MEDIUM;
            assessment.humanSummary = "Elevated capabilities monitored under baseline";
        } else if (assessment.riskScore >= 10) {
            assessment.verdict = Verdict.CLEAN;
            assessment.severity = Severity.LOW;
            assessment.confidence = Confidence.HIGH;
            assessment.humanSummary = "Standard application profile";
        } else {
            assessment.verdict = Verdict.TRUSTED;
            assessment.severity = Severity.INFO;
            assessment.confidence = Confidence.HIGH;
            assessment.humanSummary = "Trusted verified application";
        }

        return assessment;
    }
}
