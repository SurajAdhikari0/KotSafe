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

package com.kotsafe.security.ai;

import com.kotsafe.security.ai.ml.MlMalwareClassifier;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds structured semantic threat context and plain-English AI explanations (Phase 2).
 */
public class ThreatContextBuilder {

    public static class ThreatExplanationReport {
        public String appName;
        public String packageName;
        public String headline;
        public String plainEnglishRisk;
        public int riskScore;
        public String category;
        public List<String> detectedCapabilities = new ArrayList<>();
        public List<String> mitreTechniqueLabels = new ArrayList<>();
        public String actionPlan;
        public String conversationalPrompt;
    }

    public static ThreatExplanationReport buildReport(String appName, String packageName,
                                                      MlMalwareClassifier.ClassificationResult mlResult,
                                                      List<String> detectedFeatures) {
        ThreatExplanationReport report = new ThreatExplanationReport();
        report.appName = appName != null && !appName.isEmpty() ? appName : "Scanned Package";
        report.packageName = packageName != null ? packageName : "";

        if (mlResult == null) {
            report.headline = "Clean Application";
            report.plainEnglishRisk = "No anomalous bytecode structures or high-risk capability vectors were identified.";
            report.riskScore = 0;
            report.category = MlMalwareClassifier.CATEGORY_CLEAN;
            report.actionPlan = "No remediation required. The application is safe to use.";
            return report;
        }

        report.riskScore = mlResult.threatScore;
        report.category = mlResult.threatCategory;

        // Collect capabilities
        if (detectedFeatures != null) {
            for (String f : detectedFeatures) {
                if (!report.detectedCapabilities.contains(f)) {
                    report.detectedCapabilities.add(f);
                }
            }
        }
        for (String c : mlResult.contributingFeatures) {
            if (!report.detectedCapabilities.contains(c)) {
                report.detectedCapabilities.add(c);
            }
        }

        // Map MITRE Techniques
        List<MitreAttackMapper.MitreTechnique> techniques = MitreAttackMapper.mapTechniques(report.detectedCapabilities);
        for (MitreAttackMapper.MitreTechnique t : techniques) {
            report.mitreTechniqueLabels.add(t.toString());
        }

        // Generate tailored plain-English explanation
        StringBuilder sb = new StringBuilder();
        StringBuilder actionSb = new StringBuilder();

        switch (mlResult.threatCategory) {
            case MlMalwareClassifier.CATEGORY_BANKING_TROJAN:
                report.headline = "⚠️ High Risk: Banking Trojan / Overlay Hijacker";
                sb.append("KotSafe's AI analysis detected patterns typical of mobile banking trojans. ")
                  .append("This app requests powerful screen overlay and accessibility capabilities that can be used to ")
                  .append("draw fake login screens over banking and crypto apps and intercept two-factor SMS codes.\n\n")
                  .append("Why this is dangerous: An attacker can steal financial credentials and bypass two-factor authentication without your knowledge.");
                actionSb.append("1. Do not enter any login credentials or PINs.\n")
                        .append("2. Go to Settings > Accessibility and ensure this app is disabled.\n")
                        .append("3. Uninstall this application immediately.");
                break;

            case MlMalwareClassifier.CATEGORY_DROPPER_PACKER:
                report.headline = "⚠️ Suspicious: Dropper / Commercial Packer Stager";
                sb.append("This package exhibits dropper characteristics (a very small code footprint combined with a heavy encrypted asset payload). ")
                  .append("It contains code designed to download or unpack secondary executable bytecode at runtime, bypassing initial store review.\n\n")
                  .append("Why this is dangerous: Droppers often masquerade as harmless utilities and later download malicious payloads after installation.");
                actionSb.append("1. Verify if you obtained this app from an official vetted source.\n")
                        .append("2. Revoke 'Install unknown apps' permission for this app.\n")
                        .append("3. Quarantine or remove if not from a trusted developer.");
                break;

            case MlMalwareClassifier.CATEGORY_SPYWARE_RAT:
                report.headline = "⚠️ Surveillance Risk: Spyware / Remote Access Trojan";
                sb.append("This application contains surveillance and remote control capabilities. ")
                  .append("It pairs background audio/camera access with continuous GPS tracking, device serial harvesting, and direct shell process execution.\n\n")
                  .append("Why this is dangerous: It allows an unauthorized third party to monitor your communications, track your physical location, and access private files.");
                actionSb.append("1. Check Settings > Apps > Permissions and revoke Camera, Mic, and Location.\n")
                        .append("2. Put device in Airplane Mode if unexpected battery drain or overheating occurs.\n")
                        .append("3. Uninstall the application immediately.");
                break;

            case MlMalwareClassifier.CATEGORY_SMS_FRAUD:
                report.headline = "⚠️ Financial Risk: Premium SMS & WAP Fraud";
                sb.append("This application has been flagged for SMS abuse routines. ")
                  .append("It attempts background SMS message generation and boot autostart, characteristic of toll fraud and silent premium billing subscription trojans.");
                actionSb.append("1. Check your cellular bill for unauthorized carrier billing.\n")
                        .append("2. Revoke SMS permissions for this app.\n")
                        .append("3. Uninstall the application.");
                break;

            case MlMalwareClassifier.CATEGORY_GENERIC_MALWARE:
                report.headline = "🔍 Moderate Risk: Suspicious Obfuscation & Sideload Profile";
                sb.append("The application presents multiple anomalous characteristics, including high string entropy, debug certificate identity, or evasive SDK targeting. ")
                  .append("While no specific malware family signature was confirmed, its structural posture warrants caution.");
                actionSb.append("1. Review permissions granted to this application.\n")
                        .append("2. Avoid granting Accessibility or Device Admin permissions.\n")
                        .append("3. Monitor network activity in KotSafe.");
                break;

            default:
                report.headline = "Clean Application";
                sb.append("KotSafe's AI structural inspection verified this package. No hostile API sinks or dropper stubs were detected.");
                actionSb.append("No action required. The package is verified clean.");
                break;
        }

        report.plainEnglishRisk = sb.toString();
        report.actionPlan = actionSb.toString();

        // Conversational AI Prompt (for chat assistant)
        report.conversationalPrompt = "KotSafe AI Security Audit for " + report.appName + " (" + report.packageName + "):\n"
                + "Threat Category: " + report.category + " (Risk Score: " + report.riskScore + "/100)\n"
                + "Capabilities: " + String.join(", ", report.detectedCapabilities) + "\n"
                + "Explain how this threat operates in detail, what data it can access, and give me a step-by-step security action plan.";

        return report;
    }
}
