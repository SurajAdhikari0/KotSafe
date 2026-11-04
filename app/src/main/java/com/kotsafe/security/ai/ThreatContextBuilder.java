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

        // These are static capabilities, not proof that any behavior occurred.
        if (mlResult.isSuspicious || mlResult.isMalicious) {
            report.headline = "Suspicious app capabilities — review recommended";
            report.plainEnglishRisk = "Static analysis found capabilities that can be used by both legitimate apps and malware. "
                    + "This is not a confirmed malware detection. Heuristic risk score: " + mlResult.threatScore + "/100."
                    + "\n\nObserved indicators:\n" + String.join("\n", mlResult.contributingFeatures);
            report.actionPlan = "Verify the app's developer and source. Review whether its requested permissions fit its purpose. "
                    + "If you do not recognize or trust it, restrict its access or use Android's uninstall option.";
        } else {
            report.headline = "No suspicious static pattern found";
            report.plainEnglishRisk = "This structural check found no suspicious pattern. It does not prove that the app is safe.";
            report.actionPlan = "No action required from this check.";
        }

        // Conversational AI Prompt (for chat assistant)
        report.conversationalPrompt = "KotSafe AI Security Audit for " + report.appName + " (" + report.packageName + "):\n"
                + "Threat Category: " + report.category + " (Risk Score: " + report.riskScore + "/100)\n"
                + "Capabilities: " + String.join(", ", report.detectedCapabilities) + "\n"
                + "Explain the potential risks of these static capabilities without assuming malware or observed abuse, and suggest proportionate review steps.";

        return report;
    }
}
