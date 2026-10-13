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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.kotsafe.security.ai.ml.MlMalwareClassifier;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

/**
 * Unit tests for Phase 2 AI Threat Explainer & Semantic Reasoning Engine.
 */
public class ThreatExplainerTest {

    @Test
    public void testCleanAppReport_ProvidesReassuringExplanation() {
        ThreatContextBuilder.ThreatExplanationReport report =
                ThreatContextBuilder.buildReport("Legitimate Calculator", "com.example.calc", null, Collections.emptyList());

        assertNotNull(report);
        assertEquals("Clean Application", report.headline);
        assertEquals(0, report.riskScore);
        assertEquals(MlMalwareClassifier.CATEGORY_CLEAN, report.category);
        assertTrue(report.actionPlan.contains("No remediation required"));
    }

    @Test
    public void testBankingTrojanReport_TranslatesTechnicalFeaturesToPlainEnglish() {
        MlMalwareClassifier.ClassificationResult mlResult = new MlMalwareClassifier.ClassificationResult();
        mlResult.threatCategory = MlMalwareClassifier.CATEGORY_BANKING_TROJAN;
        mlResult.threatScore = 88;
        mlResult.isMalicious = true;
        mlResult.contributingFeatures = Arrays.asList(
                "Accessibility Service Binding",
                "System Alert Overlay Window",
                "SMS Interception APIs"
        );

        ThreatContextBuilder.ThreatExplanationReport report =
                ThreatContextBuilder.buildReport("FlashUpdate", "com.fake.flash", mlResult, mlResult.contributingFeatures);

        assertNotNull(report);
        assertTrue(report.headline.contains("Banking Trojan"));
        assertEquals(88, report.riskScore);
        assertTrue(report.plainEnglishRisk.contains("banking"));
        assertTrue(report.actionPlan.contains("Uninstall this application immediately"));
        assertNotNull(report.conversationalPrompt);
        assertTrue(report.conversationalPrompt.contains("com.fake.flash"));

        // Verify MITRE technique correlation
        assertFalse(report.mitreTechniqueLabels.isEmpty());
        assertTrue(report.mitreTechniqueLabels.stream().anyMatch(t -> t.contains("T1417") || t.contains("Input Capture")));
    }

    @Test
    public void testOfflineKnowledgeEngine_GeneratesFullThreatDossier() {
        String explanation = OfflineKnowledgeEngine.generateApkThreatExplainerResponse(
                "QuickLoan",
                "com.quick.loan.apk",
                82,
                MlMalwareClassifier.CATEGORY_SPYWARE_RAT,
                Arrays.asList("Audio/Mic Recording", "Background Location Tracking", "SMS Interception"),
                "Uninstall app and revoke sensitive permissions immediately."
        );

        assertNotNull(explanation);
        assertTrue(explanation.contains("QuickLoan"));
        assertTrue(explanation.contains("SPYWARE_RAT"));
        assertTrue(explanation.contains("Why this app is dangerous:"));
        assertTrue(explanation.contains("What KotSafe did:"));
        assertTrue(explanation.contains("What you should do:"));
    }
}
