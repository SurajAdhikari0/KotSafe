/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security;

import com.kotsafe.security.model.AlertRecord;
import com.kotsafe.security.model.AntivirusEvidenceItem;
import com.kotsafe.security.model.AntivirusScanEngine;

import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.ArrayList;

@RunWith(RobolectricTestRunner.class)
@Config(application = TestKotSafe.class)
public class QuarantineScoreReanalysisTest {

    @Before
    public void setUp() {
        KotSafe.isUnderTest = true;
    }

    @Test
    public void testQuarantineScoreReanalysis_RestoresScoreWhenThreatsContained() {
        AntivirusScanEngine.ScanResult result = new AntivirusScanEngine.ScanResult();
        result.totalStorageScanned = 10;
        result.evidenceList = new ArrayList<>();

        // Create 2 malicious threats and 1 suspicious threat
        AntivirusEvidenceItem threat1 = new AntivirusEvidenceItem(
                AntivirusEvidenceItem.TYPE_STORAGE_FILE,
                "Trojan.Dropper",
                "/sdcard/Download/malware.apk",
                "malware.apk",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                "High-confidence malware signature matched"
        );
        threat1.filePath = "/sdcard/Download/malware.apk";

        AntivirusEvidenceItem threat2 = new AntivirusEvidenceItem(
                AntivirusEvidenceItem.TYPE_STORAGE_FILE,
                "Exploit.PDF",
                "/sdcard/Download/invoice.pdf",
                "invoice.pdf",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                "Malicious embedded JavaScript exploit detected"
        );
        threat2.filePath = "/sdcard/Download/invoice.pdf";

        AntivirusEvidenceItem threat3 = new AntivirusEvidenceItem(
                AntivirusEvidenceItem.TYPE_STORAGE_FILE,
                "Suspicious.Doc",
                "/sdcard/Documents/resume.doc",
                "resume.doc",
                AntivirusEvidenceItem.SEVERITY_SUSPICIOUS,
                "Obfuscated VBA macro detected"
        );
        threat3.filePath = "/sdcard/Documents/resume.doc";

        result.evidenceList.add(threat1);
        result.evidenceList.add(threat2);
        result.evidenceList.add(threat3);

        result.threatsDetected = 2;
        result.suspiciousDetected = 1;

        // Initial score calculation
        int initialScore = 100 - (result.threatsDetected * 30) - (result.suspiciousDetected * 8);
        result.securityScore = initialScore;
        Assert.assertEquals(32, initialScore);

        // Simulate moving threat1 and threat2 to Quarantine
        threat1.isQuarantined = true;
        threat1.severity = AntivirusEvidenceItem.SEVERITY_RESOLVED;
        threat1.verdict = "QUARANTINED";

        threat2.isQuarantined = true;
        threat2.severity = AntivirusEvidenceItem.SEVERITY_RESOLVED;
        threat2.verdict = "QUARANTINED";

        // Re-analyze score
        int remainingThreats = 0;
        int remainingSuspicious = 0;
        for (AntivirusEvidenceItem ev : result.evidenceList) {
            if (ev.isQuarantined || AntivirusEvidenceItem.SEVERITY_RESOLVED.equals(ev.severity)) {
                continue;
            }
            if (AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(ev.severity)) {
                remainingThreats++;
            } else if (AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equals(ev.severity)) {
                remainingSuspicious++;
            }
        }

        Assert.assertEquals(0, remainingThreats);
        Assert.assertEquals(1, remainingSuspicious);

        int reanalyzedScore = 100 - (remainingThreats * 30) - (remainingSuspicious * 8);
        result.threatsDetected = remainingThreats;
        result.suspiciousDetected = remainingSuspicious;
        result.securityScore = reanalyzedScore;

        Assert.assertEquals(92, reanalyzedScore);

        // Now quarantine the last suspicious threat
        threat3.isQuarantined = true;
        threat3.severity = AntivirusEvidenceItem.SEVERITY_RESOLVED;
        threat3.verdict = "QUARANTINED";

        remainingThreats = 0;
        remainingSuspicious = 0;
        for (AntivirusEvidenceItem ev : result.evidenceList) {
            if (ev.isQuarantined || AntivirusEvidenceItem.SEVERITY_RESOLVED.equals(ev.severity)) {
                continue;
            }
            if (AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(ev.severity)) {
                remainingThreats++;
            } else if (AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equals(ev.severity)) {
                remainingSuspicious++;
            }
        }

        int finalScore = 100;
        if (remainingThreats == 0 && remainingSuspicious == 0) {
            finalScore = 100;
        }
        result.threatsDetected = remainingThreats;
        result.suspiciousDetected = remainingSuspicious;
        result.securityScore = finalScore;

        Assert.assertEquals(100, finalScore);
        Assert.assertEquals(0, result.threatsDetected);
        Assert.assertEquals(0, result.suspiciousDetected);
    }

    @Test
    public void testAlertRecord_QuarantineMetadataAndRiskReleaseSerialization() throws Exception {
        AlertRecord alert = new AlertRecord(
                "alert-1234",
                System.currentTimeMillis(),
                AlertRecord.Severity.HIGH,
                AlertRecord.AlertType.QUARANTINE,
                "Threat Quarantined: malware.apk",
                "File isolated in Sandboxed Vault.",
                "malware.apk"
        );
        alert.setQuarantineMetadata(42L, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "/sdcard/Download/malware.apk");

        JSONObject json = alert.toJson();
        Assert.assertEquals(42L, json.getLong("qRecId"));
        Assert.assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", json.getString("qSha"));
        Assert.assertEquals("/sdcard/Download/malware.apk", json.getString("qPath"));
        Assert.assertFalse(json.getBoolean("isReleased"));

        // Simulate risk accepted and released by user
        alert.isReleased = true;
        JSONObject releasedJson = alert.toJson();
        AlertRecord restoredAlert = AlertRecord.fromJson(releasedJson);
        Assert.assertTrue(restoredAlert.isReleased);
        Assert.assertEquals(42L, restoredAlert.quarantineRecordId);
        Assert.assertEquals("/sdcard/Download/malware.apk", restoredAlert.quarantinePath);
    }
}
