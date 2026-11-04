package com.kotsafe.security.model;
import static org.junit.Assert.*;
import android.app.Application;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(application = Application.class, sdk = 34, manifest = Config.NONE)
public class ApkVerdictTest {
    @Test public void highHeuristicScoreWithUnknownHashRequiresReview() {
        for (int score : new int[]{30, 69, 70, 85, 100})
            assertEquals(ApkPreInstallScanner.VERDICT_SUSPICIOUS,
                    ApkPreInstallScanner.scoreToVerdict(score, false, false, "", false));
    }
    @Test public void independentEvidenceIsNotDowngraded() {
        assertEquals(ApkPreInstallScanner.VERDICT_THREAT,
                ApkPreInstallScanner.scoreToVerdict(10, true, false, "", false));
        assertEquals(ApkPreInstallScanner.VERDICT_THREAT,
                ApkPreInstallScanner.scoreToVerdict(10, false, true, "", true));
        assertEquals(ApkPreInstallScanner.VERDICT_THREAT,
                ApkPreInstallScanner.scoreToVerdict(10, false, false, "SIGNATURE_MISMATCH", true));
    }
    @Test public void lowRiskWithoutPositiveEvidenceDoesNotBecomeAnAlert() {
        assertEquals(ApkPreInstallScanner.VERDICT_CLEAN,
                ApkPreInstallScanner.scoreToVerdict(10, false, false, "", false));
    }
    @Test public void scanReportDoesNotInventFalsePositiveMeasurements() {
        String report = AntivirusScanEngine.generateAuditReport(null, new AntivirusScanEngine.ScanResult());
        assertTrue(report.contains("Not measured"));
        assertFalse(report.contains("0.00%"));
    }
}
