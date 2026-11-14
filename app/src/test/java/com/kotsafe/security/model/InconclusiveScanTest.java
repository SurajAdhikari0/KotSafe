package com.kotsafe.security.model;

import android.app.Application;
import android.content.Context;
import android.os.Parcel;
import androidx.test.core.app.ApplicationProvider;
import java.lang.reflect.Field;
import java.util.List;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(application=Application.class, sdk=33, manifest=Config.NONE)
public class InconclusiveScanTest {
    @Test public void unknownProvidersDoNotMergeToCleanOrPreventRetry() throws Exception {
        Context context = ApplicationProvider.getApplicationContext();
        ThreatIntelRouter router = ThreatIntelRouter.getInstance(context);
        Field field = ThreatIntelRouter.class.getDeclaredField("mProviders");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<ThreatIntelProvider> providers = (List<ThreatIntelProvider>) field.get(router);
        final String hash = "a".repeat(64);
        final ThreatIntelProvider.ThreatReport error = ThreatIntelProvider.ThreatReport.error("fixture", hash);
        KotSafeCloudProvider fixture = new KotSafeCloudProvider(context) {
            public boolean isAvailable() { return true; }
            public ThreatReport queryHash(String value) { return error; }
        };
        try {
            providers.clear();
            providers.add(fixture);
            providers.add(fixture);
            assertEquals("UNKNOWN",router.queryHash(hash).verdict);
            assertNull(TiCacheDb.getInstance(context).lookup(hash));
            error.verdict = "CLEAN";
            assertTrue(router.queryHash(hash).isVerifiedClean());
            assertNotNull(TiCacheDb.getInstance(context).lookup(hash));
        } finally {
            router.refresh();
        }
    }

    @Test public void inconclusiveLookupPreservesLocalScoreAndParcelState() {
        ApkPreInstallScanner.PreInstallReport report = new ApkPreInstallScanner.PreInstallReport();
        report.dexConfidenceScore = 100;
        int local = ApkPreInstallScanner.computeFinalRiskScore(report);
        report.tiQueried = true;
        assertEquals(30,local);
        assertEquals(local,ApkPreInstallScanner.computeFinalRiskScore(report));
        Parcel parcel = Parcel.obtain();
        try {
            report.writeToParcel(parcel,0);
            parcel.setDataPosition(0);
            ApkPreInstallScanner.PreInstallReport restored = ApkPreInstallScanner.PreInstallReport.CREATOR.createFromParcel(parcel);
            assertTrue(restored.tiQueried);
            assertFalse(restored.tiVerifiedClean);
            assertEquals(local,ApkPreInstallScanner.computeFinalRiskScore(restored));
        } finally { parcel.recycle(); }
        report.tiVerifiedClean = true;
        assertEquals(15,ApkPreInstallScanner.computeFinalRiskScore(report));
    }
}
