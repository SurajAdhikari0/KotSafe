package com.kotsafe.security.model;

import android.app.Application;
import android.content.Context;
import androidx.preference.Preference;
import androidx.preference.PreferenceManager;
import androidx.preference.PreferenceScreen;
import androidx.test.core.app.ApplicationProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(application=Application.class, sdk=33, manifest=Config.NONE)
public class AdvancedSettingsVisibilityTest {
    @Test public void simpleModeHidesTechnicalControlsAndRestoresTheirOriginalVisibility() {
        Context context = ApplicationProvider.getApplicationContext();
        PreferenceScreen screen = new PreferenceManager(context).createPreferenceScreen(context);
        Preference basic = new Preference(context);
        basic.setKey("antivirus_scan_action");
        Preference technical = new Preference(context);
        technical.setKey("tls_decryption");
        Preference unavailable = new Preference(context);
        unavailable.setKey("root_capture");
        unavailable.setVisible(false);
        screen.addPreference(basic);
        screen.addPreference(technical);
        screen.addPreference(unavailable);
        AdvancedSettingsVisibility.apply(screen, false);
        assertTrue(basic.isVisible());
        assertFalse(technical.isVisible());
        AdvancedSettingsVisibility.apply(screen, true);
        assertTrue(technical.isVisible());
        assertFalse(unavailable.isVisible());
    }
}
