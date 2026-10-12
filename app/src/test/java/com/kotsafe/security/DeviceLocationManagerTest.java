/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.preference.PreferenceManager;
import androidx.test.core.app.ApplicationProvider;

import com.kotsafe.security.model.DeviceLocationManager;

import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

@RunWith(RobolectricTestRunner.class)
public class DeviceLocationManagerTest {

    private Context mContext;
    private DeviceLocationManager mLocManager;
    private SharedPreferences mPrefs;

    @Before
    public void setUp() {
        mContext = ApplicationProvider.getApplicationContext();
        DeviceLocationManager.resetInstanceForTesting();
        mPrefs = PreferenceManager.getDefaultSharedPreferences(mContext);
        mPrefs.edit()
                .putBoolean(DeviceLocationManager.PREF_LOCATION_ENABLED, false)
                .putBoolean(DeviceLocationManager.PREF_ATTACH_TO_SIEM, false)
                .commit();
        mLocManager = DeviceLocationManager.getInstance(mContext);
    }

    @Test
    public void testDisabledByDefault() {
        // Privacy requirement: location sharing MUST be disabled by default
        assertFalse(mLocManager.isLocationEnabled());
        assertFalse(mLocManager.isAttachToSiemEnabled());
        assertNull(mLocManager.getLocationTelemetryJson());
    }

    @Test
    public void testAttachToSiemRequiresMasterEnable() {
        mPrefs.edit().putBoolean(DeviceLocationManager.PREF_ATTACH_TO_SIEM, true).commit();
        // Since master toggle is false, isAttachToSiemEnabled must still return false
        assertFalse(mLocManager.isAttachToSiemEnabled());

        mPrefs.edit().putBoolean(DeviceLocationManager.PREF_LOCATION_ENABLED, true).commit();
        assertTrue(mLocManager.isLocationEnabled());
        assertTrue(mLocManager.isAttachToSiemEnabled());
    }
}
