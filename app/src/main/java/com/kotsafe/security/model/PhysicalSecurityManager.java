package com.kotsafe.security.model;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.media.Ringtone;
import android.media.RingtoneManager;
import android.net.Uri;
import android.telephony.TelephonyManager;
import android.util.Base64;
import android.util.Log;

import androidx.preference.PreferenceManager;

import com.kotsafe.security.receivers.DeviceAdminReceiverImpl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PhysicalSecurityManager {
    private static final String TAG = "PhysicalSecurityManager";
    private static final String PREF_MASTER_ENABLED = "pref_phys_sec_master_enabled";
    private static final String PREF_PIN_HASH = "pref_phys_sec_pin_hash";
    private static final String PREF_PIN_SALT = "pref_phys_sec_pin_salt";
    private static final String PREF_PIN_ITER = "pref_phys_sec_pin_iter";
    private static final String PREF_APP_LOCK_ENABLED = "pref_phys_sec_app_lock";
    private static final String PREF_KOTSAFE_APP_LOCK_ENABLED = "pref_phys_sec_kotsafe_app_lock";
    private static final String PREF_BIOMETRIC_ENABLED = "pref_phys_sec_biometric";
    private static final String PREF_LOCKED_PACKAGES = "pref_phys_sec_locked_packages";
    private static final String PREF_ANTI_THEFT_ENABLED = "pref_phys_sec_anti_theft";
    private static final String PREF_CHARGER_ALARM_ENABLED = "pref_phys_sec_charger_alarm";
    private static final String PREF_POCKET_ALARM_ENABLED = "pref_phys_sec_pocket_alarm";
    private static final String PREF_TAMPER_PROTECT_ENABLED = "pref_phys_sec_tamper_protect";
    private static final String PREF_SCREENSHOT_BLOCK_ENABLED = "pref_phys_sec_screenshot_block";
    private static final String PREF_SCREENSHOT_PROTECTED_PACKAGES = "pref_screenshot_protected_packages";
    private static final String PREF_SIM_SWAP_ENABLED = "pref_phys_sec_sim_swap";
    private static final String PREF_SIM_BASELINE_HASH = "pref_phys_sec_sim_baseline_hash";
    private static final String PREF_FIREWALL_LOCKDOWN_ENABLED = "pref_phys_sec_firewall_lockdown";
    public static final String PREF_BAD_USB_AUTO_LOCK = "pref_phys_sec_bad_usb_auto_lock";

    private static final int PBKDF2_ITERATIONS = 120_000;
    /** Maximum consecutive in-app auth failures before device lockout is triggered. */
    private static final int MAX_FAILED_AUTH_ATTEMPTS = 5;

    private static volatile PhysicalSecurityManager sInstance;
    private final Context mContext;
    private final SharedPreferences mPrefs;
    private SensorManager mSensorManager;
    private Sensor mProximitySensor;
    private boolean mPocketAlarmArmed = false;
    private boolean mWasInPocket = false;
    private Ringtone mAlarmRingtone;
    private volatile boolean mSessionAuthenticated = false;
    private int mFailedAuthAttempts = 0;

    private PhysicalSecurityManager(Context context) {
        mContext = context.getApplicationContext();
        mPrefs = PreferenceManager.getDefaultSharedPreferences(mContext);
    }

    public static PhysicalSecurityManager getInstance(Context context) {
        if (sInstance == null) {
            synchronized (PhysicalSecurityManager.class) {
                if (sInstance == null) {
                    sInstance = new PhysicalSecurityManager(context);
                }
            }
        }
        return sInstance;
    }

    public boolean isMasterSecurityEnabled() {
        return mPrefs.getBoolean(PREF_MASTER_ENABLED, false);
    }

    public void setMasterSecurityEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(PREF_MASTER_ENABLED, enabled).apply();
    }

    public boolean isPinSet() {
        return mPrefs.contains(PREF_PIN_HASH) && !mPrefs.getString(PREF_PIN_HASH, "").isEmpty();
    }

    public boolean setPin(String newPin) {
        if (newPin == null || newPin.length() < 4) return false;
        try {
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            byte[] hash = pbkdf2(newPin.toCharArray(), salt);
            mPrefs.edit()
                    .putString(PREF_PIN_HASH, Base64.encodeToString(hash, Base64.NO_WRAP))
                    .putString(PREF_PIN_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
                    .putInt(PREF_PIN_ITER, PBKDF2_ITERATIONS)
                    .apply();
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed setting PIN hash with PBKDF2: " + e.getMessage());
            return false;
        }
    }

    public boolean verifyPin(String enteredPin) {
        if (!isPinSet() || enteredPin == null) return false;
        try {
            int iter = mPrefs.getInt(PREF_PIN_ITER, 0);
            if (iter > 0) {
                byte[] salt = Base64.decode(mPrefs.getString(PREF_PIN_SALT, ""), Base64.NO_WRAP);
                byte[] stored = Base64.decode(mPrefs.getString(PREF_PIN_HASH, ""), Base64.NO_WRAP);
                byte[] computed = pbkdf2(enteredPin.toCharArray(), salt);
                boolean match = MessageDigest.isEqual(stored, computed);
                if (match) onAuthSuccess(); else onAuthFailure();
                return match;
            } else {
                String salt = mPrefs.getString(PREF_PIN_SALT, "");
                String storedHash = mPrefs.getString(PREF_PIN_HASH, "");
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest((enteredPin + salt).getBytes(StandardCharsets.UTF_8));
                String computedHash = Base64.encodeToString(hash, Base64.NO_WRAP);
                boolean match = storedHash.equals(computedHash);
                if (match) {
                    onAuthSuccess();
                    setPin(enteredPin); // Auto migrate to PBKDF2
                } else {
                    onAuthFailure();
                }
                return match;
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed verifying PIN: " + e.getMessage());
            onAuthFailure();
            return false;
        }
    }

    private static byte[] pbkdf2(char[] pin, byte[] salt) throws Exception {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return f.generateSecret(new PBEKeySpec(pin, salt, PBKDF2_ITERATIONS, 256)).getEncoded();
    }

    public void onAuthSuccess() {
        mSessionAuthenticated = true;
        mFailedAuthAttempts = 0;
    }

    public void onAuthFailure() {
        mFailedAuthAttempts++;
        Log.w(TAG, "Failed in-app auth attempt #" + mFailedAuthAttempts);
        // PS-007 Fix: Trigger device lockout after MAX_FAILED_AUTH_ATTEMPTS consecutive failures.
        // This prevents brute-force enumeration of 4-digit PINs (10,000 combinations).
        if (mFailedAuthAttempts >= MAX_FAILED_AUTH_ATTEMPTS) {
            Log.e(TAG, "[SECURITY] Max auth failures reached — locking device now!");
            mFailedAuthAttempts = 0; // Reset counter to prevent repeated lockout calls
            mSessionAuthenticated = false;
            lockDeviceNow(); // Invokes DevicePolicyManager.lockNow() if admin is active
        }
    }

    public boolean isSessionAuthenticated() {
        return mSessionAuthenticated;
    }

    public void setSessionAuthenticated(boolean authenticated) {
        mSessionAuthenticated = authenticated;
        if (authenticated) mFailedAuthAttempts = 0;
    }

    public boolean isKotSafeAppLockEnabled() {
        return isMasterSecurityEnabled() && isPinSet() && mPrefs.getBoolean(PREF_KOTSAFE_APP_LOCK_ENABLED, false);
    }

    public void setKotSafeAppLockEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(PREF_KOTSAFE_APP_LOCK_ENABLED, enabled).apply();
    }

    public boolean isBiometricEnabled() {
        return isMasterSecurityEnabled() && mPrefs.getBoolean(PREF_BIOMETRIC_ENABLED, true);
    }

    public void setBiometricEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(PREF_BIOMETRIC_ENABLED, enabled).apply();
    }

    public boolean isAppLockEnabled() {
        return isMasterSecurityEnabled() && mPrefs.getBoolean(PREF_APP_LOCK_ENABLED, false);
    }

    public void setAppLockEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(PREF_APP_LOCK_ENABLED, enabled).apply();
    }

    public Set<String> getLockedPackages() {
        return mPrefs.getStringSet(PREF_LOCKED_PACKAGES, new HashSet<>());
    }

    public void setLockedPackages(Set<String> packages) {
        mPrefs.edit().putStringSet(PREF_LOCKED_PACKAGES, packages).apply();
    }

    public boolean isAntiTheftEnabled() {
        return isMasterSecurityEnabled() && mPrefs.getBoolean(PREF_ANTI_THEFT_ENABLED, false);
    }

    public void setAntiTheftEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(PREF_ANTI_THEFT_ENABLED, enabled).apply();
    }

    public boolean isDeviceAdminActive() {
        DevicePolicyManager dpm = (DevicePolicyManager) mContext.getSystemService(Context.DEVICE_POLICY_SERVICE);
        ComponentName admin = new ComponentName(mContext, DeviceAdminReceiverImpl.class);
        return dpm != null && dpm.isAdminActive(admin);
    }

    public boolean lockDeviceNow() {
        try {
            DevicePolicyManager dpm = (DevicePolicyManager) mContext.getSystemService(Context.DEVICE_POLICY_SERVICE);
            ComponentName admin = new ComponentName(mContext, DeviceAdminReceiverImpl.class);
            if (dpm != null && dpm.isAdminActive(admin)) {
                dpm.lockNow();
                return true;
            }
        } catch (Exception e) {
            Log.e(TAG, "lockDeviceNow error: " + e.getMessage());
        }
        return false;
    }

    /**
     * Active Lockdown / Focus Trap:
     * 1. If Device Admin is granted: instantly turns off display and locks hardware Keyguard.
     * 2. Zero-Permission Play Protect Safe Fallback: Launches LockOverlayActivity immediately
     *    with FLAG_ACTIVITY_NEW_TASK | FLAG_SHOW_WHEN_LOCKED, capturing window focus and trapping
     *    all injected keystrokes inside an isolated authentication screen.
     */
    public void lockOrTrapFocus(String reason) {
        if (lockDeviceNow()) {
            Log.w(TAG, "[AUTO-LOCK] Device screen locked via DevicePolicyManager: " + reason);
            return;
        }

        try {
            Intent lockIntent = new Intent(mContext, com.kotsafe.security.activities.LockOverlayActivity.class);
            lockIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            lockIntent.putExtra("reason", reason);
            mContext.startActivity(lockIntent);
            Log.w(TAG, "[AUTO-LOCK] Focus trap engaged via LockOverlayActivity: " + reason);
        } catch (Exception e) {
            Log.e(TAG, "[AUTO-LOCK] Failed to engage focus trap: " + e.getMessage());
        }
    }

    public boolean isBadUsbAutoLockEnabled() {
        return mPrefs.getBoolean(PREF_BAD_USB_AUTO_LOCK, true);
    }

    public void setBadUsbAutoLockEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(PREF_BAD_USB_AUTO_LOCK, enabled).apply();
    }

    public boolean isChargerAlarmEnabled() {
        return isMasterSecurityEnabled() && mPrefs.getBoolean(PREF_CHARGER_ALARM_ENABLED, false);
    }

    public void setChargerAlarmEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(PREF_CHARGER_ALARM_ENABLED, enabled).apply();
    }

    public boolean isPocketAlarmEnabled() {
        return isMasterSecurityEnabled() && mPrefs.getBoolean(PREF_POCKET_ALARM_ENABLED, false);
    }

    public void setPocketAlarmEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(PREF_POCKET_ALARM_ENABLED, enabled).apply();
        if (enabled) {
            armPocketSensor();
        } else {
            disarmPocketSensor();
        }
    }

    public synchronized void armPocketSensor() {
        if (mPocketAlarmArmed) return;
        mSensorManager = (SensorManager) mContext.getSystemService(Context.SENSOR_SERVICE);
        if (mSensorManager != null) {
            mProximitySensor = mSensorManager.getDefaultSensor(Sensor.TYPE_PROXIMITY);
            if (mProximitySensor != null) {
                mSensorManager.registerListener(mPocketListener, mProximitySensor, SensorManager.SENSOR_DELAY_NORMAL);
                mPocketAlarmArmed = true;
                mWasInPocket = false;
                Log.i(TAG, "Pocket Sensor Armed");
            }
        }
    }

    public synchronized void disarmPocketSensor() {
        if (!mPocketAlarmArmed) return;
        if (mSensorManager != null && mProximitySensor != null) {
            mSensorManager.unregisterListener(mPocketListener, mProximitySensor);
        }
        stopSiren();
        mPocketAlarmArmed = false;
        Log.i(TAG, "Pocket Sensor Disarmed");
    }

    private final SensorEventListener mPocketListener = new SensorEventListener() {
        @Override
        public void onSensorChanged(SensorEvent event) {
            if (event.sensor.getType() != Sensor.TYPE_PROXIMITY) return;
            float distance = event.values[0];
            float maxRange = event.sensor.getMaximumRange();
            boolean isClose = distance < maxRange;
            if (isClose) {
                mWasInPocket = true;
            } else if (mWasInPocket) {
                triggerSiren("Pocket Removal Detected");
            }
        }

        @Override
        public void onAccuracyChanged(Sensor sensor, int accuracy) {}
    };

    public void triggerSiren(String reason) {
        try {
            if (mAlarmRingtone == null) {
                Uri alert = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM);
                if (alert == null) alert = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE);
                mAlarmRingtone = RingtoneManager.getRingtone(mContext, alert);
            }
            if (mAlarmRingtone != null && !mAlarmRingtone.isPlaying()) {
                mAlarmRingtone.play();
                Log.w(TAG, "Physical Security Siren Triggered: " + reason);
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed playing siren: " + e.getMessage());
        }
    }

    public void stopSiren() {
        if (mAlarmRingtone != null && mAlarmRingtone.isPlaying()) {
            mAlarmRingtone.stop();
        }
    }

    public boolean isTamperProtectionEnabled() {
        return isMasterSecurityEnabled() && mPrefs.getBoolean(PREF_TAMPER_PROTECT_ENABLED, false);
    }

    public void setTamperProtectionEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(PREF_TAMPER_PROTECT_ENABLED, enabled).apply();
    }

    public boolean isScreenshotProtectionEnabled() {
        return isMasterSecurityEnabled() && mPrefs.getBoolean(PREF_SCREENSHOT_BLOCK_ENABLED, false);
    }

    public void setScreenshotProtectionEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(PREF_SCREENSHOT_BLOCK_ENABLED, enabled).apply();
    }

    /** Returns the set of package names that should have screenshot blocking active. */
    public Set<String> getScreenshotProtectedPackages() {
        return new HashSet<>(mPrefs.getStringSet(PREF_SCREENSHOT_PROTECTED_PACKAGES, new HashSet<>()));
    }

    /** Persists the set of packages for which screenshots should be blocked via overlay. */
    public void setScreenshotProtectedPackages(Set<String> packages) {
        mPrefs.edit().putStringSet(PREF_SCREENSHOT_PROTECTED_PACKAGES, packages).apply();
    }

    /** Returns true if the given package is in the screenshot-block list. */
    public boolean isScreenshotBlockedForPackage(String packageName) {
        if (packageName == null) return false;
        return getScreenshotProtectedPackages().contains(packageName);
    }

    public boolean isSimSwapDetectionEnabled() {
        return isMasterSecurityEnabled() && mPrefs.getBoolean(PREF_SIM_SWAP_ENABLED, false);
    }

    public void setSimSwapDetectionEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(PREF_SIM_SWAP_ENABLED, enabled).apply();
    }

    public void updateSimBaseline() {
        try {
            TelephonyManager tm = (TelephonyManager) mContext.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm != null) {
                String simOp = tm.getSimOperatorName() + ":" + tm.getSimCountryIso();
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(simOp.getBytes(StandardCharsets.UTF_8));
                String hashB64 = Base64.encodeToString(hash, Base64.NO_WRAP);
                mPrefs.edit().putString(PREF_SIM_BASELINE_HASH, hashB64).apply();
                Log.i(TAG, "SIM baseline updated: " + simOp);
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed updating SIM baseline: " + e.getMessage());
        }
    }

    public boolean isFirewallLockdownEnabled() {
        return isMasterSecurityEnabled() && mPrefs.getBoolean(PREF_FIREWALL_LOCKDOWN_ENABLED, false);
    }

    public void setFirewallLockdownEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(PREF_FIREWALL_LOCKDOWN_ENABLED, enabled).apply();
    }
}
