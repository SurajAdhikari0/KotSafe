/*
 * =========================================================================================
 * PROPRIETARY & COPYRIGHT NOTICE - STRICT AI RESTRICTION & NON-DISCLOSURE POLICY
 * =========================================================================================
 * Copyright (c) 2026 KotSafe Cyber Security Project. All Rights Reserved.
 *
 * PROPRIETARY INTELLECTUAL PROPERTY:
 * This software, architecture, algorithms, and implementation details within this P2P module
 * are the exclusive, copyrighted intellectual property of the author/owner.
 * =========================================================================================
 */

package com.kotsafe.security.p2p;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.preference.PreferenceManager;

import com.kotsafe.security.BuildConfig;
import com.kotsafe.security.Utils;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.android.gms.tasks.Tasks;
import java.util.concurrent.TimeUnit;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * P2PLicenseManager
 *
 * Manages authentic KotSafe Pro & Enterprise activation keys, enforces device
 * seat limits (Free = 1 device, Pro = 5 devices, Enterprise = 25+ devices), and validates
 * license signatures against kotsafe.com.
 */
public final class P2PLicenseManager {

    private static final String TAG = "P2PLicenseManager";
    public static final String PRODUCTION_LICENSE_URL = "https://kotsafe.com/api/v1/license";

    private static final String PREF_IS_PRO_ACTIVATED = "p2p_license_is_pro_activated";
    private static final String PREF_LICENSE_KEY = "p2p_license_active_key";
    private static final String PREF_LICENSE_TIER = "p2p_license_tier";
    private static final String PREF_LICENSE_EXPIRES = "p2p_license_expires_epoch";
    private static final String PREF_LICENSE_MAX_DEVICES = "p2p_license_max_devices";
    private static final String PREF_LICENSE_ACTIVE_DEVICES = "p2p_license_active_devices";
    private static final String PREF_LICENSE_TOKEN = "p2p_license_server_token";
    private static final String PREF_LICENSE_LAST_VERIFIED = "p2p_license_last_verified_ts";

    public enum Tier {
        FREE,
        PRO,
        ENTERPRISE,
        LIFETIME
    }

    public interface LicenseCallback {
        void onSuccess(Tier tier, int maxDevices, long expiresAt);
        void onError(String errorMessage);
    }

    public interface DeactivateCallback {
        void onSuccess();
        void onError(String errorMessage);
    }

    private static P2PLicenseManager sInstance;
    private final Context mContext;
    private final SharedPreferences mPrefs;
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
    private final Handler mMainHandler = new Handler(Looper.getMainLooper());

    public static synchronized P2PLicenseManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new P2PLicenseManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private P2PLicenseManager(Context context) {
        mContext = context;
        mPrefs = PreferenceManager.getDefaultSharedPreferences(context);
        mMainHandler.postDelayed(new Runnable() {
            @Override public void run() {
                if (!getActiveLicenseKey().isEmpty()) verifyWithServer(null);
                mMainHandler.postDelayed(this, 15 * 60 * 1000L);
            }
        }, 5000L);
    }

    /**
     * Checks whether the current device holds an active verified Pro, Enterprise, or Lifetime license.
     */
    public boolean isProActivated() {
        if (!mPrefs.getBoolean(PREF_IS_PRO_ACTIVATED, false)) {
            return false;
        }
        String key = getActiveLicenseKey();
        if (key.isEmpty()) {
            return false;
        }
        long expiresAt = mPrefs.getLong(PREF_LICENSE_EXPIRES, 0);
        if (expiresAt > 0 && System.currentTimeMillis() > expiresAt) {
            Log.w(TAG, "KotSafe Pro license expired at: " + expiresAt);
            revokeLicense();
            return false;
        }
        String token = mPrefs.getString(PREF_LICENSE_TOKEN, "");
        if (token.isEmpty()) {
            // Unverified key without server token
            return false;
        }
        long verified = mPrefs.getLong(PREF_LICENSE_LAST_VERIFIED, 0L);
        long age = System.currentTimeMillis() - verified;
        return verified > 0 && age >= 0 && age <= 24 * 60 * 60 * 1000L;
    }

    /**
     * Returns the current license tier (FREE, PRO, ENTERPRISE, LIFETIME).
     */
    public Tier getLicenseTier() {
        if (!isProActivated()) {
            return Tier.FREE;
        }
        String tierStr = mPrefs.getString(PREF_LICENSE_TIER, "PRO");
        try {
            return Tier.valueOf(tierStr.toUpperCase(Locale.US));
        } catch (Exception e) {
            return Tier.PRO;
        }
    }

    /**
     * Returns the maximum number of concurrent exit devices permitted:
     * Free Tier = 1 Device
     * Pro Tier = 5 Devices (or server provisioned limit)
     * Enterprise Tier = 25+ Devices
     */
    public int getMaxAllowedExitDevices() {
        if (!isProActivated()) {
            return 1; // Strict Freemium Enforcement
        }
        return mPrefs.getInt(PREF_LICENSE_MAX_DEVICES, 5);
    }

    /**
     * Returns the count of registered active devices on this license.
     */
    public int getActiveDevicesCount() {
        if (!isProActivated()) {
            return 1;
        }
        return mPrefs.getInt(PREF_LICENSE_ACTIVE_DEVICES, 1);
    }

    /**
     * Returns license expiration timestamp (ms epoch). 0 means lifetime.
     */
    public long getLicenseExpiresAt() {
        return mPrefs.getLong(PREF_LICENSE_EXPIRES, 0);
    }

    public String getActiveLicenseKey() {
        return mPrefs.getString(PREF_LICENSE_KEY, "");
    }

    public String getOrCreateDeviceId() {
        String id = mPrefs.getString(GatewayPreferenceKeys.DEVICE_ID, "");
        if (id.isEmpty()) {
            id = "dev_" + Utils.genRandomString(16);
            mPrefs.edit().putString(GatewayPreferenceKeys.DEVICE_ID, id).apply();
        }
        return id;
    }

    private String getLicenseApiBaseUrl() {
        // Licensing is independent of the pairing relay. Never send account tokens to a custom relay.
        return PRODUCTION_LICENSE_URL;
    }

    private void authorize(HttpURLConnection connection) throws Exception {
        FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
        if (user == null) throw new IllegalStateException("Sign in before managing a license.");
        String token = Tasks.await(user.getIdToken(false), 15, TimeUnit.SECONDS).getToken();
        if (token == null || token.isEmpty()) throw new IllegalStateException("Sign in again to refresh your account.");
        connection.setRequestProperty("Authorization", "Bearer " + token);
        connection.setRequestProperty("X-KotSafe-Device-Id", getOrCreateDeviceId());
    }

    /**
     * Activates a license key with the official kotsafe.com licensing backend.
     */
    public void activateLicense(String rawKey, LicenseCallback callback) {
        if (rawKey == null || rawKey.trim().isEmpty()) {
            callback.onError("Please enter a valid activation key");
            return;
        }

        final String cleanKey = rawKey.trim().toUpperCase(Locale.US);

        if (!cleanKey.startsWith("KOT-")) {
            callback.onError("Invalid activation key format. KotSafe keys begin with KOT-");
            return;
        }

        final String deviceId = getOrCreateDeviceId();
        final String deviceName = Build.MANUFACTURER + " " + Build.MODEL;
        final String osVersion = "Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")";
        final String appVersion = BuildConfig.VERSION_NAME;

        mExecutor.execute(() -> {
            HttpURLConnection conn = null;
            try {
                URL url = new URL(getLicenseApiBaseUrl() + "/activate");
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                authorize(conn);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Accept", "application/json");
                conn.setConnectTimeout(8000);
                conn.setReadTimeout(8000);
                conn.setDoOutput(true);

                JSONObject req = new JSONObject();
                req.put("license_key", cleanKey);
                req.put("device_id", deviceId);
                req.put("platform", "android");
                req.put("device_name", deviceName);
                req.put("os_version", osVersion);
                req.put("app_version", appVersion);

                try (OutputStream os = conn.getOutputStream()) {
                    os.write(req.toString().getBytes(StandardCharsets.UTF_8));
                }

                int code = conn.getResponseCode();
                String responseBody = readStream(code >= 200 && code < 400 ? conn.getInputStream() : conn.getErrorStream());
                JSONObject resp = new JSONObject(responseBody);

                if (code == 200 && resp.optBoolean("success", false)) {
                    String serverTier = resp.optString("tier", "PRO");
                    Tier tier = parseTier(serverTier);
                    int maxDevices = resp.optInt("max_devices", 5);
                    int activeDevices = resp.optInt("active_devices", 1);
                    long expiresAt = resp.optLong("expires_at", 0);
                    String token = resp.optString("token", "");

                    mPrefs.edit()
                            .putBoolean(PREF_IS_PRO_ACTIVATED, true)
                            .putString(PREF_LICENSE_KEY, cleanKey)
                            .putString(PREF_LICENSE_TIER, tier.name())
                            .putLong(PREF_LICENSE_EXPIRES, expiresAt)
                            .putInt(PREF_LICENSE_MAX_DEVICES, maxDevices)
                            .putInt(PREF_LICENSE_ACTIVE_DEVICES, activeDevices)
                            .putString(PREF_LICENSE_TOKEN, token)
                            .putLong(PREF_LICENSE_LAST_VERIFIED, System.currentTimeMillis())
                            .putString(GatewayPreferenceKeys.EXIT_MAX_DEVICES, String.valueOf(maxDevices))
                            .apply();

                    Log.i(TAG, "KotSafe " + tier + " license activated! Max devices: " + maxDevices);
                    mMainHandler.post(() -> callback.onSuccess(tier, maxDevices, expiresAt));

                } else if (code == 409) {
                    // Seat limit reached
                    String msg = resp.optString("message", "Seat limit reached for this license. Please deactivate an existing device first.");
                    mMainHandler.post(() -> callback.onError(msg));

                } else {
                    String msg = resp.optString("message", "Activation failed (HTTP " + code + "). Please check your key.");
                    revokeLicense();
                    mMainHandler.post(() -> callback.onError(msg));
                }

            } catch (Exception e) {
                Log.e(TAG, "License activation error: " + e.getMessage(), e);
                mMainHandler.post(() -> callback.onError("Network error connecting to kotsafe.com: " + e.getMessage()));
            } finally {
                if (conn != null) conn.disconnect();
            }
        });
    }

    /**
     * Automatically activates this device using the active license linked to the user's KotSafe account.
     */
    public void activateFromAccount(String email, LicenseCallback callback) {
        final String deviceId = getOrCreateDeviceId();
        final String deviceName = Build.MANUFACTURER + " " + Build.MODEL;
        final String osVersion = "Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")";
        final String appVersion = BuildConfig.VERSION_NAME;

        mExecutor.execute(() -> {
            HttpURLConnection conn = null;
            try {
                URL url = new URL(getLicenseApiBaseUrl() + "/account-activate");
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                authorize(conn);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Accept", "application/json");
                conn.setConnectTimeout(8000);
                conn.setReadTimeout(8000);
                conn.setDoOutput(true);

                JSONObject req = new JSONObject();
                req.put("device_id", deviceId);
                req.put("platform", "android");
                req.put("device_name", deviceName);
                req.put("os_version", osVersion);
                req.put("app_version", appVersion);


                try (OutputStream os = conn.getOutputStream()) {
                    os.write(req.toString().getBytes(StandardCharsets.UTF_8));
                }

                int code = conn.getResponseCode();
                String responseBody = readStream(code >= 200 && code < 400 ? conn.getInputStream() : conn.getErrorStream());
                JSONObject resp = new JSONObject(responseBody);

                if (code == 200 && resp.optBoolean("valid", false)) {
                    String cleanKey = resp.optString("license_key", "");
                    String serverTier = resp.optString("tier", "PRO");
                    Tier tier = parseTier(serverTier);
                    int maxDevices = resp.optInt("max_devices", 5);
                    int activeDevices = resp.optInt("active_devices", 1);
                    long expiresAt = resp.optLong("expires_at", 0);
                    String token = resp.optString("token", "");

                    mPrefs.edit()
                            .putBoolean(PREF_IS_PRO_ACTIVATED, true)
                            .putString(PREF_LICENSE_KEY, cleanKey)
                            .putString(PREF_LICENSE_TIER, tier.name())
                            .putLong(PREF_LICENSE_EXPIRES, expiresAt)
                            .putInt(PREF_LICENSE_MAX_DEVICES, maxDevices)
                            .putInt(PREF_LICENSE_ACTIVE_DEVICES, activeDevices)
                            .putString(PREF_LICENSE_TOKEN, token)
                            .putLong(PREF_LICENSE_LAST_VERIFIED, System.currentTimeMillis())
                            .putString(GatewayPreferenceKeys.EXIT_MAX_DEVICES, String.valueOf(maxDevices))
                            .apply();

                    mMainHandler.post(() -> {
                        if (callback != null) callback.onSuccess(tier, maxDevices, expiresAt);
                    });
                } else {
                    String msg = resp.optString("message", "Failed to activate license from account. Check subscription on kotsafe.com.");
                    mMainHandler.post(() -> {
                        if (callback != null) callback.onError(msg);
                    });
                }
            } catch (Exception e) {
                Log.e(TAG, "Account activation error: " + e.getMessage(), e);
                mMainHandler.post(() -> {
                    if (callback != null) callback.onError("Network error connecting to licensing server: " + e.getMessage());
                });
            } finally {
                if (conn != null) conn.disconnect();
            }
        });
    }

    /**
     * Heartbeat re-validation with kotsafe.com server.
     */
    public void verifyWithServer(LicenseCallback callback) {
        final String key = getActiveLicenseKey();
        if (key.isEmpty()) {
            if (callback != null) callback.onError("No active license found on this device.");
            return;
        }

        final String deviceId = getOrCreateDeviceId();

        mExecutor.execute(() -> {
            HttpURLConnection conn = null;
            try {
                URL url = new URL(getLicenseApiBaseUrl() + "/verify");
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                authorize(conn);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Accept", "application/json");
                conn.setConnectTimeout(6000);
                conn.setReadTimeout(6000);
                conn.setDoOutput(true);

                JSONObject req = new JSONObject();
                req.put("license_key", key);
                req.put("device_id", deviceId);
                req.put("platform", "android");

                try (OutputStream os = conn.getOutputStream()) {
                    os.write(req.toString().getBytes(StandardCharsets.UTF_8));
                }

                int code = conn.getResponseCode();
                String responseBody = readStream(code >= 200 && code < 400 ? conn.getInputStream() : conn.getErrorStream());
                JSONObject resp = new JSONObject(responseBody);

                if (code == 200 && resp.optBoolean("valid", false)) {
                    String serverTier = resp.optString("tier", "PRO");
                    Tier tier = parseTier(serverTier);
                    int maxDevices = resp.optInt("max_devices", 5);
                    int activeDevices = resp.optInt("active_devices", 1);
                    long expiresAt = resp.optLong("expires_at", 0);
                    String token = resp.optString("token", "");

                    mPrefs.edit()
                            .putBoolean(PREF_IS_PRO_ACTIVATED, true)
                            .putString(PREF_LICENSE_TIER, tier.name())
                            .putLong(PREF_LICENSE_EXPIRES, expiresAt)
                            .putInt(PREF_LICENSE_MAX_DEVICES, maxDevices)
                            .putInt(PREF_LICENSE_ACTIVE_DEVICES, activeDevices)
                            .putString(PREF_LICENSE_TOKEN, token)
                            .putLong(PREF_LICENSE_LAST_VERIFIED, System.currentTimeMillis())
                            .apply();

                    if (callback != null) {
                        mMainHandler.post(() -> callback.onSuccess(tier, maxDevices, expiresAt));
                    }
                } else {
                    if (code == 401 || code == 403 || code == 404) revokeLicense();
                    if (callback != null) {
                        String msg = resp.optString("message", "License verification failed. Reverted to Freemium.");
                        mMainHandler.post(() -> callback.onError(msg));
                    }
                }

            } catch (Exception e) {
                Log.w(TAG, "License revalidation offline: " + e.getMessage());
                if (callback != null) {
                    mMainHandler.post(() -> callback.onError("Offline check: could not reach kotsafe.com (" + e.getMessage() + ")"));
                }
            } finally {
                if (conn != null) conn.disconnect();
            }
        });
    }

    /**
     * Deactivates the license seat on kotsafe.com and returns the device to Freemium.
     */
    public void deactivateLicense(DeactivateCallback callback) {
        final String key = getActiveLicenseKey();
        final String deviceId = getOrCreateDeviceId();

        mExecutor.execute(() -> {
            HttpURLConnection conn = null;
            try {
                if (!key.isEmpty()) {
                    URL url = new URL(getLicenseApiBaseUrl() + "/deactivate");
                    conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("POST");
                authorize(conn);
                    conn.setRequestProperty("Content-Type", "application/json");
                    conn.setRequestProperty("Accept", "application/json");
                    conn.setConnectTimeout(6000);
                    conn.setReadTimeout(6000);
                    conn.setDoOutput(true);

                    JSONObject req = new JSONObject();
                    req.put("license_key", key);
                    req.put("device_id", deviceId);
                req.put("platform", "android");

                    try (OutputStream os = conn.getOutputStream()) {
                        os.write(req.toString().getBytes(StandardCharsets.UTF_8));
                    }

                    conn.getResponseCode(); // Execute request
                }
            } catch (Exception e) {
                Log.w(TAG, "Server deactivation notice failed: " + e.getMessage());
            } finally {
                if (conn != null) conn.disconnect();
            }

            // Always revoke locally
            revokeLicense();
            if (callback != null) {
                mMainHandler.post(callback::onSuccess);
            }
        });
    }

    public void revokeLicense() {
        mPrefs.edit()
                .putBoolean(PREF_IS_PRO_ACTIVATED, false)
                .remove(PREF_LICENSE_KEY)
                .remove(PREF_LICENSE_TIER)
                .remove(PREF_LICENSE_EXPIRES)
                .remove(PREF_LICENSE_MAX_DEVICES)
                .remove(PREF_LICENSE_ACTIVE_DEVICES)
                .remove(PREF_LICENSE_TOKEN)
                .remove(PREF_LICENSE_LAST_VERIFIED)
                .putString(GatewayPreferenceKeys.EXIT_MAX_DEVICES, "1")
                .apply();
        Log.i(TAG, "KotSafe Pro license cleared. Restored to Freemium.");
    }

    private static Tier parseTier(String tierStr) {
        if (tierStr == null) return Tier.PRO;
        try {
            return Tier.valueOf(tierStr.toUpperCase(Locale.US));
        } catch (Exception e) {
            return Tier.PRO;
        }
    }

    private static String readStream(java.io.InputStream stream) {
        if (stream == null) return "{}";
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        } catch (Exception e) {
            return "{}";
        }
    }
}
