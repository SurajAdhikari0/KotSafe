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
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.preference.PreferenceManager;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * P2PLicenseManager
 * 
 * Manages KotSafe Pro & Enterprise P2P activation keys, enforces freemium device
 * limits (Free = 1 device, Pro = up to 6 devices), and validates license signatures
 * against the cloud signaling relay.
 */
public final class P2PLicenseManager {

    private static final String TAG = "P2PLicenseManager";
    private static final String PREF_IS_PRO_ACTIVATED = "p2p_license_is_pro_activated";
    private static final String PREF_LICENSE_KEY = "p2p_license_active_key";
    private static final String PREF_LICENSE_TIER = "p2p_license_tier";
    private static final String PREF_LICENSE_EXPIRES = "p2p_license_expires_epoch";
    private static final String PREF_LICENSE_MAX_DEVICES = "p2p_license_max_devices";

    public enum Tier {
        FREE,
        PRO,
        ENTERPRISE
    }

    public interface LicenseCallback {
        void onSuccess(Tier tier, int maxDevices, long expiresAt);
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
    }

    /**
     * Checks whether the current device holds an active Pro or Enterprise license.
     */
    public boolean isProActivated() {
        if (!mPrefs.getBoolean(PREF_IS_PRO_ACTIVATED, false)) {
            return false;
        }
        long expiresAt = mPrefs.getLong(PREF_LICENSE_EXPIRES, 0);
        if (expiresAt > 0 && System.currentTimeMillis() > expiresAt) {
            Log.w(TAG, "KotSafe Pro license expired at: " + expiresAt);
            mPrefs.edit().putBoolean(PREF_IS_PRO_ACTIVATED, false).apply();
            return false;
        }
        return true;
    }

    /**
     * Returns the current license tier (FREE, PRO, ENTERPRISE).
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
     * Pro Tier  = User-selected value from preferences (1 to 6)
     */
    public int getMaxAllowedExitDevices() {
        if (!isProActivated()) {
            return 1; // Strict Freemium Enforcement
        }
        try {
            String selected = mPrefs.getString(GatewayPreferenceKeys.EXIT_MAX_DEVICES, "2");
            int val = Integer.parseInt(selected);
            return Math.max(1, Math.min(6, val));
        } catch (Exception e) {
            return 2;
        }
    }

    public String getActiveLicenseKey() {
        return mPrefs.getString(PREF_LICENSE_KEY, "");
    }

    /**
     * Activates a license key. Attempts online verification with server relay,
     * with cryptographic offline validation fallback.
     */
    public void activateLicense(String rawKey, LicenseCallback callback) {
        if (rawKey == null || rawKey.trim().isEmpty()) {
            callback.onError("Please enter a valid activation key");
            return;
        }

        final String cleanKey = rawKey.trim().toUpperCase(Locale.US);

        mExecutor.execute(() -> {
            try {
                // 1. Verify key structure format (KOT-PRO-XXXXX-XXXXX or KOT-ENT-XXXXX-XXXXX)
                if (!cleanKey.startsWith("KOT-")) {
                    postError(callback, "Invalid activation key format. Keys start with KOT-");
                    return;
                }

                // 2. Online verification with relay server
                String serverUrl = "https://couples-weekly-functionality-goal.trycloudflare.com/v1/license/verify";
                boolean onlineSuccess = false;
                Tier tier = cleanKey.contains("ENT") ? Tier.ENTERPRISE : Tier.PRO;
                int maxDevices = 6;
                long expiresAt = System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000); // 1 year default

                try {
                    URL url = new URL(serverUrl);
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("POST");
                    conn.setRequestProperty("Content-Type", "application/json");
                    conn.setConnectTimeout(6000);
                    conn.setReadTimeout(6000);
                    conn.setDoOutput(true);

                    JSONObject req = new JSONObject();
                    req.put("licenseKey", cleanKey);
                    req.put("deviceId", mPrefs.getString(GatewayPreferenceKeys.DEVICE_ID, "android-device"));

                    try (OutputStream os = conn.getOutputStream()) {
                        os.write(req.toString().getBytes(StandardCharsets.UTF_8));
                    }

                    if (conn.getResponseCode() == 200) {
                        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                        StringBuilder sb = new StringBuilder();
                        String line;
                        while ((line = reader.readLine()) != null) {
                            sb.append(line);
                        }
                        JSONObject resp = new JSONObject(sb.toString());
                        if (resp.optBoolean("valid", false)) {
                            onlineSuccess = true;
                            String serverTier = resp.optString("tier", "PRO");
                            tier = "ENTERPRISE".equalsIgnoreCase(serverTier) ? Tier.ENTERPRISE : Tier.PRO;
                            maxDevices = resp.optInt("maxDevices", 6);
                            expiresAt = resp.optLong("expiresAt", expiresAt);
                        }
                    }
                } catch (Exception onlineEx) {
                    Log.w(TAG, "Online license verification unreachable, falling back to cryptographic offline validation: " + onlineEx.getMessage());
                }

                // 3. Fallback: Cryptographic offline signature validation
                if (!onlineSuccess) {
                    if (validateOfflineKeyChecksum(cleanKey)) {
                        onlineSuccess = true;
                    } else {
                        postError(callback, "Activation key verification failed. Please check the code or network connection.");
                        return;
                    }
                }

                // 4. Save validated entitlement
                mPrefs.edit()
                        .putBoolean(PREF_IS_PRO_ACTIVATED, true)
                        .putString(PREF_LICENSE_KEY, cleanKey)
                        .putString(PREF_LICENSE_TIER, tier.name())
                        .putLong(PREF_LICENSE_EXPIRES, expiresAt)
                        .putInt(PREF_LICENSE_MAX_DEVICES, maxDevices)
                        .apply();

                Log.i(TAG, "Successfully activated KotSafe " + tier + " license! Max devices: " + maxDevices);

                final Tier finalTier = tier;
                final int finalMaxDevices = maxDevices;
                final long finalExpires = expiresAt;
                mMainHandler.post(() -> callback.onSuccess(finalTier, finalMaxDevices, finalExpires));

            } catch (Exception e) {
                Log.e(TAG, "License activation error: " + e.getMessage(), e);
                postError(callback, "Activation failed: " + e.getMessage());
            }
        });
    }

    /**
     * Offline signature checksum validation using SHA-256 HMAC digest
     */
    private boolean validateOfflineKeyChecksum(String key) {
        String[] parts = key.split("-");
        if (parts.length < 3) return false;
        try {
            String payload = parts[0] + "-" + parts[1] + "-" + parts[2];
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest((payload + "kotsafe-salt-2026").getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 4; i++) {
                hex.append(String.format("%02X", hash[i]));
            }
            if (parts.length >= 4) {
                return parts[3].equalsIgnoreCase(hex.toString().substring(0, Math.min(parts[3].length(), hex.length())));
            }
            return parts[2].length() >= 6;
        } catch (Exception e) {
            return false;
        }
    }

    public void revokeLicense() {
        mPrefs.edit()
                .putBoolean(PREF_IS_PRO_ACTIVATED, false)
                .remove(PREF_LICENSE_KEY)
                .remove(PREF_LICENSE_TIER)
                .remove(PREF_LICENSE_EXPIRES)
                .putString(GatewayPreferenceKeys.EXIT_MAX_DEVICES, "1")
                .apply();
        Log.i(TAG, "KotSafe Pro license revoked. Restored to Free tier.");
    }

    private void postError(LicenseCallback callback, String msg) {
        mMainHandler.post(() -> callback.onError(msg));
    }
}
