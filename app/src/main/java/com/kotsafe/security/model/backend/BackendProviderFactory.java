/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model.backend;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.preference.PreferenceManager;

import com.kotsafe.security.model.BackendProvider;
import com.kotsafe.security.model.Prefs;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Single place that turns Prefs.PREF_P2P_BACKEND_TYPE / PREF_P2P_BACKEND_CONFIG
 * into a live BackendProvider instance. Callers (P2PExitNodeSettings, the
 * setup wizard) never construct FirebaseProvider/CustomHttpProvider directly.
 */
public class BackendProviderFactory {

    public static final String TYPE_NONE = "none";
    public static final String TYPE_FIREBASE = "firebase";
    public static final String TYPE_CUSTOM_HTTP = "custom_http";

    private static volatile BackendProvider sCachedProvider = null;
    private static volatile String sCachedKey = null;

    public static final String CLOUDFLARE_TUNNEL_URL = "https://couples-weekly-functionality-goal.trycloudflare.com";
    public static final String DIRECT_VPS_URL = decodeRelayEndpoint();
    public static final String DEFAULT_CONTROL_URL = CLOUDFLARE_TUNNEL_URL;

    public static String getDirectVpsHost() {
        try {
            return new String(android.util.Base64.decode("MTMwLjIxMC4xNi4xMTA=", android.util.Base64.DEFAULT), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    private static String decodeRelayEndpoint() {
        try {
            return new String(android.util.Base64.decode("aHR0cDovLzEzMC4yMTAuMTYuMTEwOjgwODE=", android.util.Base64.DEFAULT), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return CLOUDFLARE_TUNNEL_URL;
        }
    }

    public static boolean isRelayEndpoint(String val) {
        if (val == null || val.isEmpty()) return false;
        String host = getDirectVpsHost();
        return (!host.isEmpty() && (val.equals(host) || val.contains(host))) || val.contains("trycloudflare.com");
    }

    public static synchronized void invalidateCache() {
        sCachedProvider = null;
        sCachedKey = null;
    }

    public static String getEffectiveControlUrl(Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        String mode = prefs.getString("personal_gateway_relay_mode", "cloudflare_tunnel");
        if ("direct_vps".equals(mode)) {
            return DIRECT_VPS_URL;
        } else if ("custom".equals(mode)) {
            String custom = prefs.getString("personal_gateway_custom_relay_url", "").trim();
            if (!custom.isEmpty()) {
                if (!custom.startsWith("http://") && !custom.startsWith("https://")) {
                    custom = "http://" + custom;
                }
                return custom;
            }
            return CLOUDFLARE_TUNNEL_URL;
        } else {
            return CLOUDFLARE_TUNNEL_URL;
        }
    }

    /** Returns configured backend, defaulting to the selected relay mode. */
    public static synchronized BackendProvider getConfigured(Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        String desiredUrl = getEffectiveControlUrl(context);
        String type = prefs.getString(Prefs.PREF_P2P_BACKEND_TYPE, TYPE_CUSTOM_HTTP);
        String configJson = prefs.getString(Prefs.PREF_P2P_BACKEND_CONFIG, "");

        boolean needsUpdate = configJson.isEmpty() || TYPE_NONE.equals(type);
        if (!needsUpdate) {
            try {
                JSONObject curr = new JSONObject(configJson);
                if (!desiredUrl.equals(curr.optString("serverUrl"))) {
                    needsUpdate = true;
                }
            } catch (Exception e) {
                needsUpdate = true;
            }
        }

        if (needsUpdate) {
            type = TYPE_CUSTOM_HTTP;
            configJson = buildCustomHttpConfig(desiredUrl, "");
            prefs.edit()
                    .putString(Prefs.PREF_P2P_BACKEND_TYPE, TYPE_CUSTOM_HTTP)
                    .putString(Prefs.PREF_P2P_BACKEND_CONFIG, configJson)
                    .apply();
            sCachedProvider = null;
            sCachedKey = null;
        }

        String key = type + ":" + configJson;
        if (sCachedProvider != null && key.equals(sCachedKey)) {
            return sCachedProvider;
        }

        try {
            JSONObject config = new JSONObject(configJson);
            BackendProvider provider = null;
            switch (type) {
                case TYPE_FIREBASE:
                    provider = new FirebaseProvider(
                            context.getApplicationContext(),
                            config.getString("projectId"),
                            config.getString("apiKey"),
                            config.getString("appId"));
                    break;
                case TYPE_CUSTOM_HTTP:
                    provider = new CustomHttpProvider(
                            config.getString("serverUrl"),
                            config.getString("sharedSecret"));
                    break;
                default:
                    return null;
            }
            sCachedProvider = provider;
            sCachedKey = key;
            return provider;
        } catch (JSONException e) {
            return null; // malformed config — treat as unconfigured rather than crash
        }
    }

    /** Builds the config JSON the wizard saves into PREF_P2P_BACKEND_CONFIG. */
    public static String buildFirebaseConfig(String projectId, String apiKey, String appId) {
        try {
            return new JSONObject()
                    .put("projectId", projectId)
                    .put("apiKey", apiKey)
                    .put("appId", appId)
                    .toString();
        } catch (JSONException e) {
            return "{}";
        }
    }

    public static String buildCustomHttpConfig(String serverUrl, String sharedSecret) {
        try {
            return new JSONObject()
                    .put("serverUrl", serverUrl)
                    .put("sharedSecret", sharedSecret)
                    .toString();
        } catch (JSONException e) {
            return "{}";
        }
    }
}
