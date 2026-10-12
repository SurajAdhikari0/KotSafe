/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
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
 * * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.collection.ArrayMap;
import androidx.collection.ArraySet;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.Billing;
import com.kotsafe.security.Blacklists;
import com.kotsafe.security.BuildConfig;
import com.kotsafe.security.Log;
import com.kotsafe.security.PersistableUriPermission;
import com.kotsafe.security.ai.AiConfig;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A portable snapshot of the app configuration:
 * - Core App SharedPreferences & Options
 * - Firewall & Security Rules (IP, Domain, URL, Hash, App, Whitelist) via SecurityRulesDb
 * - Per-App Network Access Policies via AppNetworkRulesManager
 * Supports selective export/restore, sensitive key protection, and Merge vs Replace modes.
 */
public class SettingsBackup {
    private static final String TAG = "SettingsBackup";
    public static final int VERSION = 2;
    public static final String LICENSE_KEY = "license";

    public static final String KEY_FIREWALL_RULES = "firewall_rules";
    public static final String KEY_APP_NETWORK_RULES = "app_network_rules";
    public static final String KEY_SETTINGS = "settings";

    private static final Set<String> EXCLUDED_KEYS = new ArraySet<>();

    private static final String TYPE_BOOLEAN = "boolean";
    private static final String TYPE_INT = "int";
    private static final String TYPE_LONG = "long";
    private static final String TYPE_FLOAT = "float";
    private static final String TYPE_STRING = "string";
    private static final String TYPE_STRING_SET = "string_set";

    static {
        // the mitm addon and its CA certificate must be set up again on the new installation
        EXCLUDED_KEYS.add(Prefs.PREF_TLS_DECRYPTION_SETUP_DONE);
        EXCLUDED_KEYS.add(Prefs.PREF_CA_INSTALLATION_SKIPPED);

        EXCLUDED_KEYS.add(Prefs.PREF_APP_VERSION);
        EXCLUDED_KEYS.add(PersistableUriPermission.PREF_KEY);
        EXCLUDED_KEYS.add(Blacklists.PREF_BLACKLISTS_STATUS);
        EXCLUDED_KEYS.addAll(Billing.BILLING_STATE_KEYS);

        // Sensitive P2P tokens, personal gateway credentials, and Threat Intel API keys
        EXCLUDED_KEYS.add(Prefs.PREF_P2P_BACKEND_PAIRING);
        EXCLUDED_KEYS.add(com.kotsafe.security.p2p.GatewayPreferenceKeys.PAIRING_BUNDLE);
        EXCLUDED_KEYS.add(com.kotsafe.security.p2p.GatewayPreferenceKeys.DEVICE_ID);
        EXCLUDED_KEYS.add("personal_gateway_saved_profiles");
        EXCLUDED_KEYS.add(com.kotsafe.security.ThreatIntelApiClient.PREF_OTX_KEY);
        EXCLUDED_KEYS.add(com.kotsafe.security.ThreatIntelApiClient.PREF_VT_KEY);
        EXCLUDED_KEYS.add(URLhausProvider.PREF_URLHAUS_KEY);
        EXCLUDED_KEYS.add(ThreatFoxProvider.PREF_THREATFOX_KEY);
    }

    public static class RestoreResult {
        public int prefsRestored;
        public int firewallRulesRestored;
        public int appRulesRestored;
    }

    private final ArrayMap<String, Object> mSettings = new ArrayMap<>();
    private final List<SecurityRulesDb.SecurityRule> mFirewallRules = new ArrayList<>();
    private final Map<String, AppNetworkRule> mAppNetworkRules = new HashMap<>();
    private int mAppVersion;
    private String mAppVersionName = "";
    private long mCreated;
    private boolean mIncludesApiKeys;

    public static boolean isExcluded(String key) {
        return EXCLUDED_KEYS.contains(key) || key.startsWith(Billing.SKU_PREF_PREFIX);
    }

    private static boolean requiresMerge(String key) {
        return key.equals(Prefs.PREF_CAPTURE_LIST);
    }

    public static String serialize(SharedPreferences prefs) {
        // Overload for backward compatibility
        JsonObject settings = new JsonObject();
        for (Map.Entry<String, ?> entry : prefs.getAll().entrySet()) {
            if (isExcluded(entry.getKey())) continue;
            JsonObject encoded = encode(entry.getValue());
            if (encoded != null) settings.add(entry.getKey(), encoded);
        }

        JsonObject root = new JsonObject();
        root.addProperty("version", VERSION);
        root.addProperty("app_version", BuildConfig.VERSION_CODE);
        root.addProperty("app_version_name", BuildConfig.VERSION_NAME);
        root.addProperty("created", System.currentTimeMillis());
        root.add(KEY_SETTINGS, settings);

        return new GsonBuilder().setPrettyPrinting().create().toJson(root);
    }

    /**
     * Serializes complete configuration with granular module selection and sensitive key protection.
     */
    public static String serialize(Context context, boolean includePrefs, boolean includeFirewall,
                                   boolean includeAppRules, boolean includeApiKeys) {
        JsonObject root = new JsonObject();
        root.addProperty("version", VERSION);
        root.addProperty("app_version", BuildConfig.VERSION_CODE);
        root.addProperty("app_version_name", BuildConfig.VERSION_NAME);
        root.addProperty("created", System.currentTimeMillis());
        root.addProperty("includes_api_keys", includeApiKeys);

        Gson gson = new Gson();

        // 1. Preferences
        if (includePrefs) {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
            JsonObject settings = new JsonObject();
            for (Map.Entry<String, ?> entry : prefs.getAll().entrySet()) {
                String key = entry.getKey();
                if (isExcluded(key)) continue;

                // Sensitive API key protection
                if (!includeApiKeys && (key.equals(AiConfig.PREF_AI_API_KEY)
                        || key.toLowerCase().contains("api_key")
                        || key.toLowerCase().contains("secret_key"))) {
                    continue;
                }

                JsonObject encoded = encode(entry.getValue());
                if (encoded != null) {
                    settings.add(key, encoded);
                }
            }
            root.add(KEY_SETTINGS, settings);
            root.addProperty("settings_count", settings.size());
        }

        // 2. Firewall & Security Rules (SecurityRulesDb)
        if (includeFirewall) {
            List<SecurityRulesDb.SecurityRule> rules = SecurityRulesDb.getInstance(context).getAllRules();
            JsonElement rulesElement = gson.toJsonTree(rules);
            root.add(KEY_FIREWALL_RULES, rulesElement);
            root.addProperty("firewall_rules_count", rules.size());
        }

        // 3. Per-App Network Access Rules (AppNetworkRulesManager)
        if (includeAppRules) {
            Map<String, AppNetworkRule> appRules = AppNetworkRulesManager.getInstance(context).getAllRules();
            JsonElement appRulesElement = gson.toJsonTree(appRules);
            root.add(KEY_APP_NETWORK_RULES, appRulesElement);
            root.addProperty("app_network_rules_count", appRules.size());
        }

        return new GsonBuilder().setPrettyPrinting().create().toJson(root);
    }

    public static @Nullable SettingsBackup fromJson(String json) {
        try {
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();

            int version = root.has("version") ? root.getAsJsonPrimitive("version").getAsInt() : 1;
            if (version > VERSION) {
                Log.w(TAG, "unsupported backup version: " + version);
                return null;
            }

            SettingsBackup rv = new SettingsBackup();
            rv.mAppVersion = root.has("app_version") ? root.getAsJsonPrimitive("app_version").getAsInt() : 0;
            rv.mAppVersionName = root.has("app_version_name") ? root.getAsJsonPrimitive("app_version_name").getAsString() : "";
            rv.mCreated = root.has("created") ? root.getAsJsonPrimitive("created").getAsLong() : System.currentTimeMillis();
            rv.mIncludesApiKeys = root.has("includes_api_keys") && root.getAsJsonPrimitive("includes_api_keys").getAsBoolean();

            // Parse SharedPreferences settings
            if (root.has(KEY_SETTINGS)) {
                for (Map.Entry<String, JsonElement> entry : root.getAsJsonObject(KEY_SETTINGS).entrySet()) {
                    Object value = decode(entry.getValue().getAsJsonObject());
                    if (value != null) {
                        rv.mSettings.put(entry.getKey(), value);
                    }
                }
            }

            Gson gson = new Gson();

            // Parse Firewall & Security Rules
            if (root.has(KEY_FIREWALL_RULES) && root.get(KEY_FIREWALL_RULES).isJsonArray()) {
                Type listType = new TypeToken<List<SecurityRulesDb.SecurityRule>>() {}.getType();
                List<SecurityRulesDb.SecurityRule> rules = gson.fromJson(root.get(KEY_FIREWALL_RULES), listType);
                if (rules != null) {
                    rv.mFirewallRules.addAll(rules);
                }
            }

            // Parse Per-App Network Rules
            if (root.has(KEY_APP_NETWORK_RULES) && root.get(KEY_APP_NETWORK_RULES).isJsonObject()) {
                Type mapType = new TypeToken<Map<String, AppNetworkRule>>() {}.getType();
                Map<String, AppNetworkRule> map = gson.fromJson(root.get(KEY_APP_NETWORK_RULES), mapType);
                if (map != null) {
                    rv.mAppNetworkRules.putAll(map);
                }
            }

            if (rv.mSettings.isEmpty() && rv.mFirewallRules.isEmpty() && rv.mAppNetworkRules.isEmpty()) {
                return null;
            }

            return rv;
        } catch (RuntimeException e) {
            Log.e(TAG, "fromJson: " + e.getMessage());
            return null;
        }
    }

    private static @Nullable JsonObject encode(Object value) {
        JsonObject rv = new JsonObject();

        if (value instanceof Boolean) {
            rv.addProperty("type", TYPE_BOOLEAN);
            rv.addProperty("value", (Boolean) value);
        } else if (value instanceof Integer) {
            rv.addProperty("type", TYPE_INT);
            rv.addProperty("value", (Integer) value);
        } else if (value instanceof Long) {
            rv.addProperty("type", TYPE_LONG);
            rv.addProperty("value", (Long) value);
        } else if (value instanceof Float) {
            rv.addProperty("type", TYPE_FLOAT);
            rv.addProperty("value", (Float) value);
        } else if (value instanceof String) {
            rv.addProperty("type", TYPE_STRING);
            rv.addProperty("value", (String) value);
        } else if (value instanceof Set) {
            JsonArray items = new JsonArray();
            for (Object item : (Set<?>) value)
                items.add(item.toString());

            rv.addProperty("type", TYPE_STRING_SET);
            rv.add("value", items);
        } else {
            Log.w(TAG, "unhandled preference type: " + (value != null ? value.getClass().getName() : "null"));
            return null;
        }

        return rv;
    }

    private static @Nullable Object decode(JsonObject obj) {
        JsonElement type = obj.get("type");
        JsonElement value = obj.get("value");
        if ((type == null) || (value == null))
            return null;

        switch (type.getAsString()) {
            case TYPE_BOOLEAN:  return value.getAsBoolean();
            case TYPE_INT:      return value.getAsInt();
            case TYPE_LONG:     return value.getAsLong();
            case TYPE_FLOAT:    return value.getAsFloat();
            case TYPE_STRING:   return value.getAsString();
            case TYPE_STRING_SET:
                ArraySet<String> items = new ArraySet<>();
                for (JsonElement item : value.getAsJsonArray())
                    items.add(item.getAsString());
                return items;
        }

        Log.w(TAG, "unhandled backup type: " + type.getAsString());
        return null;
    }

    @SuppressLint("ApplySharedPref")
    @SuppressWarnings("unchecked")
    public void apply(SharedPreferences prefs) {
        applyPreferences(prefs, false);
    }

    /**
     * Applies full or selective configuration with merge or replace strategy.
     */
    public RestoreResult apply(Context context, SharedPreferences prefs, boolean restorePrefs,
                               boolean restoreFirewall, boolean restoreAppRules, boolean merge) {
        RestoreResult result = new RestoreResult();

        if (restorePrefs && !mSettings.isEmpty()) {
            result.prefsRestored = applyPreferences(prefs, merge);
        }

        if (restoreFirewall && !mFirewallRules.isEmpty()) {
            result.firewallRulesRestored = SecurityRulesDb.getInstance(context).restoreRules(mFirewallRules, !merge);
        }

        if (restoreAppRules && !mAppNetworkRules.isEmpty()) {
            result.appRulesRestored = AppNetworkRulesManager.getInstance(context).setAllRules(mAppNetworkRules, !merge);
        }

        return result;
    }

    @SuppressLint("ApplySharedPref")
    @SuppressWarnings("unchecked")
    private int applyPreferences(SharedPreferences prefs, boolean merge) {
        SharedPreferences.Editor editor = prefs.edit();

        if (!merge) {
            for (String key : prefs.getAll().keySet()) {
                if (!isExcluded(key) && !requiresMerge(key))
                    editor.remove(key);
            }
        }

        int restored = 0;
        for (int i = 0; i < mSettings.size(); i++) {
            String key = mSettings.keyAt(i);
            Object value = mSettings.valueAt(i);

            if (isExcluded(key) || requiresMerge(key))
                continue;

            if (value instanceof Boolean)
                editor.putBoolean(key, (Boolean) value);
            else if (value instanceof Integer)
                editor.putInt(key, (Integer) value);
            else if (value instanceof Long)
                editor.putLong(key, (Long) value);
            else if (value instanceof Float)
                editor.putFloat(key, (Float) value);
            else if (value instanceof String)
                editor.putString(key, (String) value);
            else if (value instanceof Set)
                editor.putStringSet(key, (Set<String>) value);

            restored++;
        }

        editor.commit();
        return restored;
    }

    public long getCreationTime() {
        return mCreated;
    }

    public int getAppVersion() {
        return mAppVersion;
    }

    public String getAppVersionName() {
        return mAppVersionName;
    }

    public int getSettingsCount() {
        return mSettings.size();
    }

    public int getFirewallRulesCount() {
        return mFirewallRules.size();
    }

    public int getAppRulesCount() {
        return mAppNetworkRules.size();
    }

    public List<SecurityRulesDb.SecurityRule> getFirewallRules() {
        return mFirewallRules;
    }

    public Map<String, AppNetworkRule> getAppNetworkRules() {
        return mAppNetworkRules;
    }

    public boolean includesApiKeys() {
        return mIncludesApiKeys;
    }

    public @NonNull String getString(String key) {
        Object value = mSettings.get(key);
        return (value instanceof String) ? (String) value : "";
    }
}
