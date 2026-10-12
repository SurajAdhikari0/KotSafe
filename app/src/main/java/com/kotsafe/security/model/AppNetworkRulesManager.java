/*
 * This file is part of KotSafe.
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
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.Log;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Manages per-app network access control rules and persistence.
 */
public class AppNetworkRulesManager {
    private static final String TAG = "AppNetworkRulesManager";
    private static final String PREF_NAME = "network_access_control_rules";
    private static final String KEY_RULES_JSON = "rules_json";

    private static volatile AppNetworkRulesManager sInstance;

    private final Context mContext;
    private final SharedPreferences mPrefs;
    private final Gson mGson;
    private final Map<String, AppNetworkRule> mRules = new HashMap<>();
    private final android.util.SparseArray<AppNetworkRule> mRulesByUid = new android.util.SparseArray<>();
    private final List<OnRulesChangeListener> mListeners = new ArrayList<>();

    public interface OnRulesChangeListener {
        void onRulesChanged();
    }

    private AppNetworkRulesManager(Context context) {
        mContext = context.getApplicationContext();
        mPrefs = mContext.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        mGson = new Gson();
        loadRules();
    }

    public static AppNetworkRulesManager getInstance(Context context) {
        if (sInstance == null) {
            synchronized (AppNetworkRulesManager.class) {
                if (sInstance == null) {
                    sInstance = new AppNetworkRulesManager(context);
                }
            }
        }
        return sInstance;
    }

    private void rebuildUidMap() {
        mRulesByUid.clear();
        for (AppNetworkRule rule : mRules.values()) {
            if (rule.getUid() > 0) {
                mRulesByUid.put(rule.getUid(), rule);
            }
        }
    }

    private synchronized void loadRules() {
        mRules.clear();
        mRulesByUid.clear();
        String json = mPrefs.getString(KEY_RULES_JSON, null);
        if (json != null && !json.isEmpty()) {
            try {
                Type type = new TypeToken<Map<String, AppNetworkRule>>() {}.getType();
                Map<String, AppNetworkRule> loaded = mGson.fromJson(json, type);
                if (loaded != null) {
                    mRules.putAll(loaded);
                    rebuildUidMap();
                }
            } catch (Exception e) {
                Log.e(TAG, "Error parsing rules json: " + e.getMessage());
            }
        }
        Log.d(TAG, "Loaded " + mRules.size() + " network access rules");
    }

    private synchronized void saveRules() {
        try {
            String json = mGson.toJson(mRules);
            mPrefs.edit().putString(KEY_RULES_JSON, json).apply();
        } catch (Exception e) {
            Log.e(TAG, "Error saving rules json: " + e.getMessage());
        }
    }

    @NonNull
    public synchronized AppNetworkRule getRule(@NonNull String packageName, int uid) {
        AppNetworkRule rule = mRules.get(packageName);
        if (rule == null) {
            rule = new AppNetworkRule(packageName, uid);
        } else if (uid > 0 && rule.getUid() <= 0) {
            rule.setUid(uid);
            mRulesByUid.put(uid, rule);
        }
        return new AppNetworkRule(rule);
    }

    @Nullable
    public synchronized AppNetworkRule getRule(int uid) {
        if (uid <= 0 || mRules.isEmpty()) return null;
        AppNetworkRule rule = mRulesByUid.get(uid);
        return rule != null ? new AppNetworkRule(rule) : null;
    }

    @Nullable
    public synchronized AppNetworkRule getRule(@NonNull String packageName) {
        AppNetworkRule rule = mRules.get(packageName);
        return rule != null ? new AppNetworkRule(rule) : null;
    }

    public synchronized void setRule(@NonNull AppNetworkRule rule) {
        if (rule.getPackageName().isEmpty())
            return;
        String lower = rule.getPackageName().toLowerCase(java.util.Locale.US);
        if (lower.equals("com.kotsafe.security") || lower.equals(mContext.getPackageName().toLowerCase(java.util.Locale.US)) || lower.contains("kotsafe")) {
            Log.w(TAG, "Self-Protection: Refusing to apply restrictive network rule to KotSafe itself");
            return;
        }

        if (rule.isFullyAllowed()) {
            // If completely default allowed, remove to keep storage minimal
            mRules.remove(rule.getPackageName());
        } else {
            mRules.put(rule.getPackageName(), new AppNetworkRule(rule));
        }

        rebuildUidMap();
        saveRules();
        notifyListeners();

        // Inform active capture service to reload blocklist if firewall is on
        if (CaptureService.isServiceActive()) {
            CaptureService.requireInstance().reloadBlocklist();
        }
    }

    public synchronized void deleteRule(@NonNull String packageName) {
        if (mRules.remove(packageName) != null) {
            rebuildUidMap();
            saveRules();
            notifyListeners();
            if (CaptureService.isServiceActive()) {
                CaptureService.requireInstance().reloadBlocklist();
            }
        }
    }

    public synchronized Map<String, AppNetworkRule> getAllRules() {
        Map<String, AppNetworkRule> copy = new HashMap<>();
        for (Map.Entry<String, AppNetworkRule> entry : mRules.entrySet()) {
            copy.put(entry.getKey(), new AppNetworkRule(entry.getValue()));
        }
        return Collections.unmodifiableMap(copy);
    }

    public synchronized int setAllRules(@NonNull Map<String, AppNetworkRule> rules, boolean replace) {
        if (replace) {
            mRules.clear();
        }
        int count = 0;
        for (Map.Entry<String, AppNetworkRule> entry : rules.entrySet()) {
            if (entry.getValue() != null && !entry.getValue().isFullyAllowed()) {
                mRules.put(entry.getKey(), new AppNetworkRule(entry.getValue()));
                count++;
            }
        }
        rebuildUidMap();
        saveRules();
        notifyListeners();
        if (CaptureService.isServiceActive()) {
            CaptureService.requireInstance().reloadBlocklist();
        }
        return count;
    }

    /**
     * Calculates all UIDs that should be actively blocked right now given current network type and screen state.
     */
    public synchronized Set<Integer> getBlockedUids(NetworkType networkType, boolean isScreenOn) {
        Set<Integer> blocked = new HashSet<>();
        for (AppNetworkRule rule : mRules.values()) {
            if (rule.getUid() <= 0) continue;

            if (rule.isBlockedOn(networkType)) {
                blocked.add(rule.getUid());
            } else if (rule.isBlockedForScreenState(isScreenOn)) {
                blocked.add(rule.getUid());
            }
        }
        return blocked;
    }

    /**
     * Returns an array of UIDs that have LAN access blocked.
     */
    public synchronized int[] getLanBlockedUids() {
        List<Integer> list = new ArrayList<>();
        for (AppNetworkRule rule : mRules.values()) {
            if (rule.getUid() > 0 && rule.isLanBlocked()) {
                list.add(rule.getUid());
            }
        }
        int[] arr = new int[list.size()];
        for (int i = 0; i < list.size(); i++) {
            arr[i] = list.get(i);
        }
        return arr;
    }

    public synchronized void addListener(OnRulesChangeListener listener) {
        if (!mListeners.contains(listener)) {
            mListeners.add(listener);
        }
    }

    public synchronized void removeListener(OnRulesChangeListener listener) {
        mListeners.remove(listener);
    }

    private void notifyListeners() {
        List<OnRulesChangeListener> copy;
        synchronized (this) {
            copy = new ArrayList<>(mListeners);
        }
        for (OnRulesChangeListener l : copy) {
            try {
                l.onRulesChanged();
            } catch (Exception e) {
                Log.e(TAG, "Error in rule change listener: " + e.getMessage());
            }
        }
    }
}
