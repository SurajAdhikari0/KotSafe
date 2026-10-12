/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONException;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Singleton store for security alert records.
 * Alerts are persisted in SharedPreferences as a JSON array (max 200 entries).
 */
public class AlertStore {
    private static final String PREFS_NAME = "kotsafe_alerts";
    private static final String KEY_ALERTS = "alerts_json";
    private static final int    MAX_ALERTS = 200;

    private static AlertStore sInstance;
    private final Context mContext;
    private final SharedPreferences mPrefs;
    private final List<AlertRecord> mAlerts;

    private AlertStore(Context ctx) {
        mContext = ctx.getApplicationContext();
        mPrefs  = mContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        mAlerts = new ArrayList<>();
        load();
    }

    public static synchronized AlertStore getInstance(Context ctx) {
        if (sInstance == null) sInstance = new AlertStore(ctx);
        return sInstance;
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /** Returns a snapshot of all alerts, newest-first. */
    public List<AlertRecord> getAll() {
        return new ArrayList<>(mAlerts);
    }

    /** Returns only alerts for a given type. */
    public List<AlertRecord> getByType(AlertRecord.AlertType type) {
        List<AlertRecord> result = new ArrayList<>();
        for (AlertRecord r : mAlerts) {
            if (r.type == type) result.add(r);
        }
        return result;
    }

    public int getTotalCount() { return mAlerts.size(); }

    public int getHighSeverityCount() {
        int count = 0;
        for (AlertRecord r : mAlerts) {
            if (r.severity == AlertRecord.Severity.HIGH) count++;
        }
        return count;
    }

    public int getRawEventsCount() {
        int total = 0;
        for (AlertRecord r : mAlerts) {
            total += Math.max(1, r.occurrenceCount);
        }
        return total;
    }

    /** Adds a new alert, automatically merging with similar existing alerts. */
    public synchronized AlertRecord add(AlertRecord.Severity severity,
                                        AlertRecord.AlertType type,
                                        String title,
                                        String message,
                                        String sourceApp) {
        AlertRecord r = new AlertRecord(
                UUID.randomUUID().toString(),
                System.currentTimeMillis(),
                severity, type, title, message, sourceApp);

        // Auto-merge with existing similar alert
        for (int i = 0; i < mAlerts.size(); i++) {
            AlertRecord existing = mAlerts.get(i);
            if (existing.isSimilarTo(r)) {
                existing.mergeWith(r);
                existing.message = r.message;
                mAlerts.remove(i);
                mAlerts.add(0, existing);
                save();
                try {
                    com.kotsafe.security.ai.AutonomousSocAnalyst.getInstance(mContext).preTriageAlertAsync(existing);
                } catch (Exception ignored) {}
                return existing;
            }
        }

        mAlerts.add(0, r); // newest first
        if (mAlerts.size() > MAX_ALERTS) mAlerts.remove(mAlerts.size() - 1);
        save();
        try {
            com.kotsafe.security.ai.AutonomousSocAnalyst.getInstance(mContext).preTriageAlertAsync(r);
        } catch (Exception ignored) {}
        return r;
    }

    /** Clears all stored alerts and persists empty state. */
    public synchronized void clearAll() {
        mAlerts.clear();
        mPrefs.edit().putString(KEY_ALERTS, "[]").apply();
    }

    /** Removes an individual alert by ID and persists changes. */
    public synchronized boolean removeAlert(String id) {
        if (id == null) return false;
        boolean removed = false;
        for (int i = 0; i < mAlerts.size(); i++) {
            if (id.equals(mAlerts.get(i).id)) {
                mAlerts.remove(i);
                removed = true;
                break;
            }
        }
        if (removed) {
            save();
        }
        return removed;
    }

    /** Updates an existing alert record in place and persists. */
    public synchronized void updateAlert(AlertRecord alert) {
        if (alert == null || alert.id == null) return;
        for (int i = 0; i < mAlerts.size(); i++) {
            if (alert.id.equals(mAlerts.get(i).id)) {
                mAlerts.set(i, alert);
                save();
                break;
            }
        }
    }

    // ── Persistence ──────────────────────────────────────────────────────────

    private void load() {
        mAlerts.clear();
        String json = mPrefs.getString(KEY_ALERTS, null);
        if (json == null || json.trim().isEmpty() || json.equals("[]")) {
            return;
        }
        try {
            JSONArray arr = new JSONArray(json);
            boolean modified = false;
            List<AlertRecord> loaded = new ArrayList<>();
            for (int i = 0; i < arr.length(); i++) {
                AlertRecord r = AlertRecord.fromJson(arr.getJSONObject(i));
                // Purge any legacy demo/sample data
                if (r.id != null && r.id.startsWith("d") && r.id.length() <= 3) {
                    modified = true;
                    continue;
                }
                if (r.title != null && (r.title.contains("Malware C2 Detected") || r.title.contains("Data Exfil Attempt"))) {
                    modified = true;
                    continue;
                }
                loaded.add(r);
            }

            // Automatic merge of similar alerts
            for (AlertRecord r : loaded) {
                boolean merged = false;
                for (AlertRecord existing : mAlerts) {
                    if (existing.isSimilarTo(r)) {
                        existing.mergeWith(r);
                        merged = true;
                        modified = true;
                        break;
                    }
                }
                if (!merged) {
                    mAlerts.add(r);
                }
            }

            if (modified) {
                save();
            }
        } catch (JSONException e) {
            mAlerts.clear();
            save();
        }
    }

    private void save() {
        try {
            JSONArray arr = new JSONArray();
            for (AlertRecord r : mAlerts) arr.put(r.toJson());
            mPrefs.edit().putString(KEY_ALERTS, arr.toString()).apply();
        } catch (JSONException ignored) {}
    }
}
