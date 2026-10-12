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
 *
 * Copyright 2026 KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import com.kotsafe.security.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * SQLite storage for Per-App Network Behavioral Baselines and Anomaly History.
 * Supports the KotSafe Zero-Trust Anomaly Engine.
 */
public class AppBaselineDb extends SQLiteOpenHelper {
    private static final String TAG = "AppBaselineDb";
    private static final String DB_NAME = "app_baselines.db";
    private static final int DB_VERSION = 1;

    public static final String TABLE_BASELINES = "app_baselines";
    public static final String COL_PACKAGE = "package_name";
    public static final String COL_APP_NAME = "app_name";
    public static final String COL_FIRST_SEEN = "first_seen";
    public static final String COL_LAST_SEEN = "last_seen";
    public static final String COL_IS_LEARNED = "is_learning_complete";
    public static final String COL_TOTAL_FLOWS = "total_flows";
    public static final String COL_KNOWN_PORTS = "known_ports";       // JSON Array of ints
    public static final String COL_KNOWN_DOMAINS = "known_domains";   // JSON Array of strings
    public static final String COL_ANOMALY_COUNT = "anomaly_count";

    public static final String TABLE_ANOMALIES = "anomalous_events";
    public static final String COL_ANOMALY_ID = "_id";
    public static final String COL_ANOMALY_TIME = "timestamp";
    public static final String COL_ANOMALY_PKG = "package_name";
    public static final String COL_ANOMALY_APP = "app_name";
    public static final String COL_ANOMALY_IP = "dest_ip";
    public static final String COL_ANOMALY_PORT = "dest_port";
    public static final String COL_ANOMALY_DOMAIN = "domain";
    public static final String COL_ANOMALY_TYPE = "anomaly_type";
    public static final String COL_ANOMALY_SEVERITY = "severity";
    public static final String COL_ANOMALY_DETAILS = "details";
    public static final String COL_ANOMALY_ACTION = "action_taken";

    private static volatile AppBaselineDb sInstance;

    public static synchronized AppBaselineDb getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new AppBaselineDb(context.getApplicationContext());
        }
        return sInstance;
    }

    private AppBaselineDb(Context context) {
        super(context, DB_NAME, null, DB_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE " + TABLE_BASELINES + " ("
                + COL_PACKAGE + " TEXT PRIMARY KEY, "
                + COL_APP_NAME + " TEXT, "
                + COL_FIRST_SEEN + " INTEGER, "
                + COL_LAST_SEEN + " INTEGER, "
                + COL_IS_LEARNED + " INTEGER DEFAULT 0, "
                + COL_TOTAL_FLOWS + " INTEGER DEFAULT 0, "
                + COL_KNOWN_PORTS + " TEXT, "
                + COL_KNOWN_DOMAINS + " TEXT, "
                + COL_ANOMALY_COUNT + " INTEGER DEFAULT 0"
                + ");");

        db.execSQL("CREATE TABLE " + TABLE_ANOMALIES + " ("
                + COL_ANOMALY_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
                + COL_ANOMALY_TIME + " INTEGER, "
                + COL_ANOMALY_PKG + " TEXT, "
                + COL_ANOMALY_APP + " TEXT, "
                + COL_ANOMALY_IP + " TEXT, "
                + COL_ANOMALY_PORT + " INTEGER, "
                + COL_ANOMALY_DOMAIN + " TEXT, "
                + COL_ANOMALY_TYPE + " TEXT, "
                + COL_ANOMALY_SEVERITY + " TEXT, "
                + COL_ANOMALY_DETAILS + " TEXT, "
                + COL_ANOMALY_ACTION + " TEXT"
                + ");");

        db.execSQL("CREATE INDEX idx_anom_time ON " + TABLE_ANOMALIES + " (" + COL_ANOMALY_TIME + ");");
        db.execSQL("CREATE INDEX idx_anom_pkg ON " + TABLE_ANOMALIES + " (" + COL_ANOMALY_PKG + ");");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_BASELINES);
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_ANOMALIES);
        onCreate(db);
    }

    public static class AppProfile {
        public String packageName = "";
        public String appName = "";
        public long firstSeen = 0;
        public long lastSeen = 0;
        public boolean isLearningComplete = false;
        public int totalFlows = 0;
        public Set<Integer> knownPorts = new HashSet<>();
        public Set<String> knownDomains = new HashSet<>();
        public int anomalyCount = 0;

        public boolean isKnownPort(int port) {
            return knownPorts.contains(port);
        }

        public boolean isKnownDomain(String domain) {
            if (domain == null || domain.isEmpty()) return true;
            return knownDomains.contains(domain.toLowerCase());
        }
    }

    public static class AnomalyEvent {
        public long id;
        public long timestamp;
        public String packageName;
        public String appName;
        public String destIp;
        public int destPort;
        public String domain;
        public String anomalyType;
        public String severity;
        public String details;
        public String actionTaken;
    }

    public synchronized AppProfile getProfile(String packageName) {
        if (packageName == null) return null;
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor cursor = db.query(TABLE_BASELINES, null, COL_PACKAGE + " = ?",
                new String[]{packageName}, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                AppProfile profile = new AppProfile();
                profile.packageName = cursor.getString(cursor.getColumnIndexOrThrow(COL_PACKAGE));
                profile.appName = cursor.getString(cursor.getColumnIndexOrThrow(COL_APP_NAME));
                profile.firstSeen = cursor.getLong(cursor.getColumnIndexOrThrow(COL_FIRST_SEEN));
                profile.lastSeen = cursor.getLong(cursor.getColumnIndexOrThrow(COL_LAST_SEEN));
                profile.isLearningComplete = cursor.getInt(cursor.getColumnIndexOrThrow(COL_IS_LEARNED)) == 1;
                profile.totalFlows = cursor.getInt(cursor.getColumnIndexOrThrow(COL_TOTAL_FLOWS));
                profile.anomalyCount = cursor.getInt(cursor.getColumnIndexOrThrow(COL_ANOMALY_COUNT));

                String portsJson = cursor.getString(cursor.getColumnIndexOrThrow(COL_KNOWN_PORTS));
                if (portsJson != null && !portsJson.isEmpty()) {
                    try {
                        JSONArray arr = new JSONArray(portsJson);
                        for (int i = 0; i < arr.length(); i++) {
                            profile.knownPorts.add(arr.getInt(i));
                        }
                    } catch (Exception ignored) {}
                }

                String domJson = cursor.getString(cursor.getColumnIndexOrThrow(COL_KNOWN_DOMAINS));
                if (domJson != null && !domJson.isEmpty()) {
                    try {
                        JSONArray arr = new JSONArray(domJson);
                        for (int i = 0; i < arr.length(); i++) {
                            profile.knownDomains.add(arr.getString(i).toLowerCase());
                        }
                    } catch (Exception ignored) {}
                }

                return profile;
            }
        } catch (Exception e) {
            Log.e(TAG, "Error fetching profile for " + packageName + ": " + e.getMessage());
        }
        return null;
    }

    public synchronized void saveProfile(AppProfile profile) {
        if (profile == null || profile.packageName == null) return;
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put(COL_PACKAGE, profile.packageName);
        cv.put(COL_APP_NAME, profile.appName);
        cv.put(COL_FIRST_SEEN, profile.firstSeen);
        cv.put(COL_LAST_SEEN, profile.lastSeen);
        cv.put(COL_IS_LEARNED, profile.isLearningComplete ? 1 : 0);
        cv.put(COL_TOTAL_FLOWS, profile.totalFlows);
        cv.put(COL_ANOMALY_COUNT, profile.anomalyCount);

        JSONArray portsArr = new JSONArray();
        for (Integer p : profile.knownPorts) portsArr.put(p);
        cv.put(COL_KNOWN_PORTS, portsArr.toString());

        JSONArray domArr = new JSONArray();
        for (String d : profile.knownDomains) domArr.put(d);
        cv.put(COL_KNOWN_DOMAINS, domArr.toString());

        db.insertWithOnConflict(TABLE_BASELINES, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public synchronized void recordAnomaly(AnomalyEvent event) {
        if (event == null) return;
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put(COL_ANOMALY_TIME, event.timestamp);
        cv.put(COL_ANOMALY_PKG, event.packageName);
        cv.put(COL_ANOMALY_APP, event.appName);
        cv.put(COL_ANOMALY_IP, event.destIp);
        cv.put(COL_ANOMALY_PORT, event.destPort);
        cv.put(COL_ANOMALY_DOMAIN, event.domain);
        cv.put(COL_ANOMALY_TYPE, event.anomalyType);
        cv.put(COL_ANOMALY_SEVERITY, event.severity);
        cv.put(COL_ANOMALY_DETAILS, event.details);
        cv.put(COL_ANOMALY_ACTION, event.actionTaken);

        db.insert(TABLE_ANOMALIES, null, cv);

        // Increment anomaly count on profile
        db.execSQL("UPDATE " + TABLE_BASELINES + " SET " + COL_ANOMALY_COUNT + " = " + COL_ANOMALY_COUNT + " + 1 WHERE " + COL_PACKAGE + " = ?",
                new String[]{event.packageName});
    }

    public synchronized List<AnomalyEvent> getRecentAnomalies(int limit) {
        List<AnomalyEvent> list = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor cursor = db.query(TABLE_ANOMALIES, null, null, null, null, null,
                COL_ANOMALY_TIME + " DESC", String.valueOf(limit))) {
            if (cursor != null && cursor.moveToFirst()) {
                do {
                    AnomalyEvent e = new AnomalyEvent();
                    e.id = cursor.getLong(cursor.getColumnIndexOrThrow(COL_ANOMALY_ID));
                    e.timestamp = cursor.getLong(cursor.getColumnIndexOrThrow(COL_ANOMALY_TIME));
                    e.packageName = cursor.getString(cursor.getColumnIndexOrThrow(COL_ANOMALY_PKG));
                    e.appName = cursor.getString(cursor.getColumnIndexOrThrow(COL_ANOMALY_APP));
                    e.destIp = cursor.getString(cursor.getColumnIndexOrThrow(COL_ANOMALY_IP));
                    e.destPort = cursor.getInt(cursor.getColumnIndexOrThrow(COL_ANOMALY_PORT));
                    e.domain = cursor.getString(cursor.getColumnIndexOrThrow(COL_ANOMALY_DOMAIN));
                    e.anomalyType = cursor.getString(cursor.getColumnIndexOrThrow(COL_ANOMALY_TYPE));
                    e.severity = cursor.getString(cursor.getColumnIndexOrThrow(COL_ANOMALY_SEVERITY));
                    e.details = cursor.getString(cursor.getColumnIndexOrThrow(COL_ANOMALY_DETAILS));
                    e.actionTaken = cursor.getString(cursor.getColumnIndexOrThrow(COL_ANOMALY_ACTION));
                    list.add(e);
                } while (cursor.moveToNext());
            }
        } catch (Exception e) {
            Log.e(TAG, "Error retrieving anomalies: " + e.getMessage());
        }
        return list;
    }
}
