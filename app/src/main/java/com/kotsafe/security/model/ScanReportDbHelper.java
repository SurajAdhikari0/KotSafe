/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import java.util.ArrayList;
import java.util.List;

/**
 * SQLite storage for scan execution history, background reports, and security audit telemetry.
 */
public class ScanReportDbHelper extends SQLiteOpenHelper {
    private static final String DATABASE_NAME = "scan_reports.db";
    private static final int DATABASE_VERSION = 1;

    public static final String TABLE_REPORTS = "scan_reports";

    public static final String COL_ID = "id";
    public static final String COL_TIMESTAMP = "timestamp";
    public static final String COL_SCAN_MODE = "scan_mode";
    public static final String COL_IS_BACKGROUND = "is_background";
    public static final String COL_SECURITY_SCORE = "security_score";
    public static final String COL_THREATS_DETECTED = "threats_detected";
    public static final String COL_SUSPICIOUS_DETECTED = "suspicious_detected";
    public static final String COL_LOW_RISK_COUNT = "low_risk_count";
    public static final String COL_PACKAGES_SCANNED = "packages_scanned";
    public static final String COL_SPLITS_SCANNED = "splits_scanned";
    public static final String COL_STORAGE_SCANNED = "storage_scanned";
    public static final String COL_IPS_SCANNED = "ips_scanned";
    public static final String COL_URLS_SCANNED = "urls_scanned";
    public static final String COL_DURATION_MS = "duration_ms";
    public static final String COL_SUMMARY = "summary";

    private static ScanReportDbHelper sInstance;

    public static synchronized ScanReportDbHelper getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new ScanReportDbHelper(context.getApplicationContext());
        }
        return sInstance;
    }

    private ScanReportDbHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        String createSql = "CREATE TABLE " + TABLE_REPORTS + " (" +
                COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                COL_TIMESTAMP + " INTEGER NOT NULL, " +
                COL_SCAN_MODE + " TEXT NOT NULL, " +
                COL_IS_BACKGROUND + " INTEGER NOT NULL DEFAULT 0, " +
                COL_SECURITY_SCORE + " INTEGER NOT NULL DEFAULT 100, " +
                COL_THREATS_DETECTED + " INTEGER NOT NULL DEFAULT 0, " +
                COL_SUSPICIOUS_DETECTED + " INTEGER NOT NULL DEFAULT 0, " +
                COL_LOW_RISK_COUNT + " INTEGER NOT NULL DEFAULT 0, " +
                COL_PACKAGES_SCANNED + " INTEGER NOT NULL DEFAULT 0, " +
                COL_SPLITS_SCANNED + " INTEGER NOT NULL DEFAULT 0, " +
                COL_STORAGE_SCANNED + " INTEGER NOT NULL DEFAULT 0, " +
                COL_IPS_SCANNED + " INTEGER NOT NULL DEFAULT 0, " +
                COL_URLS_SCANNED + " INTEGER NOT NULL DEFAULT 0, " +
                COL_DURATION_MS + " INTEGER NOT NULL DEFAULT 0, " +
                COL_SUMMARY + " TEXT" +
                ");";
        db.execSQL(createSql);
        db.execSQL("CREATE INDEX idx_report_time ON " + TABLE_REPORTS + " (" + COL_TIMESTAMP + " DESC);");
        db.execSQL("CREATE INDEX idx_report_bg ON " + TABLE_REPORTS + " (" + COL_IS_BACKGROUND + ");");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_REPORTS);
        onCreate(db);
    }

    public synchronized long insertReport(ScanReportEntry entry) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(COL_TIMESTAMP, entry.timestamp);
        values.put(COL_SCAN_MODE, entry.scanMode);
        values.put(COL_IS_BACKGROUND, entry.isBackground ? 1 : 0);
        values.put(COL_SECURITY_SCORE, entry.securityScore);
        values.put(COL_THREATS_DETECTED, entry.threatsDetected);
        values.put(COL_SUSPICIOUS_DETECTED, entry.suspiciousDetected);
        values.put(COL_LOW_RISK_COUNT, entry.lowRiskCount);
        values.put(COL_PACKAGES_SCANNED, entry.packagesScanned);
        values.put(COL_SPLITS_SCANNED, entry.splitsScanned);
        values.put(COL_STORAGE_SCANNED, entry.storageScanned);
        values.put(COL_IPS_SCANNED, entry.ipsScanned);
        values.put(COL_URLS_SCANNED, entry.urlsScanned);
        values.put(COL_DURATION_MS, entry.durationMs);
        values.put(COL_SUMMARY, entry.summary);

        long id = db.insert(TABLE_REPORTS, null, values);
        entry.id = id;
        return id;
    }

    public synchronized ScanReportEntry getLatestReport() {
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor c = db.query(TABLE_REPORTS, null, null, null, null, null, COL_TIMESTAMP + " DESC", "1")) {
            if (c != null && c.moveToFirst()) {
                return cursorToEntry(c);
            }
        }
        return null;
    }

    public synchronized ScanReportEntry getLatestBackgroundReport() {
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor c = db.query(TABLE_REPORTS, null, COL_IS_BACKGROUND + " = 1", null, null, null, COL_TIMESTAMP + " DESC", "1")) {
            if (c != null && c.moveToFirst()) {
                return cursorToEntry(c);
            }
        }
        return null;
    }

    public synchronized List<ScanReportEntry> getAllReports(int limit) {
        List<ScanReportEntry> list = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor c = db.query(TABLE_REPORTS, null, null, null, null, null, COL_TIMESTAMP + " DESC", String.valueOf(limit))) {
            while (c != null && c.moveToNext()) {
                list.add(cursorToEntry(c));
            }
        }
        return list;
    }

    public synchronized int clearReportsOlderThan(int days) {
        long cutoff = System.currentTimeMillis() - ((long) days * 24L * 60L * 60L * 1000L);
        SQLiteDatabase db = getWritableDatabase();
        return db.delete(TABLE_REPORTS, COL_TIMESTAMP + " < ?", new String[]{String.valueOf(cutoff)});
    }

    private ScanReportEntry cursorToEntry(Cursor c) {
        ScanReportEntry e = new ScanReportEntry();
        e.id = c.getLong(c.getColumnIndexOrThrow(COL_ID));
        e.timestamp = c.getLong(c.getColumnIndexOrThrow(COL_TIMESTAMP));
        e.scanMode = c.getString(c.getColumnIndexOrThrow(COL_SCAN_MODE));
        e.isBackground = c.getInt(c.getColumnIndexOrThrow(COL_IS_BACKGROUND)) == 1;
        e.securityScore = c.getInt(c.getColumnIndexOrThrow(COL_SECURITY_SCORE));
        e.threatsDetected = c.getInt(c.getColumnIndexOrThrow(COL_THREATS_DETECTED));
        e.suspiciousDetected = c.getInt(c.getColumnIndexOrThrow(COL_SUSPICIOUS_DETECTED));
        e.lowRiskCount = c.getInt(c.getColumnIndexOrThrow(COL_LOW_RISK_COUNT));
        e.packagesScanned = c.getInt(c.getColumnIndexOrThrow(COL_PACKAGES_SCANNED));
        e.splitsScanned = c.getInt(c.getColumnIndexOrThrow(COL_SPLITS_SCANNED));
        e.storageScanned = c.getInt(c.getColumnIndexOrThrow(COL_STORAGE_SCANNED));
        e.ipsScanned = c.getInt(c.getColumnIndexOrThrow(COL_IPS_SCANNED));
        e.urlsScanned = c.getInt(c.getColumnIndexOrThrow(COL_URLS_SCANNED));
        e.durationMs = c.getLong(c.getColumnIndexOrThrow(COL_DURATION_MS));
        e.summary = c.getString(c.getColumnIndexOrThrow(COL_SUMMARY));
        return e;
    }
}
