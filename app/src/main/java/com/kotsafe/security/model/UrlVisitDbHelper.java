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

import com.kotsafe.security.Log;

import java.util.ArrayList;
import java.util.List;

/**
 * DOMAIN 2 — LOGS
 *
 * High-write-volume table for URL visit events, scan events, and network decisions.
 * Supports configurable retention (auto-purge rows older than N days).
 * NEVER contains security rules — those live in SecurityRulesDb.
 */
public class UrlVisitDbHelper extends SQLiteOpenHelper {
    private static final String TAG = "UrlVisitDbHelper";
    public static final String DB_NAME = "logs.db";
    private static final int DB_VERSION = 1;

    // ── url_visits ────────────────────────────────────────────────────────────
    public static final String TABLE_URL_VISITS = "url_visits";
    public static final String COL_ID = "_id";
    public static final String COL_TIMESTAMP = "timestamp";
    public static final String COL_URL = "url";
    public static final String COL_DOMAIN = "domain";
    public static final String COL_IP = "ip";
    public static final String COL_APP_NAME = "app_name";
    public static final String COL_PACKAGE_NAME = "package_name";
    public static final String COL_METHOD = "method";
    public static final String COL_WAS_BLOCKED = "was_blocked";
    public static final String COL_RISK_SCORE = "risk_score";
    public static final String COL_VERDICT = "verdict";

    // ── scan_events ────────────────────────────────────────────────────────────
    public static final String TABLE_SCAN_EVENTS = "scan_events";
    public static final String COL_SCAN_MODE = "scan_mode";          // QUICK|FULL|DEEP
    public static final String COL_STARTED_AT = "started_at";
    public static final String COL_FINISHED_AT = "finished_at";
    public static final String COL_FILES_SCANNED = "files_scanned";
    public static final String COL_THREATS_FOUND = "threats_found";
    public static final String COL_SCORE = "score";

    // Default retention: 30 days
    private static final long DEFAULT_RETENTION_MS = 30L * 24 * 60 * 60 * 1000;

    private static UrlVisitDbHelper sInstance;

    public static synchronized UrlVisitDbHelper getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new UrlVisitDbHelper(context.getApplicationContext());
        }
        return sInstance;
    }

    private UrlVisitDbHelper(Context context) {
        super(context, DB_NAME, null, DB_VERSION);
    }

    @Override
    public void onConfigure(SQLiteDatabase db) {
        super.onConfigure(db);
        try {
            db.enableWriteAheadLogging();
            db.execSQL("PRAGMA busy_timeout = 5000");
        } catch (Exception ignored) {}
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_URL_VISITS + " (" +
                COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                COL_TIMESTAMP + " INTEGER NOT NULL DEFAULT (strftime('%s','now')*1000), " +
                COL_URL + " TEXT, " +
                COL_DOMAIN + " TEXT, " +
                COL_IP + " TEXT, " +
                COL_APP_NAME + " TEXT, " +
                COL_PACKAGE_NAME + " TEXT, " +
                COL_METHOD + " TEXT, " +
                COL_WAS_BLOCKED + " INTEGER DEFAULT 0, " +
                COL_RISK_SCORE + " INTEGER DEFAULT 0, " +
                COL_VERDICT + " TEXT DEFAULT 'SAFE')");

        db.execSQL("CREATE INDEX IF NOT EXISTS idx_uv_domain ON " +
                TABLE_URL_VISITS + "(" + COL_DOMAIN + ")");
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_uv_ts ON " +
                TABLE_URL_VISITS + "(" + COL_TIMESTAMP + ")");

        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_SCAN_EVENTS + " (" +
                COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                COL_SCAN_MODE + " TEXT, " +
                COL_STARTED_AT + " INTEGER, " +
                COL_FINISHED_AT + " INTEGER, " +
                COL_FILES_SCANNED + " INTEGER DEFAULT 0, " +
                COL_THREATS_FOUND + " INTEGER DEFAULT 0, " +
                COL_SCORE + " INTEGER DEFAULT 100)");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {}

    // ─── Write ────────────────────────────────────────────────────────────────

    public long logUrlVisit(UrlVisitLog entry) {
        ContentValues cv = new ContentValues();
        cv.put(COL_TIMESTAMP, entry.timestamp > 0 ? entry.timestamp : System.currentTimeMillis());
        cv.put(COL_URL, entry.url);
        cv.put(COL_DOMAIN, entry.domain);
        cv.put(COL_IP, entry.ip);
        cv.put(COL_APP_NAME, entry.appName);
        cv.put(COL_PACKAGE_NAME, entry.packageName);
        cv.put(COL_METHOD, entry.method);
        cv.put(COL_WAS_BLOCKED, entry.wasBlocked ? 1 : 0);
        cv.put(COL_RISK_SCORE, entry.riskScore);
        cv.put(COL_VERDICT, entry.verdict != null ? entry.verdict : "SAFE");
        try {
            return getWritableDatabase().insertOrThrow(TABLE_URL_VISITS, null, cv);
        } catch (Exception e) {
            Log.e(TAG, "logUrlVisit: " + e.getMessage());
            return -1;
        }
    }

    public void updateUrlVerdict(long id, int riskScore, String verdict) {
        ContentValues cv = new ContentValues();
        cv.put(COL_RISK_SCORE, riskScore);
        cv.put(COL_VERDICT, verdict);
        try {
            getWritableDatabase().update(TABLE_URL_VISITS, cv,
                    COL_ID + "=?", new String[]{String.valueOf(id)});
        } catch (Exception e) {
            Log.e(TAG, "updateUrlVerdict: " + e.getMessage());
        }
    }

    public long logScanEvent(String mode, long startedAt) {
        ContentValues cv = new ContentValues();
        cv.put(COL_SCAN_MODE, mode);
        cv.put(COL_STARTED_AT, startedAt);
        try {
            return getWritableDatabase().insertOrThrow(TABLE_SCAN_EVENTS, null, cv);
        } catch (Exception e) {
            Log.e(TAG, "logScanEvent: " + e.getMessage());
            return -1;
        }
    }

    public void finalizeScanEvent(long id, int filesScanned, int threatsFound, int score) {
        ContentValues cv = new ContentValues();
        cv.put(COL_FINISHED_AT, System.currentTimeMillis());
        cv.put(COL_FILES_SCANNED, filesScanned);
        cv.put(COL_THREATS_FOUND, threatsFound);
        cv.put(COL_SCORE, score);
        try {
            getWritableDatabase().update(TABLE_SCAN_EVENTS, cv,
                    COL_ID + "=?", new String[]{String.valueOf(id)});
        } catch (Exception e) {
            Log.e(TAG, "finalizeScanEvent: " + e.getMessage());
        }
    }

    // ─── Query ────────────────────────────────────────────────────────────────

    public List<UrlVisitLog> getRecentVisits(int limit) {
        List<UrlVisitLog> list = new ArrayList<>();
        String sql = "SELECT * FROM " + TABLE_URL_VISITS +
                " ORDER BY " + COL_TIMESTAMP + " DESC LIMIT " + limit;
        try (Cursor c = getReadableDatabase().rawQuery(sql, null)) {
            while (c.moveToNext()) list.add(cursorToLog(c));
        } catch (Exception e) {
            Log.e(TAG, "getRecentVisits: " + e.getMessage());
        }
        return list;
    }

    public List<UrlVisitLog> getVisitsByDomain(String domain, int limit) {
        List<UrlVisitLog> list = new ArrayList<>();
        try (Cursor c = getReadableDatabase().query(TABLE_URL_VISITS, null,
                COL_DOMAIN + "=?", new String[]{domain}, null, null,
                COL_TIMESTAMP + " DESC", String.valueOf(limit))) {
            while (c.moveToNext()) list.add(cursorToLog(c));
        } catch (Exception e) {
            Log.e(TAG, "getVisitsByDomain: " + e.getMessage());
        }
        return list;
    }

    public List<UrlVisitLog> getBlockedVisits(int limit) {
        List<UrlVisitLog> list = new ArrayList<>();
        try (Cursor c = getReadableDatabase().query(TABLE_URL_VISITS, null,
                COL_WAS_BLOCKED + "=1", null, null, null,
                COL_TIMESTAMP + " DESC", String.valueOf(limit))) {
            while (c.moveToNext()) list.add(cursorToLog(c));
        } catch (Exception e) {
            Log.e(TAG, "getBlockedVisits: " + e.getMessage());
        }
        return list;
    }

    // ─── Retention ────────────────────────────────────────────────────────────

    /**
     * Deletes log entries older than retentionDays. Called by RetentionWorker.
     * @return number of rows deleted
     */
    public int purgeExpiredLogs(int retentionDays) {
        long cutoff = System.currentTimeMillis() - ((long) retentionDays * 24 * 60 * 60 * 1000);
        try {
            int deleted = getWritableDatabase().delete(TABLE_URL_VISITS,
                    COL_TIMESTAMP + " < ?", new String[]{String.valueOf(cutoff)});
            Log.i(TAG, "Purged " + deleted + " URL visit logs older than " + retentionDays + " days");
            return deleted;
        } catch (Exception e) {
            Log.e(TAG, "purgeExpiredLogs: " + e.getMessage());
            return 0;
        }
    }

    /** Clears ALL logs. Called only by explicit user action. NEVER touches rules. */
    public int clearAll() {
        try {
            SQLiteDatabase db = getWritableDatabase();
            int total = db.delete(TABLE_URL_VISITS, null, null);
            total += db.delete(TABLE_SCAN_EVENTS, null, null);
            db.execSQL("VACUUM");
            return total;
        } catch (Exception e) {
            Log.e(TAG, "clearAll: " + e.getMessage());
            return 0;
        }
    }

    /** Returns count of URL visit records. */
    public int getVisitCount() {
        try (Cursor c = getReadableDatabase().rawQuery("SELECT COUNT(*) FROM " + TABLE_URL_VISITS, null)) {
            if (c.moveToFirst()) return c.getInt(0);
        } catch (Exception e) {
            Log.e(TAG, "getVisitCount: " + e.getMessage());
        }
        return 0;
    }

    private UrlVisitLog cursorToLog(Cursor c) {
        UrlVisitLog log = new UrlVisitLog();
        log.id = c.getLong(c.getColumnIndexOrThrow(COL_ID));
        log.timestamp = c.getLong(c.getColumnIndexOrThrow(COL_TIMESTAMP));
        log.url = c.getString(c.getColumnIndexOrThrow(COL_URL));
        log.domain = c.getString(c.getColumnIndexOrThrow(COL_DOMAIN));
        log.ip = c.getString(c.getColumnIndexOrThrow(COL_IP));
        log.appName = c.getString(c.getColumnIndexOrThrow(COL_APP_NAME));
        log.packageName = c.getString(c.getColumnIndexOrThrow(COL_PACKAGE_NAME));
        log.method = c.getString(c.getColumnIndexOrThrow(COL_METHOD));
        log.wasBlocked = c.getInt(c.getColumnIndexOrThrow(COL_WAS_BLOCKED)) == 1;
        log.riskScore = c.getInt(c.getColumnIndexOrThrow(COL_RISK_SCORE));
        log.verdict = c.getString(c.getColumnIndexOrThrow(COL_VERDICT));
        return log;
    }

    /** Returns recent URL visits for a specific package. Used by correlation engine. */
    public List<UrlVisitLog> getVisitsForPackage(String packageName, int limit) {
        List<UrlVisitLog> list = new ArrayList<>();
        if (packageName == null) return list;
        try (SQLiteDatabase db = getReadableDatabase();
             Cursor c = db.query(TABLE_URL_VISITS, null,
                     COL_PACKAGE_NAME + "=?", new String[]{packageName},
                     null, null, COL_TIMESTAMP + " DESC", String.valueOf(limit))) {
            while (c.moveToNext()) list.add(cursorToLog(c));
        } catch (Exception e) {
            Log.e(TAG, "getVisitsForPackage: " + e.getMessage());
        }
        return list;
    }
}

