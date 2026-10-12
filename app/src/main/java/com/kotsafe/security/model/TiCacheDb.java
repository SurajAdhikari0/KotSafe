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

/**
 * DOMAIN 3 — CACHE
 *
 * Disposable acceleration layer for Threat Intelligence responses.
 * Maps IOC → TI verdict with a TTL so the router skips redundant API calls.
 *
 * This entire database can be freely deleted at any time.
 * The next scan/query will simply re-fetch from providers.
 * It NEVER influences Security Rules.
 */
public class TiCacheDb extends SQLiteOpenHelper {
    private static final String TAG = "TiCacheDb";
    public static final String DB_NAME = "cache.db";
    private static final int DB_VERSION = 1;

    public static final String TABLE_CACHE = "ti_cache";
    public static final String COL_ID = "_id";
    public static final String COL_IOC_VALUE = "ioc_value";    // sha256 | ip | domain | url
    public static final String COL_IOC_TYPE = "ioc_type";      // HASH | IP | DOMAIN | URL
    public static final String COL_PROVIDER = "provider";      // OTX | MB | VT
    public static final String COL_IS_MALICIOUS = "is_malicious";
    public static final String COL_IS_SUSPICIOUS = "is_suspicious";
    public static final String COL_RISK_SCORE = "risk_score";
    public static final String COL_VERDICT = "verdict";
    public static final String COL_MALWARE_FAMILY = "malware_family";
    public static final String COL_DETAILS = "details";
    public static final String COL_FETCHED_AT = "fetched_at";
    public static final String COL_EXPIRES_AT = "expires_at";

    /** Default TTL: 7 days */
    public static final long DEFAULT_TTL_MS = 7L * 24 * 60 * 60 * 1000;

    private static TiCacheDb sInstance;

    public static synchronized TiCacheDb getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new TiCacheDb(context.getApplicationContext());
        }
        return sInstance;
    }

    private TiCacheDb(Context context) {
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
        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_CACHE + " (" +
                COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                COL_IOC_VALUE + " TEXT NOT NULL, " +
                COL_IOC_TYPE + " TEXT NOT NULL, " +
                COL_PROVIDER + " TEXT NOT NULL, " +
                COL_IS_MALICIOUS + " INTEGER DEFAULT 0, " +
                COL_IS_SUSPICIOUS + " INTEGER DEFAULT 0, " +
                COL_RISK_SCORE + " INTEGER DEFAULT 0, " +
                COL_VERDICT + " TEXT DEFAULT 'SAFE', " +
                COL_MALWARE_FAMILY + " TEXT, " +
                COL_DETAILS + " TEXT, " +
                COL_FETCHED_AT + " INTEGER NOT NULL, " +
                COL_EXPIRES_AT + " INTEGER NOT NULL, " +
                "UNIQUE(" + COL_IOC_VALUE + ", " + COL_PROVIDER + ") ON CONFLICT REPLACE)");

        db.execSQL("CREATE INDEX IF NOT EXISTS idx_cache_ioc ON " +
                TABLE_CACHE + "(" + COL_IOC_VALUE + ", " + COL_IOC_TYPE + ")");
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_cache_exp ON " +
                TABLE_CACHE + "(" + COL_EXPIRES_AT + ")");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int old, int nv) {}

    // ─── Write ────────────────────────────────────────────────────────────────

    public void store(String iocValue, String iocType, String provider,
                      boolean isMalicious, boolean isSuspicious,
                      int riskScore, String verdict, String malwareFamily,
                      String details, long ttlMs) {
        long now = System.currentTimeMillis();
        ContentValues cv = new ContentValues();
        cv.put(COL_IOC_VALUE, iocValue);
        cv.put(COL_IOC_TYPE, iocType);
        cv.put(COL_PROVIDER, provider);
        cv.put(COL_IS_MALICIOUS, isMalicious ? 1 : 0);
        cv.put(COL_IS_SUSPICIOUS, isSuspicious ? 1 : 0);
        cv.put(COL_RISK_SCORE, riskScore);
        cv.put(COL_VERDICT, verdict);
        cv.put(COL_MALWARE_FAMILY, malwareFamily);
        cv.put(COL_DETAILS, details);
        cv.put(COL_FETCHED_AT, now);
        cv.put(COL_EXPIRES_AT, now + (ttlMs > 0 ? ttlMs : DEFAULT_TTL_MS));
        try {
            getWritableDatabase().insertOrThrow(TABLE_CACHE, null, cv);
        } catch (Exception e) {
            Log.e(TAG, "store: " + e.getMessage());
        }
    }

    // ─── Lookup ───────────────────────────────────────────────────────────────

    /**
     * Returns the cached entry for an IOC if it exists AND has not expired.
     * Returns null if not cached or expired (caller should query TI providers).
     */
    public CacheEntry lookup(String iocValue) {
        long now = System.currentTimeMillis();
        String sql = "SELECT * FROM " + TABLE_CACHE +
                " WHERE " + COL_IOC_VALUE + "=? AND " + COL_EXPIRES_AT + ">?" +
                " ORDER BY " + COL_RISK_SCORE + " DESC LIMIT 1";
        try (Cursor c = getReadableDatabase().rawQuery(sql,
                new String[]{iocValue, String.valueOf(now)})) {
            if (c.moveToFirst()) return cursorToEntry(c);
        } catch (Exception e) {
            Log.e(TAG, "lookup: " + e.getMessage());
        }
        return null;
    }

    public boolean isCached(String iocValue) {
        return lookup(iocValue) != null;
    }

    // ─── Purge ────────────────────────────────────────────────────────────────

    /** Removes all expired entries. Called by RetentionWorker. */
    public int purgeExpired() {
        long now = System.currentTimeMillis();
        try {
            int deleted = getWritableDatabase().delete(TABLE_CACHE,
                    COL_EXPIRES_AT + " < ?", new String[]{String.valueOf(now)});
            Log.i(TAG, "Purged " + deleted + " expired TI cache entries");
            return deleted;
        } catch (Exception e) {
            Log.e(TAG, "purgeExpired: " + e.getMessage());
            return 0;
        }
    }

    /** Clears ALL cache entries. Freely callable — no security impact. */
    public int clearAll() {
        try {
            int n = getWritableDatabase().delete(TABLE_CACHE, null, null);
            getWritableDatabase().execSQL("VACUUM");
            return n;
        } catch (Exception e) {
            Log.e(TAG, "clearAll: " + e.getMessage());
            return 0;
        }
    }

    /** Returns count of cached TI entries. */
    public int getCacheCount() {
        try (Cursor c = getReadableDatabase().rawQuery("SELECT COUNT(*) FROM " + TABLE_CACHE, null)) {
            if (c.moveToFirst()) return c.getInt(0);
        } catch (Exception e) {
            Log.e(TAG, "getCacheCount: " + e.getMessage());
        }
        return 0;
    }

    // ─── POJO ─────────────────────────────────────────────────────────────────

    public static class CacheEntry {
        public String iocValue;
        public String iocType;
        public String provider;
        public boolean isMalicious;
        public boolean isSuspicious;
        public int riskScore;
        public String verdict;
        public String malwareFamily;
        public String details;
        public long fetchedAt;
        public long expiresAt;
    }

    private CacheEntry cursorToEntry(Cursor c) {
        CacheEntry e = new CacheEntry();
        e.iocValue = c.getString(c.getColumnIndexOrThrow(COL_IOC_VALUE));
        e.iocType = c.getString(c.getColumnIndexOrThrow(COL_IOC_TYPE));
        e.provider = c.getString(c.getColumnIndexOrThrow(COL_PROVIDER));
        e.isMalicious = c.getInt(c.getColumnIndexOrThrow(COL_IS_MALICIOUS)) == 1;
        e.isSuspicious = c.getInt(c.getColumnIndexOrThrow(COL_IS_SUSPICIOUS)) == 1;
        e.riskScore = c.getInt(c.getColumnIndexOrThrow(COL_RISK_SCORE));
        e.verdict = c.getString(c.getColumnIndexOrThrow(COL_VERDICT));
        e.malwareFamily = c.getString(c.getColumnIndexOrThrow(COL_MALWARE_FAMILY));
        e.details = c.getString(c.getColumnIndexOrThrow(COL_DETAILS));
        e.fetchedAt = c.getLong(c.getColumnIndexOrThrow(COL_FETCHED_AT));
        e.expiresAt = c.getLong(c.getColumnIndexOrThrow(COL_EXPIRES_AT));
        return e;
    }
}
