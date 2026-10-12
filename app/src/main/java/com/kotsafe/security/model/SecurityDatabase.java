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
import com.kotsafe.security.Log;

/**
 * Central access point for the four isolated security storage domains:
 *
 *  1. EVIDENCE  — why detections happened (IOCs, YARA hits, TI results, risk scores)
 *  2. LOGS      — what happened (network events, firewall decisions, URL visits, scan history)
 *  3. CACHE     — disposable TI responses, hash→verdict acceleration data
 *  4. RULES     — active blocks, whitelist, YARA rules, quarantine metadata
 *
 * Security guarantee:
 *   "Clear Evidence", "Clear Logs", and "Clear Cache" must NEVER touch RULES.
 *   Rules persist through all cleanup operations.
 */
public class SecurityDatabase {
    private static final String TAG = "SecurityDatabase";

    private static SecurityDatabase sInstance;

    private final EvidenceDbHelper mEvidenceDb;
    private final UrlVisitDbHelper mUrlVisitDb;
    private final TiCacheDb mTiCacheDb;
    private final SecurityRulesDb mRulesDb;

    public static synchronized SecurityDatabase getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new SecurityDatabase(context.getApplicationContext());
        }
        return sInstance;
    }

    private SecurityDatabase(Context context) {
        mEvidenceDb = EvidenceDbHelper.getInstance(context);
        mUrlVisitDb = UrlVisitDbHelper.getInstance(context);
        mTiCacheDb = TiCacheDb.getInstance(context);
        mRulesDb = SecurityRulesDb.getInstance(context);
        Log.d(TAG, "SecurityDatabase initialized (4 domains)");
    }

    // ─── Domain accessors ────────────────────────────────────────────────────

    /** Evidence domain: IOCs, YARA hits, TI results, risk scores. */
    public EvidenceDbHelper evidence() { return mEvidenceDb; }

    /** Logs domain: URL visits, scan events, network events. */
    public UrlVisitDbHelper logs() { return mUrlVisitDb; }

    /** Cache domain: disposable TI responses; can be freely deleted. */
    public TiCacheDb cache() { return mTiCacheDb; }

    /** Rules domain: active blocks, whitelist, YARA rules. NEVER auto-deleted. */
    public SecurityRulesDb rules() { return mRulesDb; }

    // ─── Selective clear operations ───────────────────────────────────────────

    /**
     * Clears all evidence records. Does NOT touch security rules.
     * @return number of evidence rows deleted
     */
    public int clearEvidence() {
        Log.i(TAG, "Clearing evidence domain");
        return mEvidenceDb.clearAll();
    }

    /**
     * Clears all log records (URL visits, scan history). Does NOT touch security rules.
     * @return number of log rows deleted
     */
    public int clearLogs() {
        Log.i(TAG, "Clearing logs domain");
        return mUrlVisitDb.clearAll();
    }

    /**
     * Clears all cached TI results. Does NOT touch security rules.
     * Safe to call at any time — next scan will re-fetch from providers.
     * @return number of cache rows deleted
     */
    public int clearCache() {
        Log.i(TAG, "Clearing cache domain");
        return mTiCacheDb.clearAll();
    }

    /**
     * Clears evidence + logs + cache in one shot.
     * Security rules are NEVER affected.
     */
    public void clearAllExceptRules() {
        Log.i(TAG, "Clearing Evidence + Logs + Cache (rules preserved)");
        mEvidenceDb.clearAll();
        mUrlVisitDb.clearAll();
        mTiCacheDb.clearAll();
    }

    // ─── Retention operations ───────────────────────────────────────────────

    /**
     * Purges evidence older than cutoffMillis. NEVER touches rules.
     */
    public int purgeEvidenceOlderThan(long cutoffMillis) {
        Log.i(TAG, "Purging evidence older than " + cutoffMillis);
        return mEvidenceDb.purgeOlderThan(cutoffMillis);
    }

    /**
     * Purges logs older than retentionDays. NEVER touches rules.
     */
    public int purgeLogsOlderThan(int retentionDays) {
        Log.i(TAG, "Purging logs older than " + retentionDays + " days");
        return mUrlVisitDb.purgeExpiredLogs(retentionDays);
    }

    /**
     * Purges expired TI cache entries. NEVER touches rules.
     */
    public int purgeExpiredCache() {
        Log.i(TAG, "Purging expired TI cache");
        return mTiCacheDb.purgeExpired();
    }

    /**
     * Reclaims fragmented database storage and optimizes SQLite pages.
     */
    public void optimizeDatabases() {
        Log.i(TAG, "Executing VACUUM on all security databases");
        try {
            mEvidenceDb.getWritableDatabase().execSQL("VACUUM");
            mUrlVisitDb.getWritableDatabase().execSQL("VACUUM");
            mTiCacheDb.getWritableDatabase().execSQL("VACUUM");
            mRulesDb.getWritableDatabase().execSQL("VACUUM");
        } catch (Exception e) {
            Log.w(TAG, "Database optimization failed: " + e.getMessage());
        }
    }

    // ─── Storage statistics ───────────────────────────────────────────────────

    public static class StorageStats {
        public long evidenceBytes;
        public long logsBytes;
        public long cacheBytes;
        public long rulesBytes;

        public int evidenceRows;
        public int logsRows;
        public int cacheRows;
        public int rulesRows;
        public int blockedRulesCount;
        public int allowedRulesCount;

        public long totalBytes() {
            return evidenceBytes + logsBytes + cacheBytes + rulesBytes;
        }
    }

    public StorageStats getStorageStats(Context context) {
        StorageStats stats = new StorageStats();
        try {
            stats.evidenceBytes = context.getDatabasePath(EvidenceDbHelper.DB_NAME).length();
            stats.logsBytes = context.getDatabasePath(UrlVisitDbHelper.DB_NAME).length();
            stats.cacheBytes = context.getDatabasePath(TiCacheDb.DB_NAME).length();
            stats.rulesBytes = context.getDatabasePath(SecurityRulesDb.DB_NAME).length();

            stats.evidenceRows = mEvidenceDb.getEvidenceCount();
            stats.logsRows = mUrlVisitDb.getVisitCount();
            stats.cacheRows = mTiCacheDb.getCacheCount();
            stats.rulesRows = mRulesDb.getRuleCount();
            stats.blockedRulesCount = mRulesDb.getRuleCountByAction(SecurityRulesDb.ACTION_BLOCK);
            stats.allowedRulesCount = mRulesDb.getRuleCountByAction(SecurityRulesDb.ACTION_ALLOW);
        } catch (Exception e) {
            Log.w(TAG, "Could not measure DB sizes: " + e.getMessage());
        }
        return stats;
    }
}
