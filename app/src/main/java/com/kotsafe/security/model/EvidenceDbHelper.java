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
import com.kotsafe.security.Utils;

import java.util.ArrayList;
import java.util.List;

/**
 * DOMAIN 1 — EVIDENCE
 *
 * Stores structured forensic evidence explaining why a detection was made.
 * Contains: detection events, file evidence, network evidence, TI provider results.
 *
 * This DB is read-heavy and write-occasional.
 * It is NEVER auto-deleted by retention workers; only by explicit user action.
 */
public class EvidenceDbHelper extends SQLiteOpenHelper {
    private static final String TAG = "EvidenceDbHelper";
    public static final String DB_NAME = "evidence.db";
    private static final int DB_VERSION = 1;

    // ── evidence (master) ────────────────────────────────────────────────────
    public static final String TABLE_EVIDENCE = "evidence";
    public static final String COL_ID = "_id";
    public static final String COL_TYPE = "type";           // FILE | NETWORK | APP | YARA | SANDBOX
    public static final String COL_TITLE = "title";
    public static final String COL_DESCRIPTION = "description";
    public static final String COL_RISK_SCORE = "risk_score";      // 0-100
    public static final String COL_VERDICT = "verdict";            // SAFE | SUSPICIOUS | HIGH | MALICIOUS
    public static final String COL_PACKAGE_NAME = "package_name";
    public static final String COL_IOC_VALUE = "ioc_value";        // sha256 / ip / domain / url
    public static final String COL_IOC_TYPE = "ioc_type";          // HASH | IP | DOMAIN | URL
    public static final String COL_MITRE_TECHNIQUES = "mitre_techniques"; // JSON array
    public static final String COL_SOURCE = "source";              // YARA | TI | HEURISTIC | USER
    public static final String COL_TIMESTAMP = "timestamp";
    public static final String COL_IS_ACTIVE = "is_active";        // 1=ongoing, 0=resolved

    // ── ti_evidence (TI provider responses) ─────────────────────────────────
    public static final String TABLE_TI_EVIDENCE = "ti_evidence";
    public static final String COL_EVIDENCE_ID = "evidence_id";    // FK → evidence._id
    public static final String COL_PROVIDER = "provider";          // OTX | MB | VT
    public static final String COL_RESULT_JSON = "result_json";
    public static final String COL_CONFIDENCE = "confidence";       // 0.0-1.0
    public static final String COL_MALWARE_FAMILY = "malware_family";
    public static final String COL_FETCHED_AT = "fetched_at";

    // ── yara_evidence ────────────────────────────────────────────────────────
    public static final String TABLE_YARA_EVIDENCE = "yara_evidence";
    public static final String COL_RULE_NAME = "rule_name";
    public static final String COL_RULE_TAGS = "rule_tags";
    public static final String COL_MATCHED_FILE = "matched_file";
    public static final String COL_MATCHED_STRINGS = "matched_strings"; // JSON

    // ── Verdict constants ─────────────────────────────────────────────────────
    public static final String VERDICT_SAFE = "SAFE";
    public static final String VERDICT_SUSPICIOUS = "SUSPICIOUS";
    public static final String VERDICT_HIGH = "HIGH";
    public static final String VERDICT_MALICIOUS = "MALICIOUS";

    private static EvidenceDbHelper sInstance;
    private final Context mContext;

    public static synchronized EvidenceDbHelper getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new EvidenceDbHelper(context.getApplicationContext());
        }
        return sInstance;
    }

    private EvidenceDbHelper(Context context) {
        super(context, DB_NAME, null, DB_VERSION);
        mContext = context;
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
    public void onOpen(SQLiteDatabase db) {
        super.onOpen(db);
        purgeSystemAppEvidence(db);
    }

    public void purgeSystemAppEvidence(SQLiteDatabase db) {
        try {
            // Remove any legacy evidence for official Android, Google, Samsung, OPPO, ColorOS, HeyTap, and OEM apps
            String sql = "DELETE FROM " + TABLE_EVIDENCE + " WHERE " +
                    COL_PACKAGE_NAME + " LIKE 'com.google.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.android.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'android%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.samsung.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.sec.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.miui.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.xiaomi.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.huawei.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.oppo.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.coloros.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.heytap.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.oplus.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.oppoex.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.vivo.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.iqoo.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.motorola.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.asus.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.oneplus.%' OR " +
                    COL_PACKAGE_NAME + " LIKE 'com.qualcomm.%'";
            db.execSQL(sql);
        } catch (Exception e) {
            Log.w(TAG, "purgeSystemAppEvidence error: " + e.getMessage());
        }
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_EVIDENCE + " (" +
                COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                COL_TYPE + " TEXT NOT NULL, " +
                COL_TITLE + " TEXT, " +
                COL_DESCRIPTION + " TEXT, " +
                COL_RISK_SCORE + " INTEGER DEFAULT 0, " +
                COL_VERDICT + " TEXT DEFAULT '" + VERDICT_SAFE + "', " +
                COL_PACKAGE_NAME + " TEXT, " +
                COL_IOC_VALUE + " TEXT, " +
                COL_IOC_TYPE + " TEXT, " +
                COL_MITRE_TECHNIQUES + " TEXT, " +
                COL_SOURCE + " TEXT, " +
                COL_TIMESTAMP + " INTEGER NOT NULL DEFAULT (strftime('%s','now')*1000), " +
                COL_IS_ACTIVE + " INTEGER DEFAULT 1)");

        db.execSQL("CREATE INDEX IF NOT EXISTS idx_evidence_ioc ON " + TABLE_EVIDENCE +
                "(" + COL_IOC_VALUE + ")");
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_evidence_ts ON " + TABLE_EVIDENCE +
                "(" + COL_TIMESTAMP + ")");

        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_TI_EVIDENCE + " (" +
                COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                COL_EVIDENCE_ID + " INTEGER, " +
                COL_PROVIDER + " TEXT, " +
                COL_IOC_VALUE + " TEXT, " +
                COL_IOC_TYPE + " TEXT, " +
                COL_RESULT_JSON + " TEXT, " +
                COL_CONFIDENCE + " REAL DEFAULT 0.0, " +
                COL_MALWARE_FAMILY + " TEXT, " +
                COL_VERDICT + " TEXT, " +
                COL_FETCHED_AT + " INTEGER NOT NULL DEFAULT (strftime('%s','now')*1000))");

        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_YARA_EVIDENCE + " (" +
                COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                COL_EVIDENCE_ID + " INTEGER, " +
                COL_RULE_NAME + " TEXT NOT NULL, " +
                COL_RULE_TAGS + " TEXT, " +
                COL_MATCHED_FILE + " TEXT, " +
                COL_MATCHED_STRINGS + " TEXT, " +
                COL_TIMESTAMP + " INTEGER NOT NULL DEFAULT (strftime('%s','now')*1000))");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        // Future migrations go here
    }

    // ─── Write operations ────────────────────────────────────────────────────

    public long insertEvidence(String type, String title, String description,
                                int riskScore, String verdict, String packageName,
                                String iocValue, String iocType, String source) {
        // Suppress only packages verified as installed system components. Namespace alone is forgeable.
        if (packageName != null && Utils.isSystemApp(mContext, packageName)) {
            return -1;
        }
        if (iocValue != null && SecurityBlocklistManager.isOfficialDomain(iocValue)) {
            return -1;
        }

        ContentValues cv = new ContentValues();
        cv.put(COL_TYPE, type);
        cv.put(COL_TITLE, title);
        cv.put(COL_DESCRIPTION, description);
        cv.put(COL_RISK_SCORE, riskScore);
        cv.put(COL_VERDICT, verdict);
        cv.put(COL_PACKAGE_NAME, packageName);
        cv.put(COL_IOC_VALUE, iocValue);
        cv.put(COL_IOC_TYPE, iocType);
        cv.put(COL_SOURCE, source);
        cv.put(COL_TIMESTAMP, System.currentTimeMillis());
        try {
            return getWritableDatabase().insertOrThrow(TABLE_EVIDENCE, null, cv);
        } catch (Exception e) {
            Log.e(TAG, "insertEvidence error: " + e.getMessage());
            return -1;
        }
    }

    public void insertTiEvidence(long evidenceId, String provider, String iocValue,
                                  String iocType, String resultJson, float confidence,
                                  String malwareFamily, String verdict) {
        ContentValues cv = new ContentValues();
        cv.put(COL_EVIDENCE_ID, evidenceId);
        cv.put(COL_PROVIDER, provider);
        cv.put(COL_IOC_VALUE, iocValue);
        cv.put(COL_IOC_TYPE, iocType);
        cv.put(COL_RESULT_JSON, resultJson);
        cv.put(COL_CONFIDENCE, confidence);
        cv.put(COL_MALWARE_FAMILY, malwareFamily);
        cv.put(COL_VERDICT, verdict);
        cv.put(COL_FETCHED_AT, System.currentTimeMillis());
        try {
            getWritableDatabase().insertOrThrow(TABLE_TI_EVIDENCE, null, cv);
        } catch (Exception e) {
            Log.e(TAG, "insertTiEvidence error: " + e.getMessage());
        }
    }

    public void insertYaraEvidence(long evidenceId, String ruleName, String tags,
                                    String matchedFile, String matchedStringsJson) {
        ContentValues cv = new ContentValues();
        cv.put(COL_EVIDENCE_ID, evidenceId);
        cv.put(COL_RULE_NAME, ruleName);
        cv.put(COL_RULE_TAGS, tags);
        cv.put(COL_MATCHED_FILE, matchedFile);
        cv.put(COL_MATCHED_STRINGS, matchedStringsJson);
        cv.put(COL_TIMESTAMP, System.currentTimeMillis());
        try {
            getWritableDatabase().insertOrThrow(TABLE_YARA_EVIDENCE, null, cv);
        } catch (Exception e) {
            Log.e(TAG, "insertYaraEvidence error: " + e.getMessage());
        }
    }

    // ─── Query operations ────────────────────────────────────────────────────

    public List<EvidenceRecord> getRecentEvidence(int limit) {
        List<EvidenceRecord> records = new ArrayList<>();
        String sql = "SELECT * FROM " + TABLE_EVIDENCE +
                " ORDER BY " + COL_TIMESTAMP + " DESC LIMIT " + limit;
        try (Cursor c = getReadableDatabase().rawQuery(sql, null)) {
            while (c.moveToNext()) {
                records.add(cursorToRecord(c));
            }
        } catch (Exception e) {
            Log.e(TAG, "getRecentEvidence error: " + e.getMessage());
        }
        return records;
    }

    public List<EvidenceRecord> getEvidenceByVerdict(String verdict, int limit) {
        List<EvidenceRecord> records = new ArrayList<>();
        try (Cursor c = getReadableDatabase().query(TABLE_EVIDENCE, null,
                COL_VERDICT + "=?", new String[]{verdict}, null, null,
                COL_TIMESTAMP + " DESC", String.valueOf(limit))) {
            while (c.moveToNext()) {
                records.add(cursorToRecord(c));
            }
        } catch (Exception e) {
            Log.e(TAG, "getEvidenceByVerdict error: " + e.getMessage());
        }
        return records;
    }

    private EvidenceRecord cursorToRecord(Cursor c) {
        EvidenceRecord r = new EvidenceRecord();
        r.id = c.getLong(c.getColumnIndexOrThrow(COL_ID));
        r.type = c.getString(c.getColumnIndexOrThrow(COL_TYPE));
        r.title = c.getString(c.getColumnIndexOrThrow(COL_TITLE));
        r.description = c.getString(c.getColumnIndexOrThrow(COL_DESCRIPTION));
        r.riskScore = c.getInt(c.getColumnIndexOrThrow(COL_RISK_SCORE));
        r.verdict = c.getString(c.getColumnIndexOrThrow(COL_VERDICT));
        r.packageName = c.getString(c.getColumnIndexOrThrow(COL_PACKAGE_NAME));
        r.iocValue = c.getString(c.getColumnIndexOrThrow(COL_IOC_VALUE));
        r.iocType = c.getString(c.getColumnIndexOrThrow(COL_IOC_TYPE));
        r.source = c.getString(c.getColumnIndexOrThrow(COL_SOURCE));
        r.timestamp = c.getLong(c.getColumnIndexOrThrow(COL_TIMESTAMP));
        r.mitreTechniques = c.getString(c.getColumnIndexOrThrow(COL_MITRE_TECHNIQUES));
        return r;
    }

    /** Clears ALL evidence. Called only by explicit user action. */
    public int clearAll() {
        try {
            SQLiteDatabase db = getWritableDatabase();
            int total = 0;
            total += db.delete(TABLE_YARA_EVIDENCE, null, null);
            total += db.delete(TABLE_TI_EVIDENCE, null, null);
            total += db.delete(TABLE_EVIDENCE, null, null);
            db.execSQL("VACUUM");
            Log.i(TAG, "Cleared " + total + " evidence rows");
            return total;
        } catch (Exception e) {
            Log.e(TAG, "clearAll error: " + e.getMessage());
            return 0;
        }
    }

    /** Purges evidence records older than cutoff timestamp. Called by RetentionWorker. */
    public int purgeOlderThan(long cutoffMillis) {
        try {
            SQLiteDatabase db = getWritableDatabase();
            int total = 0;
            total += db.delete(TABLE_YARA_EVIDENCE, COL_TIMESTAMP + " < ?", new String[]{String.valueOf(cutoffMillis)});
            total += db.delete(TABLE_TI_EVIDENCE, COL_FETCHED_AT + " < ?", new String[]{String.valueOf(cutoffMillis)});
            total += db.delete(TABLE_EVIDENCE, COL_TIMESTAMP + " < ?", new String[]{String.valueOf(cutoffMillis)});
            db.execSQL("VACUUM");
            Log.i(TAG, "Purged " + total + " evidence rows older than " + cutoffMillis);
            return total;
        } catch (Exception e) {
            Log.e(TAG, "purgeOlderThan error: " + e.getMessage());
            return 0;
        }
    }

    /** Returns count of main evidence records. */
    public int getEvidenceCount() {
        try (Cursor c = getReadableDatabase().rawQuery("SELECT COUNT(*) FROM " + TABLE_EVIDENCE, null)) {
            if (c.moveToFirst()) return c.getInt(0);
        } catch (Exception e) {
            Log.e(TAG, "getEvidenceCount: " + e.getMessage());
        }
        return 0;
    }

    // ─── Evidence Record POJO ─────────────────────────────────────────────────

    public static class EvidenceRecord {
        public long id;
        public String type;
        public String title;
        public String description;
        public int riskScore;
        public String verdict;
        public String packageName;
        public String iocValue;
        public String iocType;
        public String source;
        public String mitreTechniques;
        public long timestamp;
    }
}
