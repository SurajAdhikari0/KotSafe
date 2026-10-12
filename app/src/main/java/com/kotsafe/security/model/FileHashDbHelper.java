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

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import java.util.ArrayList;
import java.util.List;

public class FileHashDbHelper extends SQLiteOpenHelper {
    private static final String DATABASE_NAME = "file_hashes.db";
    private static final int DATABASE_VERSION = 3;

    public static final String TABLE_FILE_HASHES = "file_hashes";
    public static final String TABLE_FEATURE_VECTOR_STORE = "feature_vector_store";
    public static final String TABLE_VT_LOOKUP_QUEUE = "vt_lookup_queue";

    public static final String COL_ID = "id";
    public static final String COL_FILE_NAME = "file_name";
    public static final String COL_FILE_PATH = "file_path";
    public static final String COL_PACKAGE_NAME = "package_name";
    public static final String COL_APP_NAME = "app_name";
    public static final String COL_SHA256 = "sha256";
    public static final String COL_MD5 = "md5";
    public static final String COL_FILE_SIZE = "file_size";
    public static final String COL_IS_SERVICE = "is_service";
    public static final String COL_IS_SYSTEM = "is_system";
    public static final String COL_SCAN_TIMESTAMP = "scan_timestamp";
    public static final String COL_THREAT_STATUS = "threat_status";
    public static final String COL_THREAT_DETAILS = "threat_details";
    // v2 — smart scan metadata
    public static final String COL_FILE_LAST_MODIFIED = "file_last_modified"; // mtime ms
    public static final String COL_SCAN_TYPE = "scan_type";     // APP | STORAGE | DOWNLOAD
    public static final String COL_SHA1 = "sha1";
    public static final String COL_MIME_TYPE = "mime_type";
    public static final String COL_FILE_CLASS = "file_class";   // APK|DEX|SO|SCRIPT|ARCHIVE|MEDIA|DOCUMENT|UNKNOWN
    public static final String COL_SCAN_PRIORITY = "scan_priority"; // 0=highest
    public static final String COL_SCAN_STATUS = "scan_status";    // PENDING|DONE|SKIPPED

    // v3 — tiered scanning, confidence scores, and cloud reputation seams
    public static final String COL_SCAN_TIER = "scan_tier";                 // QUICK | FULL | DEEP
    public static final String COL_CONFIDENCE_SCORE = "confidence_score";   // 0-100 heuristic or blended
    public static final String COL_SIGNATURE_DB_VERSION = "signature_db_version"; // 0 = pre-migration, forces re-eval
    public static final String COL_MODEL_VERSION = "model_version";
    public static final String COL_CLOUD_CORRELATION_ID = "cloud_correlation_id"; // VT analysis ID or OTX pulse
    public static final String COL_CTIME = "ctime";                         // Inode metadata change time

    // feature_vector_store columns
    public static final String COL_FV_CONTENT_HASH = "content_hash";
    public static final String COL_FV_PERMISSION_BITMAP = "permission_bitmap";
    public static final String COL_FV_API_CALL_GRAPH_HASH = "api_call_graph_hash";
    public static final String COL_FV_REFLECTION_DENSITY = "reflection_density";
    public static final String COL_FV_STRING_ENTROPY = "string_entropy";
    public static final String COL_FV_NATIVE_LIB_COUNT = "native_lib_count";
    public static final String COL_FV_ASSET_TO_CODE_RATIO = "asset_to_code_ratio";
    public static final String COL_FV_EXTRACTED_AT = "extracted_at";

    // vt_lookup_queue columns
    public static final String COL_VT_CONTENT_HASH = "content_hash";
    public static final String COL_VT_FILE_PATH = "file_path";
    public static final String COL_VT_ENQUEUED_AT = "enqueued_at";
    public static final String COL_VT_STATUS = "status";

    private static FileHashDbHelper sInstance;

    public static synchronized FileHashDbHelper getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new FileHashDbHelper(context.getApplicationContext());
        }
        return sInstance;
    }

    private FileHashDbHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
        setWriteAheadLoggingEnabled(true);
    }

    @Override
    public void onConfigure(SQLiteDatabase db) {
        super.onConfigure(db);
        try {
            db.enableWriteAheadLogging();
            db.execSQL("PRAGMA busy_timeout = 5000;");
        } catch (Exception ignored) {}
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        String sql = "CREATE TABLE " + TABLE_FILE_HASHES + " (" +
                COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                COL_FILE_NAME + " TEXT, " +
                COL_FILE_PATH + " TEXT UNIQUE, " +
                COL_PACKAGE_NAME + " TEXT, " +
                COL_APP_NAME + " TEXT, " +
                COL_SHA256 + " TEXT, " +
                COL_MD5 + " TEXT, " +
                COL_SHA1 + " TEXT, " +
                COL_FILE_SIZE + " INTEGER, " +
                COL_IS_SERVICE + " INTEGER DEFAULT 0, " +
                COL_IS_SYSTEM + " INTEGER DEFAULT 0, " +
                COL_SCAN_TIMESTAMP + " INTEGER, " +
                COL_THREAT_STATUS + " TEXT, " +
                COL_THREAT_DETAILS + " TEXT, " +
                COL_FILE_LAST_MODIFIED + " INTEGER DEFAULT 0, " +
                COL_SCAN_TYPE + " TEXT DEFAULT 'APP', " +
                COL_MIME_TYPE + " TEXT, " +
                COL_FILE_CLASS + " TEXT DEFAULT 'UNKNOWN', " +
                COL_SCAN_PRIORITY + " INTEGER DEFAULT 2, " +
                COL_SCAN_STATUS + " TEXT DEFAULT 'PENDING', " +
                COL_SCAN_TIER + " TEXT DEFAULT 'QUICK', " +
                COL_CONFIDENCE_SCORE + " INTEGER DEFAULT 0, " +
                COL_SIGNATURE_DB_VERSION + " INTEGER DEFAULT 0, " +
                COL_MODEL_VERSION + " INTEGER DEFAULT 0, " +
                COL_CLOUD_CORRELATION_ID + " TEXT DEFAULT NULL, " +
                COL_CTIME + " INTEGER DEFAULT 0" +
                ")";
        db.execSQL(sql);
        db.execSQL("CREATE INDEX idx_file_pkg ON " + TABLE_FILE_HASHES + " (" + COL_PACKAGE_NAME + ")");
        db.execSQL("CREATE INDEX idx_file_sha ON " + TABLE_FILE_HASHES + " (" + COL_SHA256 + ")");
        db.execSQL("CREATE INDEX idx_file_time ON " + TABLE_FILE_HASHES + " (" + COL_SCAN_TIMESTAMP + ")");
        db.execSQL("CREATE INDEX idx_file_service ON " + TABLE_FILE_HASHES + " (" + COL_IS_SERVICE + ")");
        db.execSQL("CREATE INDEX idx_file_modified ON " + TABLE_FILE_HASHES + " (" + COL_FILE_LAST_MODIFIED + ")");
        db.execSQL("CREATE INDEX idx_file_class ON " + TABLE_FILE_HASHES + " (" + COL_FILE_CLASS + ")");
        db.execSQL("CREATE INDEX idx_file_sigver ON " + TABLE_FILE_HASHES + " (" + COL_SIGNATURE_DB_VERSION + ")");

        // Feature vector store for deep scan and bytecode metrics
        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_FEATURE_VECTOR_STORE + " (" +
                COL_FV_CONTENT_HASH + " TEXT PRIMARY KEY, " +
                COL_FV_PERMISSION_BITMAP + " BLOB, " +
                COL_FV_API_CALL_GRAPH_HASH + " TEXT, " +
                COL_FV_REFLECTION_DENSITY + " REAL, " +
                COL_FV_STRING_ENTROPY + " REAL, " +
                COL_FV_NATIVE_LIB_COUNT + " INTEGER, " +
                COL_FV_ASSET_TO_CODE_RATIO + " REAL, " +
                COL_FV_EXTRACTED_AT + " INTEGER" +
                ")");

        // Persistent rate-limited VirusTotal lookup queue
        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_VT_LOOKUP_QUEUE + " (" +
                COL_VT_CONTENT_HASH + " TEXT PRIMARY KEY, " +
                COL_VT_FILE_PATH + " TEXT, " +
                COL_VT_ENQUEUED_AT + " INTEGER, " +
                COL_VT_STATUS + " TEXT DEFAULT 'PENDING'" +
                ")");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        if (oldVersion < 2) {
            try { db.execSQL("ALTER TABLE " + TABLE_FILE_HASHES + " ADD COLUMN " + COL_SHA1 + " TEXT"); } catch (Exception ignored) {}
            try { db.execSQL("ALTER TABLE " + TABLE_FILE_HASHES + " ADD COLUMN " + COL_FILE_LAST_MODIFIED + " INTEGER DEFAULT 0"); } catch (Exception ignored) {}
            try { db.execSQL("ALTER TABLE " + TABLE_FILE_HASHES + " ADD COLUMN " + COL_SCAN_TYPE + " TEXT DEFAULT 'APP'"); } catch (Exception ignored) {}
            try { db.execSQL("ALTER TABLE " + TABLE_FILE_HASHES + " ADD COLUMN " + COL_MIME_TYPE + " TEXT"); } catch (Exception ignored) {}
            try { db.execSQL("ALTER TABLE " + TABLE_FILE_HASHES + " ADD COLUMN " + COL_FILE_CLASS + " TEXT DEFAULT 'UNKNOWN'"); } catch (Exception ignored) {}
            try { db.execSQL("ALTER TABLE " + TABLE_FILE_HASHES + " ADD COLUMN " + COL_SCAN_PRIORITY + " INTEGER DEFAULT 2"); } catch (Exception ignored) {}
            try { db.execSQL("ALTER TABLE " + TABLE_FILE_HASHES + " ADD COLUMN " + COL_SCAN_STATUS + " TEXT DEFAULT 'PENDING'"); } catch (Exception ignored) {}
            try { db.execSQL("CREATE INDEX IF NOT EXISTS idx_file_modified ON " + TABLE_FILE_HASHES + " (" + COL_FILE_LAST_MODIFIED + ")"); } catch (Exception ignored) {}
            try { db.execSQL("CREATE INDEX IF NOT EXISTS idx_file_class ON " + TABLE_FILE_HASHES + " (" + COL_FILE_CLASS + ")"); } catch (Exception ignored) {}
        }
        if (oldVersion < 3) {
            // v3 migration with safe defaults (Plan v2 §2)
            try { db.execSQL("ALTER TABLE " + TABLE_FILE_HASHES + " ADD COLUMN " + COL_SCAN_TIER + " TEXT DEFAULT 'QUICK'"); } catch (Exception ignored) {}
            try { db.execSQL("ALTER TABLE " + TABLE_FILE_HASHES + " ADD COLUMN " + COL_CONFIDENCE_SCORE + " INTEGER DEFAULT 0"); } catch (Exception ignored) {}
            try { db.execSQL("ALTER TABLE " + TABLE_FILE_HASHES + " ADD COLUMN " + COL_SIGNATURE_DB_VERSION + " INTEGER DEFAULT 0"); } catch (Exception ignored) {}
            try { db.execSQL("ALTER TABLE " + TABLE_FILE_HASHES + " ADD COLUMN " + COL_MODEL_VERSION + " INTEGER DEFAULT 0"); } catch (Exception ignored) {}
            try { db.execSQL("ALTER TABLE " + TABLE_FILE_HASHES + " ADD COLUMN " + COL_CLOUD_CORRELATION_ID + " TEXT DEFAULT NULL"); } catch (Exception ignored) {}
            try { db.execSQL("ALTER TABLE " + TABLE_FILE_HASHES + " ADD COLUMN " + COL_CTIME + " INTEGER DEFAULT 0"); } catch (Exception ignored) {}
            try { db.execSQL("CREATE INDEX IF NOT EXISTS idx_file_sigver ON " + TABLE_FILE_HASHES + " (" + COL_SIGNATURE_DB_VERSION + ")"); } catch (Exception ignored) {}

            try {
                db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_FEATURE_VECTOR_STORE + " (" +
                        COL_FV_CONTENT_HASH + " TEXT PRIMARY KEY, " +
                        COL_FV_PERMISSION_BITMAP + " BLOB, " +
                        COL_FV_API_CALL_GRAPH_HASH + " TEXT, " +
                        COL_FV_REFLECTION_DENSITY + " REAL, " +
                        COL_FV_STRING_ENTROPY + " REAL, " +
                        COL_FV_NATIVE_LIB_COUNT + " INTEGER, " +
                        COL_FV_ASSET_TO_CODE_RATIO + " REAL, " +
                        COL_FV_EXTRACTED_AT + " INTEGER" +
                        ")");
            } catch (Exception ignored) {}

            try {
                db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_VT_LOOKUP_QUEUE + " (" +
                        COL_VT_CONTENT_HASH + " TEXT PRIMARY KEY, " +
                        COL_VT_FILE_PATH + " TEXT, " +
                        COL_VT_ENQUEUED_AT + " INTEGER, " +
                        COL_VT_STATUS + " TEXT DEFAULT 'PENDING'" +
                        ")");
            } catch (Exception ignored) {}
        }
    }

    // Batched transaction management (Plan v2 §6)
    public synchronized void beginBatchTransaction() {
        try {
            getWritableDatabase().beginTransactionNonExclusive();
        } catch (Exception e) {
            try {
                getWritableDatabase().beginTransaction();
            } catch (Exception ignored) {}
        }
    }

    public synchronized void setBatchTransactionSuccessful() {
        try {
            getWritableDatabase().setTransactionSuccessful();
        } catch (Exception ignored) {}
    }

    public synchronized void endBatchTransaction() {
        try {
            getWritableDatabase().endTransaction();
        } catch (Exception ignored) {}
    }

    public synchronized void upsertFileHash(FileHashEntry entry) {
        if (entry == null || entry.filePath == null || entry.filePath.isEmpty()) return;
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = buildContentValues(entry);
        db.insertWithOnConflict(TABLE_FILE_HASHES, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public void upsertFileHashNoCommit(FileHashEntry entry) {
        if (entry == null || entry.filePath == null || entry.filePath.isEmpty()) return;
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = buildContentValues(entry);
        db.insertWithOnConflict(TABLE_FILE_HASHES, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public synchronized void upsertBatch(List<FileHashEntry> entries) {
        if (entries == null || entries.isEmpty()) return;
        SQLiteDatabase db = getWritableDatabase();
        db.beginTransactionNonExclusive();
        try {
            for (FileHashEntry entry : entries) {
                if (entry == null || entry.filePath == null || entry.filePath.isEmpty()) continue;
                ContentValues cv = buildContentValues(entry);
                db.insertWithOnConflict(TABLE_FILE_HASHES, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
            }
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }

    private ContentValues buildContentValues(FileHashEntry entry) {
        ContentValues cv = new ContentValues();
        cv.put(COL_FILE_NAME, entry.fileName);
        cv.put(COL_FILE_PATH, entry.filePath);
        cv.put(COL_PACKAGE_NAME, entry.packageName);
        cv.put(COL_APP_NAME, entry.appName);
        cv.put(COL_SHA256, entry.sha256);
        cv.put(COL_MD5, entry.md5);
        cv.put(COL_SHA1, entry.sha1);
        cv.put(COL_FILE_SIZE, entry.fileSize);
        cv.put(COL_IS_SERVICE, entry.isServiceApp ? 1 : 0);
        cv.put(COL_IS_SYSTEM, entry.isSystemApp ? 1 : 0);
        cv.put(COL_SCAN_TIMESTAMP, entry.scanTimestamp > 0 ? entry.scanTimestamp : System.currentTimeMillis());
        cv.put(COL_THREAT_STATUS, entry.threatStatus);
        cv.put(COL_THREAT_DETAILS, entry.threatDetails);
        cv.put(COL_FILE_LAST_MODIFIED, entry.fileLastModified);
        cv.put(COL_SCAN_TYPE, entry.scanType != null ? entry.scanType : "APP");
        cv.put(COL_MIME_TYPE, entry.mimeType);
        cv.put(COL_FILE_CLASS, entry.fileClass != null ? entry.fileClass : "UNKNOWN");
        cv.put(COL_SCAN_PRIORITY, entry.scanPriority);
        cv.put(COL_SCAN_STATUS, entry.scanStatus != null ? entry.scanStatus : "DONE");
        cv.put(COL_SCAN_TIER, entry.scanTier != null ? entry.scanTier : "QUICK");
        cv.put(COL_CONFIDENCE_SCORE, entry.confidenceScore);
        cv.put(COL_SIGNATURE_DB_VERSION, entry.signatureDbVersion);
        cv.put(COL_MODEL_VERSION, entry.modelVersion);
        cv.put(COL_CLOUD_CORRELATION_ID, entry.cloudCorrelationId);
        cv.put(COL_CTIME, entry.ctime);
        return cv;
    }

    public synchronized List<FileHashEntry> queryHashes(String filterText, String category, int limit, int offset) {
        List<FileHashEntry> list = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();

        StringBuilder where = new StringBuilder();
        List<String> args = new ArrayList<>();

        if (category != null && !category.equalsIgnoreCase("ALL")) {
            if (category.equalsIgnoreCase("SERVICES")) {
                where.append(COL_IS_SERVICE).append(" = 1");
            } else if (category.equalsIgnoreCase("USER")) {
                where.append(COL_IS_SYSTEM).append(" = 0");
            } else if (category.equalsIgnoreCase("SYSTEM")) {
                where.append(COL_IS_SYSTEM).append(" = 1");
            } else if (category.equalsIgnoreCase("THREATS")) {
                where.append(COL_THREAT_STATUS).append(" != 'CLEAN'");
            }
        }

        if (filterText != null && !filterText.trim().isEmpty()) {
            if (where.length() > 0) where.append(" AND ");
            where.append("(")
                    .append(COL_FILE_NAME).append(" LIKE ? OR ")
                    .append(COL_PACKAGE_NAME).append(" LIKE ? OR ")
                    .append(COL_APP_NAME).append(" LIKE ? OR ")
                    .append(COL_SHA256).append(" LIKE ?")
                    .append(")");
            String queryArg = "%" + filterText.trim() + "%";
            args.add(queryArg);
            args.add(queryArg);
            args.add(queryArg);
            args.add(queryArg);
        }

        String selection = where.length() > 0 ? where.toString() : null;
        String[] selectionArgs = args.isEmpty() ? null : args.toArray(new String[0]);
        String limitClause = limit > 0 ? (offset + ", " + limit) : null;

        try (Cursor cursor = db.query(TABLE_FILE_HASHES, null, selection, selectionArgs, null, null,
                COL_SCAN_TIMESTAMP + " DESC", limitClause)) {
            while (cursor != null && cursor.moveToNext()) {
                list.add(fromCursor(cursor));
            }
        }
        return list;
    }

    public synchronized long getCount() {
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor c = db.rawQuery("SELECT COUNT(*) FROM " + TABLE_FILE_HASHES, null)) {
            if (c != null && c.moveToFirst()) return c.getLong(0);
        }
        return 0;
    }

    public synchronized long getServiceCount() {
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor c = db.rawQuery("SELECT COUNT(*) FROM " + TABLE_FILE_HASHES + " WHERE " + COL_IS_SERVICE + " = 1", null)) {
            if (c != null && c.moveToFirst()) return c.getLong(0);
        }
        return 0;
    }

    public synchronized void clearAll() {
        getWritableDatabase().delete(TABLE_FILE_HASHES, null, null);
    }

    public synchronized void deleteOldEntries(long cutoffMillis) {
        getWritableDatabase().delete(TABLE_FILE_HASHES, COL_SCAN_TIMESTAMP + " < ?", new String[]{String.valueOf(cutoffMillis)});
    }

    public synchronized void deleteFileHash(long id) {
        getWritableDatabase().delete(TABLE_FILE_HASHES, COL_ID + " = ?", new String[]{String.valueOf(id)});
    }

    public synchronized void deleteByFilePath(String filePath) {
        if (filePath != null) {
            getWritableDatabase().delete(TABLE_FILE_HASHES, COL_FILE_PATH + " = ?", new String[]{filePath});
        }
    }

    /**
     * Smart scan helper: returns true if the file at path has changed since last scan.
     * Comparison uses file_last_modified timestamp stored in DB.
     * If no entry exists for this path, returns true (needs scanning).
     */
    public synchronized boolean isChangedSinceLastScan(String filePath, long currentLastModified) {
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor c = db.query(TABLE_FILE_HASHES,
                new String[]{COL_FILE_LAST_MODIFIED},
                COL_FILE_PATH + "=?", new String[]{filePath},
                null, null, null)) {
            if (c != null && c.moveToFirst()) {
                long stored = c.getLong(0);
                return stored == 0 || currentLastModified > stored;
            }
        } catch (Exception e) {
            com.kotsafe.security.Log.e("FileHashDbHelper", "isChangedSinceLastScan: " + e.getMessage());
        }
        return true; // no entry → must scan
    }

    public synchronized String getSha256ForPath(String filePath) {
        if (filePath == null) return null;
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor c = db.query(TABLE_FILE_HASHES,
                new String[]{COL_SHA256},
                COL_FILE_PATH + "=?", new String[]{filePath},
                null, null, null)) {
            if (c != null && c.moveToFirst()) {
                return c.getString(0);
            }
        } catch (Exception ignored) {}
        return null;
    }

    public synchronized boolean isMalicious(String hash) {
        if (hash == null || hash.isEmpty()) return false;
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor c = db.query(TABLE_FILE_HASHES,
                new String[]{COL_THREAT_STATUS},
                "(" + COL_SHA256 + "=? OR " + COL_MD5 + "=? OR " + COL_SHA1 + "=?) AND " + COL_THREAT_STATUS + "=?",
                new String[]{hash, hash, hash, "MALICIOUS"},
                null, null, null)) {
            if (c != null && c.moveToFirst()) {
                return true;
            }
        } catch (Exception ignored) {}
        return false;
    }

    public synchronized FileHashEntry getEntryByHash(String hash) {
        if (hash == null || hash.isEmpty()) return null;
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor c = db.query(TABLE_FILE_HASHES,
                null,
                COL_SHA256 + "=? OR " + COL_MD5 + "=? OR " + COL_SHA1 + "=?",
                new String[]{hash, hash, hash},
                null, null, null)) {
            if (c != null && c.moveToFirst()) {
                return fromCursor(c);
            }
        } catch (Exception ignored) {}
        return null;
    }

    private FileHashEntry fromCursor(Cursor c) {
        FileHashEntry entry = new FileHashEntry();
        entry.id = c.getLong(c.getColumnIndexOrThrow(COL_ID));
        entry.fileName = c.getString(c.getColumnIndexOrThrow(COL_FILE_NAME));
        entry.filePath = c.getString(c.getColumnIndexOrThrow(COL_FILE_PATH));
        entry.packageName = c.getString(c.getColumnIndexOrThrow(COL_PACKAGE_NAME));
        entry.appName = c.getString(c.getColumnIndexOrThrow(COL_APP_NAME));
        entry.sha256 = c.getString(c.getColumnIndexOrThrow(COL_SHA256));
        entry.md5 = c.getString(c.getColumnIndexOrThrow(COL_MD5));
        int sha1Idx = c.getColumnIndex(COL_SHA1);
        if (sha1Idx >= 0) entry.sha1 = c.getString(sha1Idx);
        entry.fileSize = c.getLong(c.getColumnIndexOrThrow(COL_FILE_SIZE));
        entry.isServiceApp = c.getInt(c.getColumnIndexOrThrow(COL_IS_SERVICE)) == 1;
        entry.isSystemApp = c.getInt(c.getColumnIndexOrThrow(COL_IS_SYSTEM)) == 1;
        entry.scanTimestamp = c.getLong(c.getColumnIndexOrThrow(COL_SCAN_TIMESTAMP));
        entry.threatStatus = c.getString(c.getColumnIndexOrThrow(COL_THREAT_STATUS));
        entry.threatDetails = c.getString(c.getColumnIndexOrThrow(COL_THREAT_DETAILS));
        int lmIdx = c.getColumnIndex(COL_FILE_LAST_MODIFIED);
        if (lmIdx >= 0) entry.fileLastModified = c.getLong(lmIdx);
        int stIdx = c.getColumnIndex(COL_SCAN_TYPE);
        if (stIdx >= 0) entry.scanType = c.getString(stIdx);
        int mtIdx = c.getColumnIndex(COL_MIME_TYPE);
        if (mtIdx >= 0) entry.mimeType = c.getString(mtIdx);
        int fcIdx = c.getColumnIndex(COL_FILE_CLASS);
        if (fcIdx >= 0) entry.fileClass = c.getString(fcIdx);
        int spIdx = c.getColumnIndex(COL_SCAN_PRIORITY);
        if (spIdx >= 0) entry.scanPriority = c.getInt(spIdx);
        int ssIdx = c.getColumnIndex(COL_SCAN_STATUS);
        if (ssIdx >= 0) entry.scanStatus = c.getString(ssIdx);

        // v3 fields
        int tierIdx = c.getColumnIndex(COL_SCAN_TIER);
        if (tierIdx >= 0) entry.scanTier = c.getString(tierIdx);
        int confIdx = c.getColumnIndex(COL_CONFIDENCE_SCORE);
        if (confIdx >= 0) entry.confidenceScore = c.getInt(confIdx);
        int sigIdx = c.getColumnIndex(COL_SIGNATURE_DB_VERSION);
        if (sigIdx >= 0) entry.signatureDbVersion = c.getInt(sigIdx);
        int modIdx = c.getColumnIndex(COL_MODEL_VERSION);
        if (modIdx >= 0) entry.modelVersion = c.getInt(modIdx);
        int cloudIdx = c.getColumnIndex(COL_CLOUD_CORRELATION_ID);
        if (cloudIdx >= 0) entry.cloudCorrelationId = c.getString(cloudIdx);
        int ctIdx = c.getColumnIndex(COL_CTIME);
        if (ctIdx >= 0) entry.ctime = c.getLong(ctIdx);

        return entry;
    }

    /**
     * FeatureVectorStore operations (Plan v2 §2.3, §4.3)
     */
    public synchronized void upsertFeatureVector(FeatureVector fv) {
        if (fv == null || fv.contentHash == null || fv.contentHash.isEmpty()) return;
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put(COL_FV_CONTENT_HASH, fv.contentHash);
        cv.put(COL_FV_PERMISSION_BITMAP, fv.permissionBitmap);
        cv.put(COL_FV_API_CALL_GRAPH_HASH, fv.apiCallGraphHash);
        cv.put(COL_FV_REFLECTION_DENSITY, fv.reflectionDensity);
        cv.put(COL_FV_STRING_ENTROPY, fv.stringEntropy);
        cv.put(COL_FV_NATIVE_LIB_COUNT, fv.nativeLibCount);
        cv.put(COL_FV_ASSET_TO_CODE_RATIO, fv.assetToCodeRatio);
        cv.put(COL_FV_EXTRACTED_AT, fv.extractedAt > 0 ? fv.extractedAt : System.currentTimeMillis());
        db.insertWithOnConflict(TABLE_FEATURE_VECTOR_STORE, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public synchronized FeatureVector getFeatureVector(String contentHash) {
        if (contentHash == null || contentHash.isEmpty()) return null;
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor c = db.query(TABLE_FEATURE_VECTOR_STORE, null,
                COL_FV_CONTENT_HASH + "=?", new String[]{contentHash},
                null, null, null)) {
            if (c != null && c.moveToFirst()) {
                FeatureVector fv = new FeatureVector();
                fv.contentHash = c.getString(c.getColumnIndexOrThrow(COL_FV_CONTENT_HASH));
                fv.permissionBitmap = c.getBlob(c.getColumnIndexOrThrow(COL_FV_PERMISSION_BITMAP));
                fv.apiCallGraphHash = c.getString(c.getColumnIndexOrThrow(COL_FV_API_CALL_GRAPH_HASH));
                fv.reflectionDensity = c.getFloat(c.getColumnIndexOrThrow(COL_FV_REFLECTION_DENSITY));
                fv.stringEntropy = c.getFloat(c.getColumnIndexOrThrow(COL_FV_STRING_ENTROPY));
                fv.nativeLibCount = c.getInt(c.getColumnIndexOrThrow(COL_FV_NATIVE_LIB_COUNT));
                fv.assetToCodeRatio = c.getFloat(c.getColumnIndexOrThrow(COL_FV_ASSET_TO_CODE_RATIO));
                fv.extractedAt = c.getLong(c.getColumnIndexOrThrow(COL_FV_EXTRACTED_AT));
                return fv;
            }
        } catch (Exception e) {
            com.kotsafe.security.Log.e("FileHashDbHelper", "getFeatureVector: " + e.getMessage());
        }
        return null;
    }

    /**
     * VirusTotal rate-limited persistent queue (Plan v2 §8.2)
     */
    public synchronized void enqueueVtLookup(String contentHash, String filePath) {
        if (contentHash == null || contentHash.isEmpty()) return;
        try {
            SQLiteDatabase db = getWritableDatabase();
            ContentValues cv = new ContentValues();
            cv.put(COL_VT_CONTENT_HASH, contentHash);
            cv.put(COL_VT_FILE_PATH, filePath != null ? filePath : "");
            cv.put(COL_VT_ENQUEUED_AT, System.currentTimeMillis());
            cv.put(COL_VT_STATUS, "PENDING");
            db.insertWithOnConflict(TABLE_VT_LOOKUP_QUEUE, null, cv, SQLiteDatabase.CONFLICT_IGNORE);
        } catch (Exception ignored) {}
    }

    public synchronized List<String> getPendingVtLookups(int limit) {
        List<String> list = new ArrayList<>();
        try {
            SQLiteDatabase db = getReadableDatabase();
            try (Cursor c = db.query(TABLE_VT_LOOKUP_QUEUE, new String[]{COL_VT_CONTENT_HASH},
                    COL_VT_STATUS + "='PENDING'", null,
                    null, null, COL_VT_ENQUEUED_AT + " ASC", String.valueOf(limit))) {
                while (c != null && c.moveToNext()) {
                    list.add(c.getString(0));
                }
            }
        } catch (Exception ignored) {}
        return list;
    }

    public synchronized void updateVtLookupStatus(String contentHash, String status) {
        if (contentHash == null) return;
        try {
            SQLiteDatabase db = getWritableDatabase();
            ContentValues cv = new ContentValues();
            cv.put(COL_VT_STATUS, status);
            db.update(TABLE_VT_LOOKUP_QUEUE, cv, COL_VT_CONTENT_HASH + "=?", new String[]{contentHash});
        } catch (Exception ignored) {}
    }

    public synchronized void updateThreatStatusByHash(String sha256, String threatStatus, String threatDetails, String cloudCorrelationId) {
        if (sha256 == null || sha256.isEmpty()) return;
        try {
            SQLiteDatabase db = getWritableDatabase();
            ContentValues cv = new ContentValues();
            cv.put(COL_THREAT_STATUS, threatStatus);
            if (threatDetails != null) cv.put(COL_THREAT_DETAILS, threatDetails);
            if (cloudCorrelationId != null) cv.put(COL_CLOUD_CORRELATION_ID, cloudCorrelationId);
            db.update(TABLE_FILE_HASHES, cv, COL_SHA256 + "=?", new String[]{sha256});
        } catch (Exception ignored) {}
    }

    /**
     * ctime helper using OS-level inode stat (Plan v2 §3)
     */
    public static long getFileCtime(String filePath) {
        if (filePath == null) return 0;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
            try {
                android.system.StructStat stat = android.system.Os.stat(filePath);
                return stat.st_ctime;
            } catch (Exception ignored) {}
        }
        return 0;
    }

    /**
     * Strict decision pipeline trust check (Plan v2 §3):
     * Requires size, mtime, ctime, signatureDbVersion >= currentDbVersion, and modelVersion >= currentModelVersion.
     */
    public synchronized boolean isUnchangedTrustCache(String filePath, long size, long mtime, long ctime, int currentDbVersion, int currentModelVersion) {
        if (filePath == null) return false;
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor c = db.query(TABLE_FILE_HASHES,
                new String[]{COL_FILE_SIZE, COL_FILE_LAST_MODIFIED, COL_CTIME, COL_SIGNATURE_DB_VERSION, COL_MODEL_VERSION},
                COL_FILE_PATH + "=?", new String[]{filePath},
                null, null, null)) {
            if (c != null && c.moveToFirst()) {
                long storedSize = c.getLong(0);
                long storedMtime = c.getLong(1);
                long storedCtime = c.getLong(2);
                int storedDbVer = c.getInt(3);
                int storedModelVer = c.getInt(4);

                // Pre-migration rows (storedDbVer == 0) or older signature DB fail trust check -> force re-evaluation
                if (storedDbVer == 0 || storedDbVer < currentDbVersion) return false;
                if (storedModelVer < currentModelVersion) return false;
                if (storedSize != size) return false;
                if (storedMtime != mtime) return false;
                if (storedCtime != 0 && ctime != 0 && storedCtime != ctime) return false;

                return true; // Trusted unchanged cache hit
            }
        } catch (Exception e) {
            com.kotsafe.security.Log.e("FileHashDbHelper", "isUnchangedTrustCache: " + e.getMessage());
        }
        return false;
    }

    /** Returns all hash entries for a given package name. Used by correlation engine. */
    public List<FileHashEntry> queryHashesByPackage(String packageName) {
        List<FileHashEntry> list = new ArrayList<>();
        if (packageName == null) return list;
        try (android.database.sqlite.SQLiteDatabase db = getReadableDatabase();
             android.database.Cursor c = db.query(TABLE_FILE_HASHES, null,
                     COL_PACKAGE_NAME + "=?", new String[]{packageName},
                     null, null, COL_SCAN_TIMESTAMP + " DESC")) {
            while (c.moveToNext()) list.add(fromCursor(c));
        } catch (Exception e) {
            com.kotsafe.security.Log.e("FileHashDbHelper", "queryHashesByPackage: " + e.getMessage());
        }
        return list;
    }

    /** Returns true if the given sha256 hash belongs to a system app. */
    public synchronized boolean isSystemAppHash(String sha256) {
        if (sha256 == null || sha256.isEmpty()) return false;
        try (android.database.sqlite.SQLiteDatabase db = getReadableDatabase();
             android.database.Cursor c = db.rawQuery(
                     "SELECT " + COL_ID + " FROM " + TABLE_FILE_HASHES +
                     " WHERE " + COL_SHA256 + " = ? AND " + COL_IS_SYSTEM + " = 1 LIMIT 1",
                     new String[]{sha256})) {
            return c != null && c.moveToFirst();
        } catch (Exception e) {
            return false;
        }
    }
}
