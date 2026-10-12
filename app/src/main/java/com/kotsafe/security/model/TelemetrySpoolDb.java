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
 * Offline SQLite buffer for enterprise SIEM telemetry events.
 * Bounded to MAX_RECORDS (5,000) using FIFO pruning to protect device flash storage.
 */
public class TelemetrySpoolDb extends SQLiteOpenHelper {

    private static final String TAG = "TelemetrySpoolDb";
    private static final String DB_NAME = "telemetry_spool.db";
    private static final int DB_VERSION = 1;

    private static final String TABLE_NAME = "telemetry_spool";
    private static final String COL_ID = "_id";
    private static final String COL_EVENT_ID = "event_id";
    private static final String COL_TIMESTAMP = "timestamp_ms";
    private static final String COL_EVENT_TYPE = "event_type";
    private static final String COL_SEVERITY = "severity";
    private static final String COL_PAYLOAD = "payload_json";
    private static final String COL_ATTEMPTS = "attempts";
    private static final String COL_CREATED_AT = "created_at";

    private static final int MAX_RECORDS = 5000;
    private static final int PRUNE_CHUNK = 500;

    private static volatile TelemetrySpoolDb sInstance;

    public static TelemetrySpoolDb getInstance(Context context) {
        if (sInstance == null) {
            synchronized (TelemetrySpoolDb.class) {
                if (sInstance == null) {
                    sInstance = new TelemetrySpoolDb(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    public static class SpooledEvent {
        public final long dbId;
        public final String eventId;
        public final long timestampMs;
        public final String eventType;
        public final String severity;
        public final String payloadJson;
        public final int attempts;

        public SpooledEvent(long dbId, String eventId, long timestampMs, String eventType,
                            String severity, String payloadJson, int attempts) {
            this.dbId = dbId;
            this.eventId = eventId;
            this.timestampMs = timestampMs;
            this.eventType = eventType;
            this.severity = severity;
            this.payloadJson = payloadJson;
            this.attempts = attempts;
        }
    }

    private TelemetrySpoolDb(Context context) {
        super(context, DB_NAME, null, DB_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_NAME + " ("
                + COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
                + COL_EVENT_ID + " TEXT UNIQUE, "
                + COL_TIMESTAMP + " INTEGER, "
                + COL_EVENT_TYPE + " TEXT, "
                + COL_SEVERITY + " TEXT, "
                + COL_PAYLOAD + " TEXT, "
                + COL_ATTEMPTS + " INTEGER DEFAULT 0, "
                + COL_CREATED_AT + " INTEGER"
                + ")");
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_spool_created ON " + TABLE_NAME + " (" + COL_CREATED_AT + ")");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_NAME);
        onCreate(db);
    }

    public synchronized void enqueue(String eventId, long timestampMs, String eventType,
                                    String severity, String payloadJson) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put(COL_EVENT_ID, eventId);
        cv.put(COL_TIMESTAMP, timestampMs);
        cv.put(COL_EVENT_TYPE, eventType);
        cv.put(COL_SEVERITY, severity);
        cv.put(COL_PAYLOAD, payloadJson);
        cv.put(COL_ATTEMPTS, 0);
        cv.put(COL_CREATED_AT, System.currentTimeMillis());

        db.insertWithOnConflict(TABLE_NAME, null, cv, SQLiteDatabase.CONFLICT_IGNORE);
        pruneIfExceeded(db);
    }

    private void pruneIfExceeded(SQLiteDatabase db) {
        try {
            long count = getPendingCount();
            if (count > MAX_RECORDS) {
                db.execSQL("DELETE FROM " + TABLE_NAME + " WHERE " + COL_ID + " IN ("
                        + "SELECT " + COL_ID + " FROM " + TABLE_NAME
                        + " ORDER BY " + COL_ID + " ASC LIMIT " + PRUNE_CHUNK + ")");
                Log.i(TAG, "Pruned " + PRUNE_CHUNK + " oldest telemetry events from spool (size was " + count + ")");
            }
        } catch (Exception e) {
            Log.w(TAG, "Error pruning telemetry spool: " + e.getMessage());
        }
    }

    public synchronized List<SpooledEvent> pollBatch(int batchSize) {
        List<SpooledEvent> batch = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor c = db.query(TABLE_NAME,
                new String[]{COL_ID, COL_EVENT_ID, COL_TIMESTAMP, COL_EVENT_TYPE, COL_SEVERITY, COL_PAYLOAD, COL_ATTEMPTS},
                COL_ATTEMPTS + " < ?", new String[]{"5"},
                null, null, COL_ID + " ASC", String.valueOf(batchSize))) {
            while (c != null && c.moveToNext()) {
                batch.add(new SpooledEvent(
                        c.getLong(0),
                        c.getString(1),
                        c.getLong(2),
                        c.getString(3),
                        c.getString(4),
                        c.getString(5),
                        c.getInt(6)
                ));
            }
        } catch (Exception e) {
            Log.w(TAG, "Error polling telemetry batch: " + e.getMessage());
        }
        return batch;
    }

    public synchronized void markDelivered(List<Long> ids) {
        if (ids == null || ids.isEmpty()) return;
        SQLiteDatabase db = getWritableDatabase();
        db.beginTransaction();
        try {
            for (Long id : ids) {
                db.delete(TABLE_NAME, COL_ID + " = ?", new String[]{String.valueOf(id)});
            }
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }

    public synchronized void recordAttemptFailure(List<Long> ids) {
        if (ids == null || ids.isEmpty()) return;
        SQLiteDatabase db = getWritableDatabase();
        db.beginTransaction();
        try {
            for (Long id : ids) {
                db.execSQL("UPDATE " + TABLE_NAME + " SET " + COL_ATTEMPTS + " = " + COL_ATTEMPTS + " + 1 WHERE " + COL_ID + " = " + id);
            }
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }

    public synchronized long getPendingCount() {
        SQLiteDatabase db = getReadableDatabase();
        try (Cursor c = db.rawQuery("SELECT COUNT(*) FROM " + TABLE_NAME, null)) {
            if (c != null && c.moveToFirst()) {
                return c.getLong(0);
            }
        } catch (Exception ignored) {}
        return 0;
    }

    public synchronized void clearAll() {
        SQLiteDatabase db = getWritableDatabase();
        db.delete(TABLE_NAME, null, null);
    }
}
