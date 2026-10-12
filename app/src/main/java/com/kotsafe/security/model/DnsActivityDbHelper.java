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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.kotsafe.security.Log;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * SQLite storage for live DNS and Tracker activity events.
 *
 * Maintains a sliding window (pruning older entries past 1,000) for fast UI rendering
 * and zero battery/storage impact.
 */
public class DnsActivityDbHelper extends SQLiteOpenHelper {
    private static final String TAG = "DnsActivityDbHelper";
    public static final String DB_NAME = "dns_activity.db";
    private static final int DB_VERSION = 1;

    public static final String TABLE_DNS_LOGS = "dns_logs";
    public static final String COL_ID = "_id";
    public static final String COL_DOMAIN = "domain";
    public static final String COL_QUERY_TYPE = "query_type";
    public static final String COL_CALLER_APP = "caller_app";
    public static final String COL_CALLER_PKG = "caller_pkg";
    public static final String COL_STATUS = "status"; // BLOCKED | ALLOWED
    public static final String COL_BLOCK_REASON = "block_reason";
    public static final String COL_TIMESTAMP = "timestamp";

    private static final int MAX_LOG_ENTRIES = 1000;
    private static DnsActivityDbHelper sInstance;

    private final ExecutorService mDbExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "DnsDbWriter");
        t.setDaemon(true);
        return t;
    });
    private int mInsertCounter = 0;

    public static synchronized DnsActivityDbHelper getInstance(@NonNull Context context) {
        if (sInstance == null) {
            sInstance = new DnsActivityDbHelper(context.getApplicationContext());
        }
        return sInstance;
    }

    private DnsActivityDbHelper(Context context) {
        super(context, DB_NAME, null, DB_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE " + TABLE_DNS_LOGS + " ("
                + COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
                + COL_DOMAIN + " TEXT NOT NULL, "
                + COL_QUERY_TYPE + " TEXT, "
                + COL_CALLER_APP + " TEXT, "
                + COL_CALLER_PKG + " TEXT, "
                + COL_STATUS + " TEXT NOT NULL, "
                + COL_BLOCK_REASON + " TEXT, "
                + COL_TIMESTAMP + " INTEGER NOT NULL"
                + ");");
        db.execSQL("CREATE INDEX idx_dns_domain ON " + TABLE_DNS_LOGS + "(" + COL_DOMAIN + ");");
        db.execSQL("CREATE INDEX idx_dns_status ON " + TABLE_DNS_LOGS + "(" + COL_STATUS + ");");
        db.execSQL("CREATE INDEX idx_dns_timestamp ON " + TABLE_DNS_LOGS + "(" + COL_TIMESTAMP + ");");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_DNS_LOGS);
        onCreate(db);
    }

    public void logQuery(@NonNull String domain, @Nullable String queryType,
                         @Nullable String callerApp, @Nullable String callerPkg,
                         boolean isBlocked, @Nullable String blockReason) {
        final long now = System.currentTimeMillis();
        mDbExecutor.execute(() -> {
            try {
                SQLiteDatabase db = getWritableDatabase();
                ContentValues cv = new ContentValues();
                cv.put(COL_DOMAIN, domain);
                cv.put(COL_QUERY_TYPE, queryType != null ? queryType : "A");
                cv.put(COL_CALLER_APP, callerApp != null ? callerApp : "System / Network");
                cv.put(COL_CALLER_PKG, callerPkg != null ? callerPkg : "");
                cv.put(COL_STATUS, isBlocked ? DnsActivityEntry.STATUS_BLOCKED : DnsActivityEntry.STATUS_ALLOWED);
                cv.put(COL_BLOCK_REASON, blockReason != null ? blockReason : "");
                cv.put(COL_TIMESTAMP, now);

                db.insert(TABLE_DNS_LOGS, null, cv);

                if (++mInsertCounter % 100 == 0) {
                    pruneOldRecords(db);
                }
            } catch (Exception e) {
                Log.w(TAG, "logQuery failed: " + e.getMessage());
            }
        });
    }

    public void logDnsQuery(@NonNull String domain, @NonNull String status,
                            @Nullable String blockReason, @Nullable String callerPkg,
                            @Nullable String queryType) {
        boolean isBlocked = DnsActivityEntry.STATUS_BLOCKED.equalsIgnoreCase(status);
        logQuery(domain, queryType, callerPkg, callerPkg, isBlocked, blockReason);
    }

    private void pruneOldRecords(SQLiteDatabase db) {
        try {
            db.execSQL("DELETE FROM " + TABLE_DNS_LOGS + " WHERE " + COL_ID + " NOT IN ("
                    + "SELECT " + COL_ID + " FROM " + TABLE_DNS_LOGS
                    + " ORDER BY " + COL_TIMESTAMP + " DESC LIMIT " + MAX_LOG_ENTRIES + ")");
        } catch (Exception e) {
            Log.w(TAG, "pruneOldRecords error: " + e.getMessage());
        }
    }

    @NonNull
    public synchronized List<DnsActivityEntry> queryLogs(@Nullable String filterStatus, @Nullable String searchFilter, int limit, int offset) {
        List<DnsActivityEntry> list = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();

        StringBuilder where = new StringBuilder("1=1");
        List<String> args = new ArrayList<>();

        if (filterStatus != null && !filterStatus.isEmpty()) {
            where.append(" AND ").append(COL_STATUS).append(" = ?");
            args.add(filterStatus);
        }
        if (searchFilter != null && !searchFilter.isEmpty()) {
            where.append(" AND (").append(COL_DOMAIN).append(" LIKE ? OR ").append(COL_CALLER_APP).append(" LIKE ?)");
            args.add("%" + searchFilter + "%");
            args.add("%" + searchFilter + "%");
        }

        String sql = "SELECT * FROM " + TABLE_DNS_LOGS
                + " WHERE " + where
                + " ORDER BY " + COL_TIMESTAMP + " DESC LIMIT " + limit + " OFFSET " + offset;

        try (Cursor c = db.rawQuery(sql, args.toArray(new String[0]))) {
            while (c != null && c.moveToNext()) {
                DnsActivityEntry e = new DnsActivityEntry();
                e.id = c.getLong(c.getColumnIndexOrThrow(COL_ID));
                e.domain = c.getString(c.getColumnIndexOrThrow(COL_DOMAIN));
                e.queryType = c.getString(c.getColumnIndexOrThrow(COL_QUERY_TYPE));
                e.callerApp = c.getString(c.getColumnIndexOrThrow(COL_CALLER_APP));
                e.callerPkg = c.getString(c.getColumnIndexOrThrow(COL_CALLER_PKG));
                e.status = c.getString(c.getColumnIndexOrThrow(COL_STATUS));
                e.blockReason = c.getString(c.getColumnIndexOrThrow(COL_BLOCK_REASON));
                e.timestamp = c.getLong(c.getColumnIndexOrThrow(COL_TIMESTAMP));
                list.add(e);
            }
        } catch (Exception e) {
            Log.w(TAG, "queryLogs error: " + e.getMessage());
        }
        return list;
    }

    public synchronized void clearLogs() {
        SQLiteDatabase db = getWritableDatabase();
        db.delete(TABLE_DNS_LOGS, null, null);
    }
}
