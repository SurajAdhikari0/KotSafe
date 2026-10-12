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

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;

import java.util.ArrayList;
import java.util.List;

public class FirewallLogDbHelper extends SQLiteOpenHelper {
    private static final String TAG = "FirewallLogDbHelper";
    private static final String DATABASE_NAME = "firewall_logs.db";
    private static final int DATABASE_VERSION = 3;

    /** Window (ms) within which an identical flow entry is considered a duplicate and dropped. */
    private static final long DEDUP_WINDOW_MS = 2000L;

    public static final String TABLE_LOGS = "firewall_logs";

    public static final String COL_ID = "_id";
    public static final String COL_TIMESTAMP = "timestamp";
    public static final String COL_UID = "uid";
    public static final String COL_PACKAGE_NAME = "package_name";
    public static final String COL_APP_NAME = "app_name";
    public static final String COL_IS_SERVICE = "is_service";
    public static final String COL_SRC_IP = "src_ip";
    public static final String COL_SRC_PORT = "src_port";
    public static final String COL_DST_IP = "dst_ip";
    public static final String COL_DST_PORT = "dst_port";
    public static final String COL_PROTOCOL = "protocol";
    public static final String COL_L7_PROTO = "l7proto";
    public static final String COL_DOMAIN_URL = "domain_url";
    public static final String COL_PAYLOAD_HASH = "payload_hash";
    public static final String COL_ACTION = "action";
    public static final String COL_BLOCK_REASON = "block_reason";
    public static final String COL_BLOCK_TYPE = "block_type";
    public static final String COL_NETWORK_TYPE = "network_type";
    public static final String COL_IS_BACKGROUND = "is_background";
    public static final String COL_BYTES_SENT = "bytes_sent";
    public static final String COL_BYTES_RCVD = "bytes_rcvd";
    public static final String COL_DURATION = "duration";
    public static final String COL_COUNTRY = "country";
    public static final String COL_ASN = "asn";
    public static final String COL_THREAT_VERDICT = "threat_verdict";
    public static final String COL_THREAT_SCORE = "threat_score";
    public static final String COL_THREAT_SOURCE = "threat_source";
    public static final String COL_THREAT_DETAILS = "threat_details";

    // 7 days in milliseconds
    public static final long RETENTION_PERIOD_MILLIS = 7L * 24L * 60L * 60L * 1000L;

    private static volatile FirewallLogDbHelper sInstance;
    private final Context mContext;

    public static FirewallLogDbHelper getInstance(Context context) {
        if(sInstance == null) {
            synchronized (FirewallLogDbHelper.class) {
                if(sInstance == null) {
                    sInstance = new FirewallLogDbHelper(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    public FirewallLogDbHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
        mContext = context.getApplicationContext();
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
        String createTableQuery = "CREATE TABLE " + TABLE_LOGS + " ("
                + COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
                + COL_TIMESTAMP + " INTEGER NOT NULL, "
                + COL_UID + " INTEGER, "
                + COL_PACKAGE_NAME + " TEXT, "
                + COL_APP_NAME + " TEXT, "
                + COL_IS_SERVICE + " INTEGER DEFAULT 0, "
                + COL_SRC_IP + " TEXT, "
                + COL_SRC_PORT + " INTEGER, "
                + COL_DST_IP + " TEXT, "
                + COL_DST_PORT + " INTEGER, "
                + COL_PROTOCOL + " TEXT, "
                + COL_L7_PROTO + " TEXT, "
                + COL_DOMAIN_URL + " TEXT, "
                + COL_PAYLOAD_HASH + " TEXT, "
                + COL_ACTION + " TEXT NOT NULL, "
                + COL_BLOCK_REASON + " TEXT, "
                + COL_BLOCK_TYPE + " TEXT, "
                + COL_NETWORK_TYPE + " TEXT, "
                + COL_IS_BACKGROUND + " INTEGER DEFAULT 0, "
                + COL_BYTES_SENT + " INTEGER DEFAULT 0, "
                + COL_BYTES_RCVD + " INTEGER DEFAULT 0, "
                + COL_DURATION + " INTEGER DEFAULT 0, "
                + COL_COUNTRY + " TEXT, "
                + COL_ASN + " TEXT, "
                + COL_THREAT_VERDICT + " TEXT, "
                + COL_THREAT_SCORE + " INTEGER DEFAULT -1, "
                + COL_THREAT_SOURCE + " TEXT, "
                + COL_THREAT_DETAILS + " TEXT"
                + ");";

        db.execSQL(createTableQuery);

        // Optimized indexes for search, filtering, and timestamp auto-pruning
        db.execSQL("CREATE INDEX idx_logs_timestamp ON " + TABLE_LOGS + "(" + COL_TIMESTAMP + ");");
        db.execSQL("CREATE INDEX idx_logs_action ON " + TABLE_LOGS + "(" + COL_ACTION + ");");
        db.execSQL("CREATE INDEX idx_logs_pkg ON " + TABLE_LOGS + "(" + COL_PACKAGE_NAME + ");");
        db.execSQL("CREATE INDEX idx_logs_dst ON " + TABLE_LOGS + "(" + COL_DST_IP + ");");
        // Compound index used by the time-windowed deduplication query
        db.execSQL("CREATE INDEX idx_logs_dedup ON " + TABLE_LOGS
                + "(" + COL_UID + "," + COL_DST_IP + "," + COL_DST_PORT + "," + COL_ACTION + "," + COL_TIMESTAMP + ");");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        if (oldVersion < 2) {
            try {
                db.execSQL("ALTER TABLE " + TABLE_LOGS + " ADD COLUMN " + COL_BLOCK_TYPE + " TEXT;");
            } catch (Exception ignored) {}
        }
        if (oldVersion < 3) {
            // Add compound index used by the deduplication query
            try {
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_logs_dedup ON " + TABLE_LOGS
                        + "(" + COL_UID + "," + COL_DST_IP + "," + COL_DST_PORT + "," + COL_ACTION + "," + COL_TIMESTAMP + ");");
            } catch (Exception ignored) {}
        }
    }

    /**
     * Purges logs older than 7 days (1 week).
     * @return Number of rows deleted.
     */
    public synchronized int purgeOldLogs() {
        try {
            SQLiteDatabase db = getWritableDatabase();
            long cutoff = System.currentTimeMillis() - RETENTION_PERIOD_MILLIS;
            int deleted = db.delete(TABLE_LOGS, COL_TIMESTAMP + " < ?", new String[]{String.valueOf(cutoff)});
            if(deleted > 0) {
                Log.i(TAG, "Purged " + deleted + " firewall log entries older than 7 days");
            }
            return deleted;
        } catch (Exception e) {
            Log.e(TAG, "Error purging old logs: " + e.getMessage());
            return 0;
        }
    }

    public synchronized long insertLog(FirewallLogEntry entry) {
        try {
            SQLiteDatabase db = getWritableDatabase();

            // ---- Time-windowed deduplication -----------------------------------------------
            // Drop the row if an identical (uid + dst_ip + dst_port + action) entry was already
            // inserted within the last DEDUP_WINDOW_MS milliseconds.  This prevents multiple
            // rapid-fire snapshots from the same flow appearing as separate log lines.
            long cutoff = entry.timestamp - DEDUP_WINDOW_MS;
            String dedupSql = "SELECT COUNT(*) FROM " + TABLE_LOGS
                    + " WHERE " + COL_UID    + "=?"
                    + " AND "  + COL_DST_IP  + "=?"
                    + " AND "  + COL_DST_PORT + "=?"
                    + " AND "  + COL_ACTION  + "=?"
                    + " AND "  + COL_TIMESTAMP + ">?";
            try (android.database.Cursor dedup = db.rawQuery(dedupSql, new String[]{
                    String.valueOf(entry.uid),
                    entry.dstIp != null ? entry.dstIp : "",
                    String.valueOf(entry.dstPort),
                    entry.action != null ? entry.action : FirewallLogEntry.ACTION_ALLOWED,
                    String.valueOf(cutoff)
            })) {
                if (dedup != null && dedup.moveToFirst() && dedup.getInt(0) > 0) {
                    // Duplicate within the dedup window — skip insertion
                    return -2;
                }
            } catch (Exception ignored) {}
            // ---------------------------------------------------------------------------------

            // If this connection is BLOCKED or ALERT, prune any preliminary ALLOWED record
            // logged during initial packet handshake within the same window
            if (FirewallLogEntry.ACTION_BLOCKED.equals(entry.action) || FirewallLogEntry.ACTION_ALERT.equals(entry.action)) {
                try {
                    db.delete(TABLE_LOGS, COL_UID + "=? AND " + COL_DST_IP + "=? AND " + COL_DST_PORT + "=? AND " + COL_ACTION + "=? AND " + COL_TIMESTAMP + ">?",
                            new String[]{String.valueOf(entry.uid), entry.dstIp != null ? entry.dstIp : "", String.valueOf(entry.dstPort), FirewallLogEntry.ACTION_ALLOWED, String.valueOf(cutoff)});
                } catch (Exception ignored) {}
            }

            ContentValues cv = new ContentValues();
            cv.put(COL_TIMESTAMP, entry.timestamp);
            cv.put(COL_UID, entry.uid);
            cv.put(COL_PACKAGE_NAME, entry.packageName != null ? entry.packageName : "");
            cv.put(COL_APP_NAME, entry.appName != null ? entry.appName : "");
            cv.put(COL_IS_SERVICE, entry.isServiceApp ? 1 : 0);
            cv.put(COL_SRC_IP, entry.srcIp != null ? entry.srcIp : "");
            cv.put(COL_SRC_PORT, entry.srcPort);
            cv.put(COL_DST_IP, entry.dstIp != null ? entry.dstIp : "");
            cv.put(COL_DST_PORT, entry.dstPort);
            cv.put(COL_PROTOCOL, entry.protocol != null ? entry.protocol : "TCP");
            cv.put(COL_L7_PROTO, entry.l7proto != null ? entry.l7proto : "");
            cv.put(COL_DOMAIN_URL, entry.domainOrUrl != null ? entry.domainOrUrl : "");
            cv.put(COL_PAYLOAD_HASH, entry.payloadHash != null ? entry.payloadHash : "");
            cv.put(COL_ACTION, entry.action != null ? entry.action : FirewallLogEntry.ACTION_ALLOWED);
            cv.put(COL_BLOCK_REASON, entry.blockReason != null ? entry.blockReason : "");
            cv.put(COL_BLOCK_TYPE, entry.blockType != null && !entry.blockType.isEmpty() ? entry.blockType : entry.getFormattedBlockType());
            cv.put(COL_NETWORK_TYPE, entry.networkType != null ? entry.networkType : "UNKNOWN");
            cv.put(COL_IS_BACKGROUND, entry.isBackground ? 1 : 0);
            cv.put(COL_BYTES_SENT, entry.bytesSent);
            cv.put(COL_BYTES_RCVD, entry.bytesRcvd);
            cv.put(COL_DURATION, entry.duration);
            cv.put(COL_COUNTRY, entry.country != null ? entry.country : "");
            cv.put(COL_ASN, entry.asn != null ? entry.asn : "");
            cv.put(COL_THREAT_VERDICT, entry.threatVerdict != null ? entry.threatVerdict : FirewallLogEntry.VERDICT_UNKNOWN);
            cv.put(COL_THREAT_SCORE, entry.threatScore);
            cv.put(COL_THREAT_SOURCE, entry.threatSource != null ? entry.threatSource : "");
            cv.put(COL_THREAT_DETAILS, entry.threatDetails != null ? entry.threatDetails : "");

            long rowId = db.insert(TABLE_LOGS, null, cv);
            entry.id = rowId;
            return rowId;
        } catch (Exception e) {
            Log.e(TAG, "Error inserting log: " + e.getMessage());
            return -1;
        }
    }

    public synchronized List<FirewallLogEntry> queryLogs(String filterType, String searchQuery, int limit, int offset) {
        List<FirewallLogEntry> list = new ArrayList<>();
        try {
            SQLiteDatabase db = getReadableDatabase();
            StringBuilder where = new StringBuilder("1=1");
            List<String> args = new ArrayList<>();

            if(filterType != null) {
                switch(filterType.toUpperCase()) {
                    case "BLOCKED":
                        where.append(" AND ").append(COL_ACTION).append(" = ?");
                        args.add(FirewallLogEntry.ACTION_BLOCKED);
                        break;
                    case "ALLOWED":
                        where.append(" AND ").append(COL_ACTION).append(" = ?");
                        args.add(FirewallLogEntry.ACTION_ALLOWED);
                        break;
                    case "THREATS":
                        where.append(" AND (").append(COL_ACTION).append(" = ? OR ")
                                .append(COL_THREAT_VERDICT).append(" = ? OR ")
                                .append(COL_THREAT_VERDICT).append(" = ?)");
                        args.add(FirewallLogEntry.ACTION_ALERT);
                        args.add(FirewallLogEntry.VERDICT_MALICIOUS);
                        args.add(FirewallLogEntry.VERDICT_SUSPICIOUS);
                        break;
                    case "BACKGROUND":
                        where.append(" AND ").append(COL_IS_BACKGROUND).append(" = 1");
                        break;
                    case "SERVICES":
                        where.append(" AND ").append(COL_IS_SERVICE).append(" = 1");
                        break;
                }
            }

            if(searchQuery != null && !searchQuery.trim().isEmpty()) {
                String pattern = "%" + searchQuery.trim() + "%";
                where.append(" AND (")
                        .append(COL_APP_NAME).append(" LIKE ? OR ")
                        .append(COL_PACKAGE_NAME).append(" LIKE ? OR ")
                        .append(COL_DST_IP).append(" LIKE ? OR ")
                        .append(COL_DOMAIN_URL).append(" LIKE ? OR ")
                        .append(COL_PAYLOAD_HASH).append(" LIKE ?)");
                args.add(pattern);
                args.add(pattern);
                args.add(pattern);
                args.add(pattern);
                args.add(pattern);
            }

            String limitStr = limit > 0 ? (offset > 0 ? offset + "," + limit : String.valueOf(limit)) : null;

            Cursor cursor = db.query(TABLE_LOGS, null, where.toString(), args.toArray(new String[0]),
                    null, null, COL_TIMESTAMP + " DESC", limitStr);

            if(cursor != null) {
                try {
                    while(cursor.moveToNext()) {
                        FirewallLogEntry entry = cursorToEntry(cursor);
                        list.add(entry);
                    }
                } finally {
                    cursor.close();
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error querying logs: " + e.getMessage());
        }
        return list;
    }

    public synchronized void clearAll() {
        try {
            SQLiteDatabase db = getWritableDatabase();
            db.delete(TABLE_LOGS, null, null);
        } catch (Exception e) {
            Log.e(TAG, "Error clearing logs: " + e.getMessage());
        }
    }

    public synchronized int getCount() {
        Cursor cursor = null;
        try {
            SQLiteDatabase db = getReadableDatabase();
            cursor = db.rawQuery("SELECT COUNT(*) FROM " + TABLE_LOGS, null);
            if(cursor != null && cursor.moveToFirst()) {
                return cursor.getInt(0);
            }
        } catch (Exception e) {
            Log.e(TAG, "Error counting logs: " + e.getMessage());
        } finally {
            if(cursor != null) cursor.close();
        }
        return 0;
    }

    public synchronized int getBlockedCount() {
        Cursor cursor = null;
        try {
            SQLiteDatabase db = getReadableDatabase();
            cursor = db.rawQuery("SELECT COUNT(*) FROM " + TABLE_LOGS + " WHERE " + COL_ACTION + " = 'BLOCKED'", null);
            if(cursor != null && cursor.moveToFirst()) {
                return cursor.getInt(0);
            }
        } catch (Exception e) {
            Log.e(TAG, "Error counting blocked logs: " + e.getMessage());
        } finally {
            if(cursor != null) cursor.close();
        }
        return 0;
    }

    private FirewallLogEntry cursorToEntry(Cursor c) {
        FirewallLogEntry e = new FirewallLogEntry();
        e.id = c.getLong(c.getColumnIndexOrThrow(COL_ID));
        e.timestamp = c.getLong(c.getColumnIndexOrThrow(COL_TIMESTAMP));
        e.uid = c.getInt(c.getColumnIndexOrThrow(COL_UID));
        e.packageName = c.getString(c.getColumnIndexOrThrow(COL_PACKAGE_NAME));
        e.appName = c.getString(c.getColumnIndexOrThrow(COL_APP_NAME));
        e.isServiceApp = c.getInt(c.getColumnIndexOrThrow(COL_IS_SERVICE)) == 1;
        e.srcIp = c.getString(c.getColumnIndexOrThrow(COL_SRC_IP));
        e.srcPort = c.getInt(c.getColumnIndexOrThrow(COL_SRC_PORT));
        e.dstIp = c.getString(c.getColumnIndexOrThrow(COL_DST_IP));
        e.dstPort = c.getInt(c.getColumnIndexOrThrow(COL_DST_PORT));
        e.protocol = c.getString(c.getColumnIndexOrThrow(COL_PROTOCOL));
        e.l7proto = c.getString(c.getColumnIndexOrThrow(COL_L7_PROTO));
        e.domainOrUrl = c.getString(c.getColumnIndexOrThrow(COL_DOMAIN_URL));
        e.payloadHash = c.getString(c.getColumnIndexOrThrow(COL_PAYLOAD_HASH));
        e.action = c.getString(c.getColumnIndexOrThrow(COL_ACTION));
        e.blockReason = c.getString(c.getColumnIndexOrThrow(COL_BLOCK_REASON));
        int btIdx = c.getColumnIndex(COL_BLOCK_TYPE);
        if (btIdx >= 0) {
            e.blockType = c.getString(btIdx);
        }
        if (e.blockType == null || e.blockType.isEmpty()) {
            e.blockType = e.getFormattedBlockType();
        }
        e.networkType = c.getString(c.getColumnIndexOrThrow(COL_NETWORK_TYPE));
        e.isBackground = c.getInt(c.getColumnIndexOrThrow(COL_IS_BACKGROUND)) == 1;
        e.bytesSent = c.getLong(c.getColumnIndexOrThrow(COL_BYTES_SENT));
        e.bytesRcvd = c.getLong(c.getColumnIndexOrThrow(COL_BYTES_RCVD));
        e.duration = c.getLong(c.getColumnIndexOrThrow(COL_DURATION));
        e.country = c.getString(c.getColumnIndexOrThrow(COL_COUNTRY));
        e.asn = c.getString(c.getColumnIndexOrThrow(COL_ASN));
        e.threatVerdict = c.getString(c.getColumnIndexOrThrow(COL_THREAT_VERDICT));
        e.threatScore = c.getInt(c.getColumnIndexOrThrow(COL_THREAT_SCORE));
        e.threatSource = c.getString(c.getColumnIndexOrThrow(COL_THREAT_SOURCE));
        e.threatDetails = c.getString(c.getColumnIndexOrThrow(COL_THREAT_DETAILS));
        return e;
    }

    /** Returns true if the destination IP is associated with any Android system application. */
    public synchronized boolean isSystemAppIp(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        try (SQLiteDatabase db = getReadableDatabase();
             Cursor cursor = db.rawQuery(
                     "SELECT DISTINCT " + COL_PACKAGE_NAME + " FROM " + TABLE_LOGS +
                     " WHERE " + COL_DST_IP + " = ? LIMIT 10",
                     new String[]{ip})) {
            while (cursor != null && cursor.moveToNext()) {
                String pkg = cursor.getString(0);
                if (Utils.isSystemApp(mContext, pkg)) return true;
            }
        } catch (Exception e) {
            Log.w(TAG, "isSystemAppIp error: " + e.getMessage());
        }
        return false;
    }
}
