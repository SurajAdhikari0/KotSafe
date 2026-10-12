/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * QuarantineDbHelper
 * ==================
 * SQLite database tracking all files moved into the Sandboxed Quarantine Vault.
 */

package com.kotsafe.security.model;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class QuarantineDbHelper extends SQLiteOpenHelper {
    private static final String DATABASE_NAME = "kotsafe_quarantine.db";
    private static final int DATABASE_VERSION = 1;

    public static final String TABLE_QUARANTINE = "quarantine_vault";
    public static final String COL_ID = "id";
    public static final String COL_ORIGINAL_PATH = "original_path";
    public static final String COL_FILE_NAME = "file_name";
    public static final String COL_SHA256 = "sha256";
    public static final String COL_FILE_SIZE = "file_size";
    public static final String COL_THREAT_CATEGORY = "threat_category";
    public static final String COL_THREAT_DETAILS = "threat_details";
    public static final String COL_QUARANTINE_TIMESTAMP = "quarantine_timestamp";
    public static final String COL_VAULT_FILE_NAME = "vault_file_name";
    public static final String COL_IS_RESTORED = "is_restored";

    public static class QuarantineRecord implements Serializable {
        public long id;
        public String originalPath;
        public String fileName;
        public String sha256;
        public long fileSize;
        public String threatCategory;
        public String threatDetails;
        public long quarantineTimestamp;
        public String vaultFileName;
        public boolean isRestored;
    }

    private static volatile QuarantineDbHelper sInstance;

    public static synchronized QuarantineDbHelper getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new QuarantineDbHelper(context.getApplicationContext());
        }
        return sInstance;
    }

    private QuarantineDbHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        String CREATE_TABLE = "CREATE TABLE " + TABLE_QUARANTINE + " ("
                + COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, "
                + COL_ORIGINAL_PATH + " TEXT NOT NULL, "
                + COL_FILE_NAME + " TEXT NOT NULL, "
                + COL_SHA256 + " TEXT, "
                + COL_FILE_SIZE + " INTEGER, "
                + COL_THREAT_CATEGORY + " TEXT, "
                + COL_THREAT_DETAILS + " TEXT, "
                + COL_QUARANTINE_TIMESTAMP + " INTEGER, "
                + COL_VAULT_FILE_NAME + " TEXT NOT NULL, "
                + COL_IS_RESTORED + " INTEGER DEFAULT 0"
                + ")";
        db.execSQL(CREATE_TABLE);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_QUARANTINE);
        onCreate(db);
    }

    public synchronized long addRecord(String originalPath, String fileName, String sha256,
                                       long fileSize, String threatCategory, String threatDetails,
                                       String vaultFileName) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put(COL_ORIGINAL_PATH, originalPath);
        cv.put(COL_FILE_NAME, fileName);
        cv.put(COL_SHA256, sha256);
        cv.put(COL_FILE_SIZE, fileSize);
        cv.put(COL_THREAT_CATEGORY, threatCategory);
        cv.put(COL_THREAT_DETAILS, threatDetails);
        cv.put(COL_QUARANTINE_TIMESTAMP, System.currentTimeMillis());
        cv.put(COL_VAULT_FILE_NAME, vaultFileName);
        cv.put(COL_IS_RESTORED, 0);

        return db.insert(TABLE_QUARANTINE, null, cv);
    }

    public synchronized List<QuarantineRecord> getActiveQuarantined() {
        List<QuarantineRecord> list = new ArrayList<>();
        SQLiteDatabase db = getReadableDatabase();
        String query = "SELECT * FROM " + TABLE_QUARANTINE + " WHERE " + COL_IS_RESTORED + " = 0 ORDER BY " + COL_QUARANTINE_TIMESTAMP + " DESC";
        try (Cursor c = db.rawQuery(query, null)) {
            while (c != null && c.moveToNext()) {
                QuarantineRecord r = new QuarantineRecord();
                r.id = c.getLong(c.getColumnIndexOrThrow(COL_ID));
                r.originalPath = c.getString(c.getColumnIndexOrThrow(COL_ORIGINAL_PATH));
                r.fileName = c.getString(c.getColumnIndexOrThrow(COL_FILE_NAME));
                r.sha256 = c.getString(c.getColumnIndexOrThrow(COL_SHA256));
                r.fileSize = c.getLong(c.getColumnIndexOrThrow(COL_FILE_SIZE));
                r.threatCategory = c.getString(c.getColumnIndexOrThrow(COL_THREAT_CATEGORY));
                r.threatDetails = c.getString(c.getColumnIndexOrThrow(COL_THREAT_DETAILS));
                r.quarantineTimestamp = c.getLong(c.getColumnIndexOrThrow(COL_QUARANTINE_TIMESTAMP));
                r.vaultFileName = c.getString(c.getColumnIndexOrThrow(COL_VAULT_FILE_NAME));
                r.isRestored = c.getInt(c.getColumnIndexOrThrow(COL_IS_RESTORED)) == 1;
                list.add(r);
            }
        }
        return list;
    }

    public synchronized QuarantineRecord getRecordById(long id) {
        SQLiteDatabase db = getReadableDatabase();
        String query = "SELECT * FROM " + TABLE_QUARANTINE + " WHERE " + COL_ID + " = ? LIMIT 1";
        try (Cursor c = db.rawQuery(query, new String[]{String.valueOf(id)})) {
            if (c != null && c.moveToFirst()) {
                QuarantineRecord r = new QuarantineRecord();
                r.id = c.getLong(c.getColumnIndexOrThrow(COL_ID));
                r.originalPath = c.getString(c.getColumnIndexOrThrow(COL_ORIGINAL_PATH));
                r.fileName = c.getString(c.getColumnIndexOrThrow(COL_FILE_NAME));
                r.sha256 = c.getString(c.getColumnIndexOrThrow(COL_SHA256));
                r.fileSize = c.getLong(c.getColumnIndexOrThrow(COL_FILE_SIZE));
                r.threatCategory = c.getString(c.getColumnIndexOrThrow(COL_THREAT_CATEGORY));
                r.threatDetails = c.getString(c.getColumnIndexOrThrow(COL_THREAT_DETAILS));
                r.quarantineTimestamp = c.getLong(c.getColumnIndexOrThrow(COL_QUARANTINE_TIMESTAMP));
                r.vaultFileName = c.getString(c.getColumnIndexOrThrow(COL_VAULT_FILE_NAME));
                r.isRestored = c.getInt(c.getColumnIndexOrThrow(COL_IS_RESTORED)) == 1;
                return r;
            }
        }
        return null;
    }

    public synchronized int markRestored(long id) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put(COL_IS_RESTORED, 1);
        return db.update(TABLE_QUARANTINE, cv, COL_ID + " = ?", new String[]{String.valueOf(id)});
    }

    public synchronized int deleteRecord(long id) {
        SQLiteDatabase db = getWritableDatabase();
        return db.delete(TABLE_QUARANTINE, COL_ID + " = ?", new String[]{String.valueOf(id)});
    }

    public synchronized int getActiveQuarantineCount() {
        SQLiteDatabase db = getReadableDatabase();
        String query = "SELECT COUNT(*) FROM " + TABLE_QUARANTINE + " WHERE " + COL_IS_RESTORED + " = 0";
        try (Cursor c = db.rawQuery(query, null)) {
            if (c != null && c.moveToFirst()) {
                return c.getInt(0);
            }
        }
        return 0;
    }
}
