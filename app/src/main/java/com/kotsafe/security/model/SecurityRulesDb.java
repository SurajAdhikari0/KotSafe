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
import com.kotsafe.security.model.backend.BackendProviderFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * DOMAIN 4 — SECURITY RULES  (The most important storage domain)
 *
 * Stores active protection state: block rules, whitelist, quarantine metadata.
 *
 * CRITICAL: This database is NEVER auto-deleted by retention workers.
 * It NEVER shares a deletion path with Evidence, Logs, or Cache.
 *
 * Rule priority order (higher = evaluated first):
 *   1000 Emergency system protection
 *    900 Explicit user block
 *    800 Quarantine
 *    700 Explicit user allow (whitelist)
 *    500 Threat-intelligence detection
 *    400 YARA / heuristic detection
 *    100 Default policy
 */
public class SecurityRulesDb extends SQLiteOpenHelper {
    private static final String TAG = "SecurityRulesDb";
    public static final String DB_NAME = "rules.db";
    private static final int DB_VERSION = 1;

    public static final String TABLE_RULES = "security_rules";
    public static final String COL_ID = "_id";
    public static final String COL_TYPE = "type";        // APP | IP | DOMAIN | URL | HASH
    public static final String COL_VALUE = "value";      // the actual IOC or package name
    public static final String COL_ACTION = "action";    // BLOCK | ALLOW | WARN | QUARANTINE
    public static final String COL_SCOPE = "scope";      // EXACT | DOMAIN_WIDE | PREFIX
    public static final String COL_SOURCE = "source";    // USER | SYSTEM | TI | YARA | HEURISTIC
    public static final String COL_REASON = "reason";
    public static final String COL_SEVERITY = "severity";
    public static final String COL_PRIORITY = "priority";
    public static final String COL_CREATED_AT = "created_at";
    public static final String COL_EXPIRES_AT = "expires_at";   // 0 = never expires
    public static final String COL_ENABLED = "enabled";
    public static final String COL_HIT_COUNT = "hit_count";     // how many times this rule fired

    // Rule types
    public static final String TYPE_APP = "APP";
    public static final String TYPE_IP = "IP";
    public static final String TYPE_DOMAIN = "DOMAIN";
    public static final String TYPE_URL = "URL";
    public static final String TYPE_HASH = "HASH";
    public static final String TYPE_JA3 = "JA3";
    public static final String TYPE_COMPOUND = "COMPOUND";

    // Actions
    public static final String ACTION_BLOCK = "BLOCK";
    public static final String ACTION_ALLOW = "ALLOW";
    public static final String ACTION_WARN = "WARN";
    public static final String ACTION_QUARANTINE = "QUARANTINE";
    public static final String ACTION_RATE_LIMIT = "RATE_LIMIT";

    // Sources
    public static final String SOURCE_USER = "USER";
    public static final String SOURCE_SYSTEM = "SYSTEM";
    public static final String SOURCE_TI = "TI";
    public static final String SOURCE_YARA = "YARA";
    public static final String SOURCE_HEURISTIC = "HEURISTIC";

    // Scopes
    public static final String SCOPE_EXACT = "EXACT";
    public static final String SCOPE_DOMAIN_WIDE = "DOMAIN_WIDE";
    public static final String SCOPE_PREFIX = "PREFIX";

    // Priority constants
    public static final int PRIORITY_EMERGENCY = 1000;
    public static final int PRIORITY_EXPLICIT_BLOCK = 900;
    public static final int PRIORITY_QUARANTINE = 800;
    public static final int PRIORITY_USER_ALLOW = 700;
    public static final int PRIORITY_TI = 500;
    public static final int PRIORITY_YARA = 400;
    public static final int PRIORITY_DEFAULT = 100;

    private static SecurityRulesDb sInstance;

    public static synchronized SecurityRulesDb getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new SecurityRulesDb(context.getApplicationContext());
        }
        return sInstance;
    }

    private SecurityRulesDb(Context context) {
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
    public void onOpen(SQLiteDatabase db) {
        super.onOpen(db);
        purgeLegacyTiRules(db);
        purgeCorruptedRules(db);
    }

    public void purgeLegacyTiRules(SQLiteDatabase db) {
        try {
            int count = db.delete(TABLE_RULES, COL_SOURCE + "=?", new String[]{SOURCE_TI});
            if (count > 0) {
                Log.i(TAG, "Purged " + count + " legacy auto-blocked TI rules");
            }
        } catch (Exception e) {
            Log.w(TAG, "purgeLegacyTiRules error: " + e.getMessage());
        }
    }

    public void purgeCorruptedRules(SQLiteDatabase db) {
        try {
            int count = db.delete(TABLE_RULES, "value LIKE 'dns tunneling%' OR value LIKE '%entropy%' OR value LIKE '%...%'", null);
            if (count > 0) {
                Log.i(TAG, "Purged " + count + " corrupted heuristic rules");
            }
        } catch (Exception e) {
            Log.w(TAG, "purgeCorruptedRules error: " + e.getMessage());
        }
    }

    public int deleteRulesBySource(String source) {
        try {
            return getWritableDatabase().delete(TABLE_RULES,
                    COL_SOURCE + "=?", new String[]{source});
        } catch (Exception e) {
            Log.e(TAG, "deleteRulesBySource: " + e.getMessage());
            return 0;
        }
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE IF NOT EXISTS " + TABLE_RULES + " (" +
                COL_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                COL_TYPE + " TEXT NOT NULL, " +
                COL_VALUE + " TEXT NOT NULL, " +
                COL_ACTION + " TEXT NOT NULL, " +
                COL_SCOPE + " TEXT DEFAULT '" + SCOPE_EXACT + "', " +
                COL_SOURCE + " TEXT NOT NULL, " +
                COL_REASON + " TEXT, " +
                COL_SEVERITY + " TEXT DEFAULT 'MEDIUM', " +
                COL_PRIORITY + " INTEGER DEFAULT " + PRIORITY_EXPLICIT_BLOCK + ", " +
                COL_CREATED_AT + " INTEGER NOT NULL DEFAULT (strftime('%s','now')*1000), " +
                COL_EXPIRES_AT + " INTEGER DEFAULT 0, " +
                COL_ENABLED + " INTEGER DEFAULT 1, " +
                COL_HIT_COUNT + " INTEGER DEFAULT 0, " +
                "UNIQUE(" + COL_TYPE + ", " + COL_VALUE + ") ON CONFLICT REPLACE)");

        db.execSQL("CREATE INDEX IF NOT EXISTS idx_rules_value ON " +
                TABLE_RULES + "(" + COL_VALUE + ")");
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_rules_type ON " +
                TABLE_RULES + "(" + COL_TYPE + ", " + COL_ENABLED + ")");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int old, int nv) {}

    // ─── Insert / update ──────────────────────────────────────────────────────

    public long addRule(String type, String value, String action, String scope,
                        String source, String reason, int priority) {
        ContentValues cv = new ContentValues();
        cv.put(COL_TYPE, type);
        cv.put(COL_VALUE, value.toLowerCase().trim());
        cv.put(COL_ACTION, action);
        cv.put(COL_SCOPE, scope != null ? scope : SCOPE_EXACT);
        cv.put(COL_SOURCE, source);
        cv.put(COL_REASON, reason);
        cv.put(COL_PRIORITY, priority);
        cv.put(COL_ENABLED, 1);
        cv.put(COL_CREATED_AT, System.currentTimeMillis());
        try {
            long id = getWritableDatabase().insertOrThrow(TABLE_RULES, null, cv);
            Log.i(TAG, "Rule added: " + action + " " + type + " [" + value + "] src=" + source);
            return id;
        } catch (Exception e) {
            Log.e(TAG, "addRule error: " + e.getMessage());
            return -1;
        }
    }

    public long blockIp(String ip, String reason, String source) {
        if (ip == null || ip.trim().isEmpty()) return -1;
        String clean = cleanHostOrValue(ip);
        if (clean.equals("127.0.0.1") || clean.equalsIgnoreCase("localhost")
                || clean.equals("8.8.8.8") || clean.equals("8.8.4.4")
                || clean.equals("1.1.1.1") || clean.equals("1.0.0.1")
                || clean.equals(BackendProviderFactory.getDirectVpsHost())) {
            Log.w(TAG, "Prevented recorded block rule for critical DNS / Loopback / P2P Relay IP: " + clean);
            return -1;
        }
        return addRule(TYPE_IP, ip, ACTION_BLOCK, SCOPE_EXACT, source, reason, PRIORITY_EXPLICIT_BLOCK);
    }

    public long blockDomain(String domain, String reason, String source) {
        return addRule(TYPE_DOMAIN, domain, ACTION_BLOCK, SCOPE_DOMAIN_WIDE, source, reason, PRIORITY_EXPLICIT_BLOCK);
    }

    public long blockUrl(String url, String reason, String source) {
        return addRule(TYPE_URL, url, ACTION_BLOCK, SCOPE_EXACT, source, reason, PRIORITY_EXPLICIT_BLOCK);
    }

    public long blockHash(String sha256, String reason, String source) {
        return addRule(TYPE_HASH, sha256, ACTION_BLOCK, SCOPE_EXACT, source, reason, PRIORITY_EXPLICIT_BLOCK);
    }

    public long quarantineHash(String sha256, String reason, String source) {
        if (sha256 == null || sha256.trim().isEmpty()) return -1;
        return addRule(TYPE_HASH, sha256, ACTION_QUARANTINE, SCOPE_EXACT, source, reason, PRIORITY_QUARANTINE);
    }

    public long blockApp(String packageName, String reason, String source) {
        if (packageName == null || packageName.trim().isEmpty()) return -1;
        String lower = packageName.trim().toLowerCase(java.util.Locale.US);
        if (lower.equals("com.kotsafe.security") || lower.contains("kotsafe")) {
            Log.w(TAG, "Self-Protection: Refusing to record block rule for KotSafe: " + packageName);
            return -1;
        }
        return addRule(TYPE_APP, packageName, ACTION_BLOCK, SCOPE_EXACT, source, reason, PRIORITY_EXPLICIT_BLOCK);
    }

    public long quarantineApp(String packageName, String reason, String source) {
        if (packageName == null || packageName.trim().isEmpty()) return -1;
        String lower = packageName.trim().toLowerCase(java.util.Locale.US);
        if (lower.equals("com.kotsafe.security") || lower.contains("kotsafe")) {
            Log.w(TAG, "Self-Protection: Refusing to record quarantine rule for KotSafe: " + packageName);
            return -1;
        }
        return addRule(TYPE_APP, packageName, ACTION_QUARANTINE, SCOPE_EXACT, source, reason, PRIORITY_QUARANTINE);
    }

    public long quarantineDomain(String domain, String reason, String source) {
        String clean = cleanHostOrValue(domain);
        if (clean.isEmpty()) clean = domain;
        return addRule(TYPE_DOMAIN, clean, ACTION_QUARANTINE, SCOPE_DOMAIN_WIDE, source, reason, PRIORITY_QUARANTINE);
    }

    public long quarantineUrl(String url, String reason, String source) {
        if (url == null || url.trim().isEmpty()) return -1;
        return addRule(TYPE_URL, url, ACTION_QUARANTINE, SCOPE_EXACT, source, reason, PRIORITY_QUARANTINE);
    }

    public long blockJa3(String ja3Hash, String reason, String source) {
        return addRule(TYPE_JA3, ja3Hash != null ? ja3Hash.toLowerCase().trim() : "",
                ACTION_BLOCK, SCOPE_EXACT, source, reason, PRIORITY_EXPLICIT_BLOCK);
    }

    public long addCompoundRule(CompoundRule rule) {
        if (rule == null) return -1;
        String json = rule.toJson();
        ContentValues cv = new ContentValues();
        cv.put(COL_TYPE, TYPE_COMPOUND);
        cv.put(COL_VALUE, json);
        cv.put(COL_ACTION, rule.action != null ? rule.action : ACTION_BLOCK);
        cv.put(COL_SCOPE, SCOPE_EXACT);
        cv.put(COL_SOURCE, rule.source != null ? rule.source : SOURCE_USER);
        cv.put(COL_REASON, rule.reason != null ? rule.reason : (rule.name != null ? rule.name : "Compound firewall rule"));
        cv.put(COL_PRIORITY, rule.priority > 0 ? rule.priority : PRIORITY_EXPLICIT_BLOCK);
        cv.put(COL_ENABLED, rule.enabled ? 1 : 0);
        cv.put(COL_CREATED_AT, rule.createdAt > 0 ? rule.createdAt : System.currentTimeMillis());
        try {
            long id = getWritableDatabase().insert(TABLE_RULES, null, cv);
            rule.id = id;
            Log.i(TAG, "Compound rule added: id=" + id + " action=" + rule.action);
            return id;
        } catch (Exception e) {
            Log.e(TAG, "addCompoundRule error: " + e.getMessage());
            return -1;
        }
    }

    public List<CompoundRule> getAllCompoundRules() {
        List<CompoundRule> list = new ArrayList<>();
        String sql = "SELECT * FROM " + TABLE_RULES + " WHERE " + COL_TYPE + "=? ORDER BY " + COL_PRIORITY + " DESC, " + COL_CREATED_AT + " DESC";
        try (Cursor c = getReadableDatabase().rawQuery(sql, new String[]{TYPE_COMPOUND})) {
            while (c.moveToNext()) {
                SecurityRule sr = cursorToRule(c);
                CompoundRule cr = CompoundRule.fromJson(sr.value);
                if (cr != null) {
                    cr.id = sr.id;
                    cr.enabled = sr.enabled;
                    cr.hitCount = sr.hitCount;
                    cr.priority = sr.priority;
                    if (cr.action == null) cr.action = sr.action;
                    list.add(cr);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "getAllCompoundRules error: " + e.getMessage());
        }
        return list;
    }

    public CompoundRule matchCompoundRule(String app, String dstIp, int dstPort, String domain, String proto, String ja3) {
        String sql = "SELECT * FROM " + TABLE_RULES + " WHERE " + COL_TYPE + "=? AND " + COL_ENABLED + "=1 ORDER BY " + COL_PRIORITY + " DESC";
        try (Cursor c = getReadableDatabase().rawQuery(sql, new String[]{TYPE_COMPOUND})) {
            while (c.moveToNext()) {
                SecurityRule sr = cursorToRule(c);
                CompoundRule cr = CompoundRule.fromJson(sr.value);
                if (cr != null && cr.enabled) {
                    cr.id = sr.id;
                    cr.priority = sr.priority;
                    if (cr.action == null) cr.action = sr.action;
                    if (cr.matches(app, dstIp, dstPort, domain, proto, ja3)) {
                        return cr;
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "matchCompoundRule error: " + e.getMessage());
        }
        return null;
    }

    public SecurityRule findJa3BlockRule(String ja3Hash) {
        if (ja3Hash == null || ja3Hash.isEmpty()) return null;
        String val = ja3Hash.toLowerCase().trim();
        String sql = "SELECT * FROM " + TABLE_RULES +
                " WHERE " + COL_VALUE + "=? AND " + COL_TYPE + "=? AND " + COL_ACTION + "=? AND " + COL_ENABLED + "=1" +
                " ORDER BY " + COL_PRIORITY + " DESC LIMIT 1";
        try (Cursor c = getReadableDatabase().rawQuery(sql, new String[]{val, TYPE_JA3, ACTION_BLOCK})) {
            if (c.moveToFirst()) return cursorToRule(c);
        } catch (Exception e) {
            Log.e(TAG, "findJa3BlockRule: " + e.getMessage());
        }
        return null;
    }

    public long whitelist(String type, String value, String scope, String reason) {
        return addRule(type, value, ACTION_ALLOW, scope, SOURCE_USER, reason, PRIORITY_USER_ALLOW);
    }

    public void setEnabled(long ruleId, boolean enabled) {
        ContentValues cv = new ContentValues();
        cv.put(COL_ENABLED, enabled ? 1 : 0);
        try {
            getWritableDatabase().update(TABLE_RULES, cv,
                    COL_ID + "=?", new String[]{String.valueOf(ruleId)});
        } catch (Exception e) {
            Log.e(TAG, "setEnabled: " + e.getMessage());
        }
    }

    public SecurityRule getRule(long ruleId) {
        String sql = "SELECT * FROM " + TABLE_RULES + " WHERE " + COL_ID + "=? LIMIT 1";
        try (Cursor c = getReadableDatabase().rawQuery(sql, new String[]{String.valueOf(ruleId)})) {
            if (c.moveToFirst()) return cursorToRule(c);
        } catch (Exception e) {
            Log.e(TAG, "getRule: " + e.getMessage());
        }
        return null;
    }

    public void deleteRule(long ruleId) {
        try {
            getWritableDatabase().delete(TABLE_RULES,
                    COL_ID + "=?", new String[]{String.valueOf(ruleId)});
        } catch (Exception e) {
            Log.e(TAG, "deleteRule: " + e.getMessage());
        }
    }

    public int deleteRuleByValue(String value) {
        if (value == null || value.isEmpty()) return 0;
        String clean = cleanHostOrValue(value).toLowerCase();
        try {
            return getWritableDatabase().delete(TABLE_RULES,
                    COL_VALUE + "=? OR " + COL_VALUE + " LIKE ? OR ? LIKE '%' || " + COL_VALUE + " || '%'",
                    new String[]{clean, "%" + clean + "%", clean});
        } catch (Exception e) {
            Log.e(TAG, "deleteRuleByValue: " + e.getMessage());
            return 0;
        }
    }

    public void incrementHitCount(long ruleId) {
        try {
            getWritableDatabase().execSQL(
                    "UPDATE " + TABLE_RULES + " SET " + COL_HIT_COUNT +
                            " = " + COL_HIT_COUNT + " + 1 WHERE " + COL_ID + " = ?",
                    new Object[]{ruleId});
        } catch (Exception e) {
            Log.e(TAG, "incrementHitCount: " + e.getMessage());
        }
    }

    // ─── Lookup (called in fast packet path — must be synchronous & quick) ────

    /**
     * Checks if a value is blocked. Returns the highest-priority matching active rule,
     * or null if no block rule exists.
     * This is called in the hot path — uses indexed lookup only.
     */
    public static String cleanHostOrValue(String value) {
        if (value == null) return "";
        String u = value.trim().toLowerCase();
        if (u.startsWith("http://")) u = u.substring(7);
        else if (u.startsWith("https://")) u = u.substring(8);
        else if (u.startsWith("dns://")) u = u.substring(6);
        int slash = u.indexOf('/');
        if (slash > 0) u = u.substring(0, slash);
        int colon = u.lastIndexOf(':');
        if (colon > 0 && !u.contains("::")) u = u.substring(0, colon);
        return u.trim();
    }

    public SecurityRule findBlockRule(String value) {
        if (value == null || value.isEmpty()) return null;
        String val = value.toLowerCase().trim();
        String host = cleanHostOrValue(val);

        if (isWhitelisted(val) || (!host.isEmpty() && isWhitelisted(host))) return null;

        String sql = "SELECT * FROM " + TABLE_RULES +
                " WHERE " + COL_VALUE + "=? AND (" + COL_ACTION + "=? OR " + COL_ACTION + "=?) AND " + COL_ENABLED + "=1" +
                " ORDER BY " + COL_PRIORITY + " DESC LIMIT 1";

        // 1. Exact match on raw val
        try (Cursor c = getReadableDatabase().rawQuery(sql, new String[]{val, ACTION_BLOCK, ACTION_QUARANTINE})) {
            if (c.moveToFirst()) return cursorToRule(c);
        } catch (Exception e) {
            Log.e(TAG, "findBlockRule raw: " + e.getMessage());
        }

        // 2. Match on normalized host/IP (stripping port, scheme, and path)
        if (!host.isEmpty() && !host.equals(val)) {
            try (Cursor c = getReadableDatabase().rawQuery(sql, new String[]{host, ACTION_BLOCK, ACTION_QUARANTINE})) {
                if (c.moveToFirst()) return cursorToRule(c);
            } catch (Exception e) {
                Log.e(TAG, "findBlockRule host: " + e.getMessage());
            }
        }

        // 3. Match URL block rules stored in DB (e.g. if DB has 'https://vegamoviess.foo/' or 'http://vegamoviess.foo', match against 'vegamoviess.foo')
        String targetDomain = !host.isEmpty() ? host : val;
        if (targetDomain.contains(".")) {
            String sqlUrl = "SELECT * FROM " + TABLE_RULES +
                    " WHERE (" + COL_VALUE + "=? OR " + COL_VALUE + "=? OR " + COL_VALUE + " LIKE ? OR " + COL_VALUE + " LIKE ?)" +
                    " AND " + COL_ACTION + "=? AND " + COL_ENABLED + "=1 ORDER BY " + COL_PRIORITY + " DESC LIMIT 1";
            try (Cursor c = getReadableDatabase().rawQuery(sqlUrl,
                    new String[]{"http://" + targetDomain, "https://" + targetDomain,
                            "http://" + targetDomain + "/%", "https://" + targetDomain + "/%", ACTION_BLOCK})) {
                if (c.moveToFirst()) return cursorToRule(c);
            } catch (Exception e) {
                Log.e(TAG, "findBlockRule url variant: " + e.getMessage());
            }
        }

        // 4. Domain hierarchy check (e.g. 'sub.evil.com' -> checks 'evil.com')
        if (!host.isEmpty() && host.contains(".")) {
            int dot = host.indexOf('.');
            while (dot != -1 && dot < host.length() - 1) {
                String parent = host.substring(dot + 1);
                try (Cursor c = getReadableDatabase().rawQuery(sql, new String[]{parent, ACTION_BLOCK})) {
                    if (c.moveToFirst()) {
                        SecurityRule r = cursorToRule(c);
                        if (r != null && SCOPE_DOMAIN_WIDE.equalsIgnoreCase(r.scope)) {
                            return r;
                        }
                    }
                } catch (Exception ignored) {}
                dot = host.indexOf('.', dot + 1);
            }
        }

        return null;
    }

    public boolean isWhitelisted(String value) {
        if (value == null || value.isEmpty()) return false;
        String val = value.toLowerCase().trim();
        String host = cleanHostOrValue(val);

        String sql = "SELECT " + COL_ID + " FROM " + TABLE_RULES +
                " WHERE " + COL_VALUE + "=? AND " + COL_ACTION + "=? AND " + COL_ENABLED + "=1 LIMIT 1";
        try (Cursor c = getReadableDatabase().rawQuery(sql, new String[]{val, ACTION_ALLOW})) {
            if (c.moveToFirst()) return true;
        } catch (Exception e) {
            Log.e(TAG, "isWhitelisted: " + e.getMessage());
        }

        if (!host.isEmpty() && !host.equals(val)) {
            try (Cursor c = getReadableDatabase().rawQuery(sql, new String[]{host, ACTION_ALLOW})) {
                if (c.moveToFirst()) return true;
            } catch (Exception ignored) {}
        }
        return false;
    }

    public static String extractHostSimple(String url) {
        return cleanHostOrValue(url);
    }

    // ─── List queries ─────────────────────────────────────────────────────────

    public List<SecurityRule> getAllRules() {
        List<SecurityRule> list = new ArrayList<>();
        String sql = "SELECT * FROM " + TABLE_RULES + " ORDER BY " + COL_PRIORITY + " DESC, " + COL_CREATED_AT + " DESC";
        try (Cursor c = getReadableDatabase().rawQuery(sql, null)) {
            while (c.moveToNext()) list.add(cursorToRule(c));
        } catch (Exception e) {
            Log.e(TAG, "getAllRules: " + e.getMessage());
        }
        return list;
    }

    public List<SecurityRule> getRulesByAction(String action) {
        List<SecurityRule> list = new ArrayList<>();
        try (Cursor c = getReadableDatabase().query(TABLE_RULES, null,
                COL_ACTION + "=? AND " + COL_ENABLED + "=1",
                new String[]{action}, null, null,
                COL_PRIORITY + " DESC")) {
            while (c.moveToNext()) list.add(cursorToRule(c));
        } catch (Exception e) {
            Log.e(TAG, "getRulesByAction: " + e.getMessage());
        }
        return list;
    }

    public List<SecurityRule> getRulesByType(String type) {
        List<SecurityRule> list = new ArrayList<>();
        try (Cursor c = getReadableDatabase().query(TABLE_RULES, null,
                COL_TYPE + "=? AND " + COL_ENABLED + "=1",
                new String[]{type}, null, null,
                COL_CREATED_AT + " DESC")) {
            while (c.moveToNext()) list.add(cursorToRule(c));
        } catch (Exception e) {
            Log.e(TAG, "getRulesByType: " + e.getMessage());
        }
        return list;
    }

    public List<SecurityRule> getRulesBySource(String source) {
        List<SecurityRule> list = new ArrayList<>();
        try (Cursor c = getReadableDatabase().query(TABLE_RULES, null,
                COL_SOURCE + "=? AND " + COL_ENABLED + "=1",
                new String[]{source}, null, null,
                COL_CREATED_AT + " DESC")) {
            while (c.moveToNext()) list.add(cursorToRule(c));
        } catch (Exception e) {
            Log.e(TAG, "getRulesBySource: " + e.getMessage());
        }
        return list;
    }

    public List<SecurityRule> searchRules(String query) {
        List<SecurityRule> list = new ArrayList<>();
        if (query == null || query.trim().isEmpty()) {
            return getAllRules();
        }
        String pattern = "%" + query.trim() + "%";
        String selection = COL_VALUE + " LIKE ? OR " + COL_REASON + " LIKE ? OR " + COL_TYPE + " LIKE ? OR " + COL_SOURCE + " LIKE ?";
        String[] selectionArgs = new String[]{pattern, pattern, pattern, pattern};
        try (Cursor c = getReadableDatabase().query(TABLE_RULES, null,
                selection, selectionArgs, null, null,
                COL_PRIORITY + " DESC, " + COL_CREATED_AT + " DESC")) {
            while (c.moveToNext()) list.add(cursorToRule(c));
        } catch (Exception e) {
            Log.e(TAG, "searchRules: " + e.getMessage());
        }
        return list;
    }

    public int getTotalHits() {
        String sql = "SELECT SUM(" + COL_HIT_COUNT + ") FROM " + TABLE_RULES;
        try (Cursor c = getReadableDatabase().rawQuery(sql, null)) {
            if (c.moveToFirst()) return c.getInt(0);
        } catch (Exception e) {
            Log.e(TAG, "getTotalHits: " + e.getMessage());
        }
        return 0;
    }

    public void clearAllRules() {
        try {
            getWritableDatabase().delete(TABLE_RULES, null, null);
        } catch (Exception e) {
            Log.e(TAG, "clearAllRules: " + e.getMessage());
        }
    }

    public int restoreRules(List<SecurityRule> rules, boolean replace) {
        if (rules == null || rules.isEmpty()) return 0;
        SQLiteDatabase db = getWritableDatabase();
        int count = 0;
        db.beginTransaction();
        try {
            if (replace) {
                db.delete(TABLE_RULES, null, null);
            }
            for (SecurityRule r : rules) {
                if (r.value == null || r.value.trim().isEmpty() || r.type == null) continue;
                ContentValues cv = new ContentValues();
                cv.put(COL_TYPE, r.type);
                cv.put(COL_VALUE, r.value.toLowerCase().trim());
                cv.put(COL_ACTION, r.action != null ? r.action : ACTION_BLOCK);
                cv.put(COL_SCOPE, r.scope != null ? r.scope : SCOPE_EXACT);
                cv.put(COL_SOURCE, r.source != null ? r.source : SOURCE_USER);
                cv.put(COL_REASON, r.reason != null ? r.reason : "Restored from backup");
                cv.put(COL_SEVERITY, r.severity != null ? r.severity : "MEDIUM");
                cv.put(COL_PRIORITY, r.priority > 0 ? r.priority : PRIORITY_EXPLICIT_BLOCK);
                cv.put(COL_ENABLED, r.enabled ? 1 : 0);
                cv.put(COL_CREATED_AT, r.createdAt > 0 ? r.createdAt : System.currentTimeMillis());
                cv.put(COL_EXPIRES_AT, r.expiresAt);
                cv.put(COL_HIT_COUNT, r.hitCount);
                try {
                    db.insertWithOnConflict(TABLE_RULES, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
                    count++;
                } catch (Exception e) {
                    Log.e(TAG, "restoreRules insert error: " + e.getMessage());
                }
            }
            db.setTransactionSuccessful(); // Commit only if all inserts attempted (L-001 fix)
        } catch (Exception e) {
            Log.e(TAG, "restoreRules transaction error: " + e.getMessage());
        } finally {
            db.endTransaction();
        }
        return count;
    }


    // ─── POJO ─────────────────────────────────────────────────────────────────

    public static class SecurityRule {
        public long id;
        public String type;
        public String value;
        public String action;
        public String scope;
        public String source;
        public String reason;
        public String severity;
        public int priority;
        public long createdAt;
        public long expiresAt;
        public boolean enabled;
        public int hitCount;

        public boolean isBlock() { return ACTION_BLOCK.equals(action); }
        public boolean isAllow() { return ACTION_ALLOW.equals(action); }
        public boolean isQuarantine() { return ACTION_QUARANTINE.equals(action); }
        public boolean isRateLimit() { return ACTION_RATE_LIMIT.equals(action); }
    }

    private SecurityRule cursorToRule(Cursor c) {
        SecurityRule r = new SecurityRule();
        r.id = c.getLong(c.getColumnIndexOrThrow(COL_ID));
        r.type = c.getString(c.getColumnIndexOrThrow(COL_TYPE));
        r.value = c.getString(c.getColumnIndexOrThrow(COL_VALUE));
        r.action = c.getString(c.getColumnIndexOrThrow(COL_ACTION));
        r.scope = c.getString(c.getColumnIndexOrThrow(COL_SCOPE));
        r.source = c.getString(c.getColumnIndexOrThrow(COL_SOURCE));
        r.reason = c.getString(c.getColumnIndexOrThrow(COL_REASON));
        r.severity = c.getString(c.getColumnIndexOrThrow(COL_SEVERITY));
        r.priority = c.getInt(c.getColumnIndexOrThrow(COL_PRIORITY));
        r.createdAt = c.getLong(c.getColumnIndexOrThrow(COL_CREATED_AT));
        r.expiresAt = c.getLong(c.getColumnIndexOrThrow(COL_EXPIRES_AT));
        r.enabled = c.getInt(c.getColumnIndexOrThrow(COL_ENABLED)) == 1;
        r.hitCount = c.getInt(c.getColumnIndexOrThrow(COL_HIT_COUNT));
        return r;
    }

    /** Returns total number of security rules. */
    public int getRuleCount() {
        try (Cursor c = getReadableDatabase().rawQuery("SELECT COUNT(*) FROM " + TABLE_RULES, null)) {
            if (c.moveToFirst()) return c.getInt(0);
        } catch (Exception e) {
            Log.e(TAG, "getRuleCount: " + e.getMessage());
        }
        return 0;
    }

    /** Returns number of security rules by action (e.g. BLOCK, ALLOW). */
    public int getRuleCountByAction(String action) {
        try (Cursor c = getReadableDatabase().rawQuery(
                "SELECT COUNT(*) FROM " + TABLE_RULES + " WHERE " + COL_ACTION + "=?",
                new String[]{action})) {
            if (c.moveToFirst()) return c.getInt(0);
        } catch (Exception e) {
            Log.e(TAG, "getRuleCountByAction: " + e.getMessage());
        }
        return 0;
    }
}
