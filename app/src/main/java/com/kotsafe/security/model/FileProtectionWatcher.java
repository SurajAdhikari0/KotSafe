/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.Manifest;
import android.content.ContentUris;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.database.ContentObserver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.FileObserver;
import android.os.Handler;
import android.os.Looper;
import android.provider.MediaStore;
import androidx.core.content.ContextCompat;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.EvidenceDbHelper;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Real-Time File & Download Guardian (Active Defender).
 *
 * Implements a Dual-Sentinel Architecture:
 * 1. Scoped Storage Sentinel (Android 10+ / API 29+):
 *    Registers a ContentObserver on MediaStore.Downloads.EXTERNAL_CONTENT_URI.
 *    Accesses newly downloaded streams via ContentResolver.openInputStream(uri) backed by
 *    READ_EXTERNAL_STORAGE without maxSdkVersion capping.
 * 2. Broad Storage Sentinel (API < 29 or with MANAGE_EXTERNAL_STORAGE):
 *    Employs an active FileObserver watching /sdcard/Download/ directly.
 *
 * For every detected download:
 *   1. Incremental streaming SHA-256 calculation.
 *   2. Cloaked double extension (.pdf.apk, .png.dex) & Ransomware canary marker inspection.
 *   3. Firewall blocklist policy evaluation.
 *   4. YARA rule pattern matching.
 *   5. Cloud/local Threat Intelligence lookup.
 *   6. Real-time SmartScreen threat intervention and evidence logging.
 */
public class FileProtectionWatcher {
    private static final String TAG = "FileProtectionWatcher";

    private final Context mContext;
    private final ExecutorService mExecutor;
    private final Handler mMainHandler;
    private FileObserver mDownloadsObserver;
    private ContentObserver mDownloadsContentObserver;
    private boolean mIsActive = false;

    // Cache of recently inspected URIs/hashes to prevent redundant burst evaluations
    private final Set<String> mRecentlyInspected = Collections.synchronizedSet(
            Collections.newSetFromMap(new java.util.LinkedHashMap<String, Boolean>() {
                @Override
                protected boolean removeEldestEntry(java.util.Map.Entry<String, Boolean> eldest) {
                    return size() > 100;
                }
            })
    );

    private static FileProtectionWatcher sInstance;

    public static synchronized FileProtectionWatcher getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new FileProtectionWatcher(context.getApplicationContext());
        }
        return sInstance;
    }

    private FileProtectionWatcher(Context context) {
        mContext = context;
        mExecutor = Executors.newSingleThreadExecutor();
        mMainHandler = new Handler(Looper.getMainLooper());
    }

    public synchronized void startWatching() {
        if (mIsActive) return;

        boolean startedAny = false;

        // 1. Scoped Storage Sentinel via MediaStore.Downloads ContentObserver (Android 10+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                mDownloadsContentObserver = new ContentObserver(mMainHandler) {
                    @Override
                    public void onChange(boolean selfChange, Uri uri) {
                        if (uri != null) {
                            mExecutor.execute(() -> handleMediaStoreChange(uri));
                        }
                    }
                };

                mContext.getContentResolver().registerContentObserver(
                        MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                        true,
                        mDownloadsContentObserver
                );
                startedAny = true;
                Log.i(TAG, "MediaStore.Downloads Sentinel active (Scoped Storage Mode)");
            } catch (Exception e) {
                Log.w(TAG, "Could not register MediaStore.Downloads observer: " + e.getMessage());
            }
        }

        // 2. Broad Storage FileObserver Sentinel (Android < 10 or with MANAGE_EXTERNAL_STORAGE)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || Utils.canTraverseAllStorage(mContext)) {
            try {
                File downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
                if (downloads != null && downloads.exists() && downloads.canRead()) {
                    int mask = FileObserver.CLOSE_WRITE | FileObserver.MOVED_TO;
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        mDownloadsObserver = new FileObserver(downloads, mask) {
                            @Override
                            public void onEvent(int event, String path) {
                                if (path == null) return;
                                File file = new File(downloads, path);
                                if (file.exists() && !file.isDirectory()) {
                                    mExecutor.execute(() -> inspectNewFile(file));
                                }
                            }
                        };
                    } else {
                        mDownloadsObserver = new FileObserver(downloads.getAbsolutePath(), mask) {
                            @Override
                            public void onEvent(int event, String path) {
                                if (path == null) return;
                                File file = new File(downloads, path);
                                if (file.exists() && !file.isDirectory()) {
                                    mExecutor.execute(() -> inspectNewFile(file));
                                }
                            }
                        };
                    }
                    mDownloadsObserver.startWatching();
                    startedAny = true;
                    Log.i(TAG, "Direct FileObserver Sentinel active on: " + downloads.getAbsolutePath());
                }
            } catch (Exception e) {
                Log.w(TAG, "Could not start direct FileObserver: " + e.getMessage());
            }
        }

        mIsActive = startedAny;
        if (mIsActive) {
            Log.i(TAG, "FileProtectionWatcher active defense successfully engaged.");
        }

        boolean isFullPower = "fullPower".equalsIgnoreCase(com.kotsafe.security.BuildConfig.FLAVOR);
        boolean hasManageStorage = Build.VERSION.SDK_INT < Build.VERSION_CODES.R
                || Environment.isExternalStorageManager();
        if (isFullPower && !hasManageStorage) {
            SecurityNotificationHub.getInstance(mContext).postProtectionDegradedAlert(
                    "Limited Real-Time Protection",
                    "Grant 'All Files Access' so KotSafe can monitor all storage paths. " +
                    "Tap to open settings."
            );
            Log.w(TAG, "C-001: MANAGE_EXTERNAL_STORAGE not granted — broad FileObserver inactive. " +
                    "Posted Protection Degraded notification.");
        }
    }

    public synchronized void stopWatching() {
        if (!mIsActive) return;
        try {
            if (mDownloadsContentObserver != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                mContext.getContentResolver().unregisterContentObserver(mDownloadsContentObserver);
                mDownloadsContentObserver = null;
            }
            if (mDownloadsObserver != null) {
                mDownloadsObserver.stopWatching();
                mDownloadsObserver = null;
            }
            mIsActive = false;
            Log.i(TAG, "FileProtectionWatcher stopped");
        } catch (Exception e) {
            Log.w(TAG, "Error stopping FileProtectionWatcher: " + e.getMessage());
        }
    }

    /**
     * Handles changes triggered by MediaStore.Downloads ContentObserver.
     */
    private void handleMediaStoreChange(Uri uri) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return;

        try {
            String[] projection = new String[]{
                    MediaStore.Downloads._ID,
                    MediaStore.Downloads.DISPLAY_NAME,
                    MediaStore.Downloads.SIZE,
                    MediaStore.Downloads.DATE_MODIFIED
            };

            // If notification is generic (collection URI), query latest downloads
            Uri targetQueryUri = uri;
            String sortOrder = null;
            if (uri.equals(MediaStore.Downloads.EXTERNAL_CONTENT_URI)) {
                sortOrder = MediaStore.Downloads.DATE_ADDED + " DESC LIMIT 3";
            }

            try (Cursor cursor = mContext.getContentResolver().query(targetQueryUri, projection, null, null, sortOrder)) {
                if (cursor != null) {
                    while (cursor.moveToNext()) {
                        long id = cursor.getLong(cursor.getColumnIndexOrThrow(MediaStore.Downloads._ID));
                        String displayName = cursor.getString(cursor.getColumnIndexOrThrow(MediaStore.Downloads.DISPLAY_NAME));
                        long size = cursor.getLong(cursor.getColumnIndexOrThrow(MediaStore.Downloads.SIZE));
                        long dateModified = cursor.getLong(cursor.getColumnIndexOrThrow(MediaStore.Downloads.DATE_MODIFIED));

                        Uri itemUri = ContentUris.withAppendedId(MediaStore.Downloads.EXTERNAL_CONTENT_URI, id);
                        String uriKey = itemUri.toString() + "_" + size + "_" + dateModified;
                        if (mRecentlyInspected.contains(uriKey)) continue;
                        mRecentlyInspected.add(uriKey);

                        inspectDownloadUri(itemUri, displayName, size, dateModified);
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "handleMediaStoreChange error: " + e.getMessage());
        }
    }

    /**
     * Inspects a newly downloaded content URI via openInputStream.
     */
    private void inspectDownloadUri(Uri uri, String displayName, long size, long dateModified) {
        if (displayName == null || uri == null) return;
        String lowerName = displayName.toLowerCase();

        boolean isDoubleExt = AntivirusScanEngine.isDoubleExtensionCloaked(lowerName);
        boolean isCanary = AntivirusScanEngine.isRansomwareCanaryFile(lowerName);
        boolean isExec = lowerName.endsWith(".apk") || lowerName.endsWith(".dex") || lowerName.endsWith(".jar")
                || lowerName.endsWith(".sh") || lowerName.endsWith(".bin") || lowerName.endsWith(".so");

        if (!isDoubleExt && !isCanary && !isExec && size < 1024) return;

        Log.d(TAG, "Inspecting download URI: " + displayName + " (size=" + size + ")");

        File tempFile = null;
        try {
            // Copy stream to temp cache file for multi-pass evaluation (hash + YARA)
            tempFile = new File(mContext.getCacheDir(), "sentinel_eval_" + System.currentTimeMillis() + ".tmp");
            try (InputStream is = mContext.getContentResolver().openInputStream(uri);
                 FileOutputStream fos = new FileOutputStream(tempFile)) {
                if (is == null) return;
                byte[] buf = new byte[16384];
                int r;
                while ((r = is.read(buf)) != -1) {
                    fos.write(buf, 0, r);
                }
            }

            if (!tempFile.exists() || tempFile.length() == 0) return;

            String sha256 = FileHashScanner.computeHash(tempFile, "SHA-256");
            if (sha256 == null || sha256.isEmpty()) return;

            evaluateThreat(tempFile, displayName, uri.toString(), sha256, size, dateModified, isDoubleExt, isCanary);
        } catch (Exception e) {
            Log.e(TAG, "Error inspecting download URI: " + e.getMessage());
        } finally {
            if (tempFile != null && tempFile.exists()) {
                //noinspection ResultOfMethodCallIgnored
                tempFile.delete();
            }
        }
    }

    /**
     * Inspects a direct filesystem path (broad storage sentinel fallback).
     */
    private void inspectNewFile(File file) {
        try {
            String name = file.getName();
            String lowerName = name.toLowerCase();

            boolean isDoubleExt = AntivirusScanEngine.isDoubleExtensionCloaked(lowerName);
            boolean isCanary = AntivirusScanEngine.isRansomwareCanaryFile(lowerName);
            boolean isExec = lowerName.endsWith(".apk") || lowerName.endsWith(".dex") || lowerName.endsWith(".jar")
                    || lowerName.endsWith(".sh") || lowerName.endsWith(".bin") || lowerName.endsWith(".so");

            if (!isDoubleExt && !isCanary && !isExec && file.length() < 1024) return;

            String cacheKey = file.getAbsolutePath() + "_" + file.length() + "_" + file.lastModified();
            if (mRecentlyInspected.contains(cacheKey)) return;
            mRecentlyInspected.add(cacheKey);

            Log.d(TAG, "Inspecting raw file download: " + name);
            String sha256 = FileHashScanner.computeHash(file, "SHA-256");
            if (sha256 == null || sha256.isEmpty()) return;

            evaluateThreat(file, name, file.getAbsolutePath(), sha256, file.length(), file.lastModified(), isDoubleExt, isCanary);
        } catch (Exception e) {
            Log.e(TAG, "inspectNewFile error: " + e.getMessage());
        }
    }

    /**
     * Core multi-vector threat evaluation for any captured binary.
     */
    private void evaluateThreat(File evalFile, String displayName, String sourcePath,
                                String sha256, long size, long lastModified,
                                boolean isDoubleExt, boolean isCanary) {
        boolean isMalicious = false;
        boolean isSuspicious = false;
        String threatDetails = "";
        String threatFamily = "";

        // Self-protection: immediately exempt and record KotSafe self package
        if (displayName.toLowerCase().endsWith(".apk") || sourcePath.toLowerCase().endsWith(".apk")) {
            try {
                PackageManager pm = mContext.getPackageManager();
                PackageInfo pi = pm.getPackageArchiveInfo(evalFile.getAbsolutePath(), 0);
                if (pi != null && pi.packageName != null &&
                        (pi.packageName.equals(mContext.getPackageName()) || pi.packageName.startsWith("com.kotsafe.security") || pi.packageName.startsWith("com.kotsafe.security"))) {
                    Log.i(TAG, "Exempting KotSafe self package from threat evaluation: " + pi.packageName);
                    FileHashDbHelper hashDb = FileHashDbHelper.getInstance(mContext);
                    FileHashEntry entry = new FileHashEntry();
                    entry.fileName = displayName;
                    entry.filePath = sourcePath;
                    entry.fileSize = size;
                    entry.fileLastModified = lastModified;
                    entry.scanType = FileHashEntry.SCAN_TYPE_STORAGE;
                    entry.fileClass = FileHashEntry.FILE_CLASS_APK;
                    entry.scanPriority = ScanModeConfig.getPriority(FileHashEntry.FILE_CLASS_APK, true);
                    entry.scanStatus = FileHashEntry.SCAN_STATUS_DONE;
                    entry.sha256 = sha256;
                    entry.threatStatus = FileHashEntry.THREAT_CLEAN;
                    entry.threatDetails = "KotSafe Application Package (Self Verified)";
                    entry.scanTier = "DEEP";
                    entry.ctime = FileHashDbHelper.getFileCtime(evalFile.getAbsolutePath());
                    hashDb.upsertFileHash(entry);
                    return;
                }
            } catch (Exception ignored) {}
        }

        // 0. Evasion & Canary Heuristics
        if (isCanary) {
            isMalicious = true;
            threatFamily = "Ransomware Canary";
            threatDetails = "Ransomware Encrypted Artifact: " + displayName;
        } else if (isDoubleExt) {
            isMalicious = true;
            threatFamily = "Cloaked Dropper";
            threatDetails = "Cloaked Double Extension Evasion: " + displayName;
        }

        // 1. Firewall Security Rules check
        SecurityBlocklistManager secMgr = SecurityBlocklistManager.getInstance(mContext);
        if (secMgr.isHashBlocked(sha256)) {
            SecurityRulesDb.SecurityRule rule = secMgr.findBlockRule(sha256);
            String ruleReason = (rule != null && rule.reason != null) ? rule.reason : "Firewall Hash Block Rule";
            try {
                SmartScreenManager.getInstance(mContext).showFirewallBlockPage(
                        displayName + " [SHA-256: " + (sha256.length() > 16 ? sha256.substring(0, 16) + "…" : sha256) + "]",
                        "HASH",
                        ruleReason,
                        "File Downloads Sentinel",
                        ""
                );
            } catch (Exception ignored) {}
            isMalicious = true;
            threatFamily = "Blocked Hash";
            threatDetails = "Blocked Policy: " + ruleReason;
        }

        // 2. YARA Rule Engine Scan
        YaraRuleEngine yara = YaraRuleEngine.getInstance(mContext);
        List<YaraRuleEngine.YaraMatch> matches = displayName.toLowerCase().endsWith(".apk")
                ? yara.scanApk(evalFile, "")
                : yara.scanFile(evalFile);

        if (!matches.isEmpty()) {
            for (YaraRuleEngine.YaraMatch m : matches) {
                if (AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(m.severity)) {
                    isMalicious = true;
                    threatFamily = m.ruleName;
                    threatDetails = "YARA matched: " + m.description;
                    break;
                } else if (AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equals(m.severity)) {
                    isSuspicious = true;
                    threatFamily = m.ruleName;
                    threatDetails = "YARA suspicious pattern: " + m.description;
                }
            }
        }

        // 3. Threat Intelligence Router
        ThreatIntelRouter router = ThreatIntelRouter.getInstance(mContext);
        ThreatIntelProvider.ThreatReport tiReport = router.queryHash(sha256);
        if (tiReport != null && tiReport.isMalicious) {
            isMalicious = true;
            threatFamily = tiReport.malwareFamily != null ? tiReport.malwareFamily : threatFamily;
            threatDetails = "[" + tiReport.provider + "] " + tiReport.details;
        }

        // 4. Record into FileHashDbHelper
        FileHashDbHelper hashDb = FileHashDbHelper.getInstance(mContext);
        FileHashEntry entry = new FileHashEntry();
        entry.fileName = displayName;
        entry.filePath = sourcePath;
        entry.fileSize = size;
        entry.fileLastModified = lastModified;
        entry.sha256 = sha256;
        entry.fileClass = displayName.toLowerCase().endsWith(".apk") ? FileHashEntry.FILE_CLASS_APK : FileHashEntry.FILE_CLASS_UNKNOWN;
        entry.scanType = FileHashEntry.SCAN_TYPE_DOWNLOAD;
        entry.scanPriority = FileHashEntry.PRIORITY_HIGH;
        entry.scanStatus = FileHashEntry.SCAN_STATUS_DONE;
        entry.threatStatus = isMalicious ? FileHashEntry.THREAT_MALICIOUS : (isSuspicious ? FileHashEntry.THREAT_SUSPICIOUS : FileHashEntry.THREAT_CLEAN);
        entry.threatDetails = threatDetails;
        hashDb.upsertFileHash(entry);

        // 5. Alert user via SmartScreen & Evidence Ledger
        if (isMalicious) {
            Log.w(TAG, "KOTSAFE SENTINEL ALERT: Malicious file detected: " + displayName);
            SmartScreenManager.getInstance(mContext).showFileThreat(
                    displayName, sourcePath, sha256,
                    threatFamily, "KotSafe Downloads Sentinel"
            );

            SecurityDatabase.getInstance(mContext).evidence().insertEvidence(
                    "FILE",
                    "Malicious Download: " + displayName,
                    threatDetails,
                    95,
                    EvidenceDbHelper.VERDICT_MALICIOUS,
                    "",
                    sha256,
                    "HASH",
                    "SENTINEL"
            );
        }
    }
}
