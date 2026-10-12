/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.app.ActivityManager;
import android.content.Context;
import android.content.ContentUris;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.MediaStore;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Smart file hash scanner implementing the staged pipeline:
 *
 *   Stage 1: stat() metadata — compare mtime to DB; skip if unchanged
 *   Stage 2: compute SHA-256 (+ SHA-1/MD5 for high-risk classes)
 *   Stage 3: classify file, assign priority, store in DB
 *
 * Scan modes (via ScanModeConfig):
 *   QUICK — recently updated/new apps + Downloads
 *   FULL  — all installed APKs (smart-cached)
 *   DEEP  — FULL + system apps + external storage walk
 *
 * Never re-hashes a file whose mtime is unchanged since last scan.
 */
public class FileHashScanner {
    private static final String TAG = "FileHashScanner";
    private static final long MIN_STORAGE_FILE_SIZE = 10 * 1024; // 10 KB minimum for storage files

    public interface ScanListener {
        void onScanProgress(int current, int total, String currentItem);
        void onScanCompleted(int totalScanned, int skipped, int servicesCount);
    }

    private final Context mContext;
    private final FileHashDbHelper mDbHelper;
    private final ExecutorService mExecutor;
    private final Handler mMainHandler;
    private final AtomicBoolean mIsScanning = new AtomicBoolean(false);

    private static FileHashScanner sInstance;

    public static synchronized FileHashScanner getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new FileHashScanner(context.getApplicationContext());
        }
        return sInstance;
    }

    private FileHashScanner(Context context) {
        mContext = context;
        mDbHelper = FileHashDbHelper.getInstance(context);
        mExecutor = Executors.newSingleThreadExecutor();
        mMainHandler = new Handler(Looper.getMainLooper());
    }

    public boolean isScanning() { return mIsScanning.get(); }

    // ─── Public scan entry points ─────────────────────────────────────────────

    /** Full scan of all installed APKs (smart-cached — skips unchanged). */
    public void startFullScan(ScanListener listener) {
        startScan(ScanModeConfig.ScanMode.FULL, listener);
    }

    /** Quick scan: only apps updated/installed in last 7 days + Downloads folder. */
    public void startQuickScan(ScanListener listener) {
        startScan(ScanModeConfig.ScanMode.QUICK, listener);
    }

    /** Deep scan: all APKs + system apps + external storage walk. */
    public void startDeepScan(ScanListener listener) {
        startScan(ScanModeConfig.ScanMode.DEEP, listener);
    }

    public void startScan(ScanModeConfig.ScanMode mode, ScanListener listener) {
        if (mIsScanning.getAndSet(true)) {
            Log.d(TAG, "Scan already in progress");
            return;
        }

        mExecutor.execute(() -> {
            Log.i(TAG, "Starting " + ScanModeConfig.getLabel(mode));
            int totalScanned = 0;
            int totalSkipped = 0;
            int servicesFound = 0;

            try {
                ScanModeConfig.ScanScope scope = ScanModeConfig.getScopeFor(mode);
                PackageManager pm = mContext.getPackageManager();
                ActivityManager am = (ActivityManager) mContext.getSystemService(Context.ACTIVITY_SERVICE);

                // ── Step 1: collect running background service packages ────────
                Set<String> runningServicePkgs = new HashSet<>();
                try {
                    List<ActivityManager.RunningServiceInfo> services = am.getRunningServices(200);
                    if (services != null) {
                        for (ActivityManager.RunningServiceInfo s : services) {
                            if (s.service != null) runningServicePkgs.add(s.service.getPackageName());
                        }
                    }
                } catch (Exception e) {
                    Log.w(TAG, "Cannot query running services: " + e.getMessage());
                }

                // ── Step 2: collect APK candidates based on scope ─────────────
                List<PackageInfo> packages = pm.getInstalledPackages(PackageManager.GET_SERVICES);
                long recentCutoff = scope.recentAppsDays > 0
                        ? System.currentTimeMillis() - ((long) scope.recentAppsDays * 86400_000L)
                        : 0;

                List<PackageInfo> candidates = new ArrayList<>();
                for (PackageInfo pkg : packages) {
                    ApplicationInfo ai = pkg.applicationInfo;
                    if (ai == null || ai.sourceDir == null) continue;
                        boolean isSystem = Utils.classifyAppInstall(ai) == Utils.AppInstallClass.SYSTEM;
                    if (isSystem && !scope.includeSystemApps) continue;
                    if (!isSystem && !scope.includeUserApps) continue;
                    // Quick scan: only recently updated apps
                    if (recentCutoff > 0 && pkg.lastUpdateTime < recentCutoff) continue;
                    candidates.add(pkg);
                }

                int total = candidates.size();
                // Add storage file count estimate for progress (will update dynamically)
                int current = 0;

                // ── Step 3: hash each APK candidate ──────────────────────────
                for (PackageInfo pkg : candidates) {
                    current++;
                    ApplicationInfo ai = pkg.applicationInfo;
                    String appLabel = pm.getApplicationLabel(ai).toString();
                    boolean hasServices = (pkg.services != null && pkg.services.length > 0)
                            || runningServicePkgs.contains(pkg.packageName);
                        boolean isSystem = Utils.classifyAppInstall(ai) == Utils.AppInstallClass.SYSTEM;
                    if (hasServices) servicesFound++;

                    final int fc = current;
                    final String fl = appLabel;
                    post(listener, () -> listener.onScanProgress(fc, total, "Hashing " + fl + "…"));

                    // Hash base APK with smart-cache check
                    File baseApk = new File(ai.sourceDir);
                    if (baseApk.exists() && baseApk.canRead()) {
                        long mtime = baseApk.lastModified();
                        if (scope.skipUnchangedFiles && !mDbHelper.isChangedSinceLastScan(ai.sourceDir, mtime)) {
                            totalSkipped++;
                        } else {
                            FileHashEntry entry = buildApkEntry(pm, pkg, baseApk, appLabel, hasServices, isSystem, false);
                            if (entry.sha256 != null && !entry.sha256.isEmpty()) {
                                mDbHelper.upsertFileHash(entry);
                                totalScanned++;
                            }
                        }
                    }

                    // Hash split APKs
                    if (ai.splitSourceDirs != null) {
                        for (String splitPath : ai.splitSourceDirs) {
                            File sf = new File(splitPath);
                            if (!sf.exists() || !sf.canRead()) continue;
                            long mtime = sf.lastModified();
                            if (scope.skipUnchangedFiles && !mDbHelper.isChangedSinceLastScan(splitPath, mtime)) {
                                totalSkipped++;
                            } else {
                                FileHashEntry se = buildApkEntry(pm, pkg, sf, appLabel + " (Split)", hasServices, isSystem, true);
                                if (se.sha256 != null && !se.sha256.isEmpty()) {
                                    mDbHelper.upsertFileHash(se);
                                    totalScanned++;
                                }
                            }
                        }
                    }

                    Thread.sleep(5); // yield CPU briefly
                }

                // ── Step 4: Downloads folder scan ────────────────────────────
                if (scope.includeDownloads) {
                    final int fCurrent = current;
                    final int fTotal = total;
                    post(listener, () -> listener.onScanProgress(fCurrent, fTotal, "Scanning Downloads…"));

                    // Modern Android 10+ (API 29+): MediaStore.Downloads (fast, zero permissions)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        int[] mediaResults = scanMediaStoreDownloads(listener, current, total);
                        totalScanned += mediaResults[0];
                        totalSkipped += mediaResults[1];
                    }

                    // Fallback / legacy: scan filesystem Downloads if readable
                    File downloads = Environment.getExternalStoragePublicDirectory(
                            Environment.DIRECTORY_DOWNLOADS);
                    if (downloads != null && downloads.exists() && downloads.canRead()) {
                        int[] results = scanDirectory(downloads, FileHashEntry.SCAN_TYPE_DOWNLOAD, listener, current, total);
                        totalScanned += results[0];
                        totalSkipped += results[1];
                    }
                }

                // ── Step 5: Deep storage scan ─────────────────────────────────
                if (scope.includeStorage && !scope.storagePaths.isEmpty()) {
                    for (File storageRoot : scope.storagePaths) {
                        if (!storageRoot.exists() || !storageRoot.canRead()) continue;
                        final String rootName = storageRoot.getName();
                        post(listener, () -> listener.onScanProgress(0, 0, "Deep scan: " + rootName + "…"));
                        int[] results = scanDirectory(storageRoot, FileHashEntry.SCAN_TYPE_STORAGE, listener, 0, 0);
                        totalScanned += results[0];
                        totalSkipped += results[1];
                    }
                }

            } catch (Exception e) {
                Log.e(TAG, "Scan error: " + e.getMessage());
            } finally {
                mIsScanning.set(false);
            }

            final int fs = totalScanned;
            final int fsk = totalSkipped;
            final int fsv = servicesFound;
            post(listener, () -> listener.onScanCompleted(fs, fsk, fsv));
            Log.i(TAG, "Scan complete — scanned=" + totalScanned + " skipped=" + totalSkipped);
        });
    }

    // ─── Modern MediaStore Downloads Scanner (Zero Permission, Android 10+) ───

    private int[] scanMediaStoreDownloads(ScanListener listener, int baseProgress, int totalEstimate) {
        int scanned = 0;
        int skipped = 0;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return new int[]{0, 0};
        }

        Uri collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI;
        String[] projection = {
                MediaStore.Downloads._ID,
                MediaStore.Downloads.DISPLAY_NAME,
                MediaStore.Downloads.DATE_MODIFIED,
                MediaStore.Downloads.SIZE
        };

        try (Cursor cursor = mContext.getContentResolver().query(collection, projection, null, null, null)) {
            if (cursor != null) {
                int idCol = cursor.getColumnIndex(MediaStore.Downloads._ID);
                int nameCol = cursor.getColumnIndex(MediaStore.Downloads.DISPLAY_NAME);
                int dateCol = cursor.getColumnIndex(MediaStore.Downloads.DATE_MODIFIED);
                int sizeCol = cursor.getColumnIndex(MediaStore.Downloads.SIZE);

                while (cursor.moveToNext()) {
                    long id = idCol >= 0 ? cursor.getLong(idCol) : -1;
                    String displayName = nameCol >= 0 ? cursor.getString(nameCol) : null;
                    long dateModifiedSec = dateCol >= 0 ? cursor.getLong(dateCol) : 0;
                    long fileSize = sizeCol >= 0 ? cursor.getLong(sizeCol) : 0;

                    if (id < 0 || displayName == null || displayName.trim().isEmpty()) continue;

                    String fileClass = ScanModeConfig.classifyFile(displayName);
                    boolean isEligible = FileHashEntry.FILE_CLASS_SCRIPT.equals(fileClass)
                            || FileHashEntry.FILE_CLASS_DOCUMENT.equals(fileClass)
                            || displayName.toLowerCase().endsWith(".svg")
                            || FileHashEntry.FILE_CLASS_APK.equals(fileClass);

                    if (!isEligible && fileSize < MIN_STORAGE_FILE_SIZE) continue;

                    long mtimeMs = dateModifiedSec * 1000L;
                    String virtualPath = "Download/" + displayName;
                    Uri fileUri = ContentUris.withAppendedId(collection, id);

                    if (mDbHelper.isChangedSinceLastScan(virtualPath, mtimeMs)) {
                        post(listener, () -> listener.onScanProgress(0, 0, "Hashing " + displayName));

                        String sha256 = null;
                        try (InputStream is = mContext.getContentResolver().openInputStream(fileUri)) {
                            if (is != null) {
                                sha256 = computeHash(is, "SHA-256");
                            }
                        } catch (Exception ignored) {}

                        if (sha256 == null || sha256.isEmpty()) {
                            continue;
                        }

                        FileHashEntry entry = new FileHashEntry();
                        entry.fileName = displayName;
                        entry.filePath = virtualPath;
                        entry.fileSize = fileSize;
                        entry.fileLastModified = mtimeMs;
                        entry.scanType = FileHashEntry.SCAN_TYPE_DOWNLOAD;
                        entry.fileClass = fileClass;
                        entry.scanPriority = ScanModeConfig.getPriority(fileClass, true);
                        entry.scanStatus = FileHashEntry.SCAN_STATUS_DONE;
                        entry.sha256 = sha256;

                        if (entry.isHighRiskClass()) {
                            try (InputStream is = mContext.getContentResolver().openInputStream(fileUri)) {
                                if (is != null) {
                                    entry.md5 = computeHash(is, "MD5");
                                }
                            } catch (Exception ignored) {}
                        }
                        entry.threatStatus = FileHashEntry.THREAT_CLEAN;
                        mDbHelper.upsertFileHash(entry);
                        scanned++;
                    } else {
                        skipped++;
                    }
                    Thread.sleep(2);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Error querying MediaStore.Downloads: " + e.getMessage());
        }

        return new int[]{scanned, skipped};
    }

    private static final int MAX_RECURSION_DEPTH = 12;

    // ─── Directory walker (for Downloads + Deep storage) ──────────────────────

    /**
     * Recursively walks a directory and hashes eligible files.
     * Skips: hidden dirs, Android system dirs, files < MIN_STORAGE_FILE_SIZE.
     * Uses smart metadata cache to skip unchanged files.
     * @return int[2] = {scanned count, skipped count}
     */
    private int[] scanDirectory(File dir, String scanType, ScanListener listener,
                                 int baseProgress, int totalEstimate) {
        return scanDirectoryInternal(dir, scanType, listener, baseProgress, totalEstimate, 0);
    }

    private int[] scanDirectoryInternal(File dir, String scanType, ScanListener listener,
                                         int baseProgress, int totalEstimate, int depth) {
        int scanned = 0, skipped = 0;
        if (dir == null || depth > MAX_RECURSION_DEPTH) return new int[]{0, 0};

        File[] files = null;
        try {
            if (!dir.canRead()) return new int[]{0, 0};
            files = dir.listFiles();
        } catch (SecurityException se) {
            Log.w(TAG, "Permission denied accessing: " + dir.getPath());
            return new int[]{0, 0};
        }
        if (files == null) return new int[]{0, 0};

        for (File f : files) {
            try {
                if (f.isDirectory()) {
                    String name = f.getName();
                    // Skip Android internal dirs to avoid re-hashing system data
                    if (name.startsWith(".") || name.equals("Android")
                            || name.equals("data") || name.equals("obb")) continue;
                    int[] sub = scanDirectoryInternal(f, scanType, listener, baseProgress, totalEstimate, depth + 1);
                    scanned += sub[0];
                    skipped += sub[1];
                } else if (f.isFile() && f.length() > 0) {
                    String fileClass = ScanModeConfig.classifyFile(f.getName());
                    boolean isScriptOrDocOrSvg = FileHashEntry.FILE_CLASS_SCRIPT.equals(fileClass)
                            || FileHashEntry.FILE_CLASS_DOCUMENT.equals(fileClass)
                            || f.getName().toLowerCase().endsWith(".svg");
                    if (!isScriptOrDocOrSvg && f.length() < MIN_STORAGE_FILE_SIZE) continue;
                    long mtime = f.lastModified();
                    if (mDbHelper.isChangedSinceLastScan(f.getAbsolutePath(), mtime)) {
                        final String fname = f.getName();
                        post(listener, () -> listener.onScanProgress(0, 0, "Hashing " + fname));
                        FileHashEntry entry = new FileHashEntry();
                        entry.fileName = f.getName();
                        entry.filePath = f.getAbsolutePath();
                        entry.fileSize = f.length();
                        entry.fileLastModified = mtime;
                        entry.scanType = scanType;
                        entry.fileClass = fileClass;
                        entry.scanPriority = ScanModeConfig.getPriority(fileClass, true);
                        entry.scanStatus = FileHashEntry.SCAN_STATUS_DONE;
                        entry.sha256 = computeHash(f, "SHA-256");

                        // Skip inserting if hash computation failed or file was unreadable
                        if (entry.sha256 == null || entry.sha256.isEmpty()) {
                            continue;
                        }

                        // Only compute MD5 for high-risk files
                        if (entry.isHighRiskClass()) {
                            entry.md5 = computeHash(f, "MD5");
                        }
                        entry.threatStatus = FileHashEntry.THREAT_CLEAN;
                        mDbHelper.upsertFileHash(entry);
                        scanned++;
                    } else {
                        skipped++;
                    }
                    Thread.sleep(2); // yield
                }
            } catch (SecurityException se) {
                Log.w(TAG, "SecurityException scanning " + f.getPath() + ": " + se.getMessage());
            } catch (Exception e) {
                Log.w(TAG, "Error scanning " + f.getPath() + ": " + e.getMessage());
            }
        }
        return new int[]{scanned, skipped};
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private FileHashEntry buildApkEntry(PackageManager pm, PackageInfo pkg, File apkFile,
                                         String appLabel, boolean hasServices,
                                         boolean isSystem, boolean isSplit) {
        FileHashEntry entry = new FileHashEntry();
        entry.fileName = apkFile.getName();
        entry.filePath = apkFile.getAbsolutePath();
        entry.packageName = pkg.packageName;
        entry.appName = isSplit ? appLabel : pm.getApplicationLabel(pkg.applicationInfo).toString();
        entry.fileSize = apkFile.length();
        entry.fileLastModified = apkFile.lastModified();
        entry.isServiceApp = hasServices;
        entry.isSystemApp = isSystem;
        entry.scanType = FileHashEntry.SCAN_TYPE_APP;
        entry.fileClass = FileHashEntry.FILE_CLASS_APK;
        entry.scanPriority = FileHashEntry.PRIORITY_HIGH;
        entry.scanStatus = FileHashEntry.SCAN_STATUS_DONE;
        entry.sha256 = computeHash(apkFile, "SHA-256");
        entry.md5 = computeHash(apkFile, "MD5");

        // Check if official service, self package, or standard background service
        boolean isSelf = pkg.packageName != null && (pkg.packageName.equals("com.kotsafe.security") || pkg.packageName.startsWith("com.kotsafe.security") || pkg.packageName.equals("com.kotsafe.security") || pkg.packageName.startsWith("com.kotsafe.security"));
        boolean isOfficial = isSystem || isSelf
            || com.kotsafe.security.Utils.isSystemApp(mContext, pkg.packageName)
            || com.kotsafe.security.Utils.isVerifiedGoogleTrustedService(mContext, pkg.packageName);
        entry.isSystemApp = isOfficial;
        entry.threatStatus = FileHashEntry.THREAT_CLEAN;
        if (isSelf) {
            entry.threatDetails = "Authorized KotSafe Sentinel Security Engine";
        } else if (hasServices && pm.getLaunchIntentForPackage(pkg.packageName) == null) {
            entry.threatDetails = isOfficial ? "Official System / Core Service (No launcher activity)" : "Standard background service (No launcher activity)";
        }
        return entry;
    }

    public static String computeHash(File file, String algorithm) {
        try (InputStream fis = new FileInputStream(file)) {
            return computeHash(fis, algorithm);
        } catch (Exception e) {
            return "";
        }
    }

    public static String computeHash(InputStream is, String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] buffer = new byte[16384];
            int read;
            while ((read = is.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
            byte[] hashBytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private void post(ScanListener listener, Runnable r) {
        if (listener != null) mMainHandler.post(r);
    }
}
