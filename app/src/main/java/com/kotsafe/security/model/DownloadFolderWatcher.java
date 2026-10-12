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
 *
 * Copyright 2026 - KotSafe
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.os.Build;
import android.os.Environment;
import android.os.FileObserver;

import androidx.annotation.Nullable;

import com.kotsafe.security.Log;

import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Real-time Sideload & Download File Watcher.
 * Uses FileObserver to monitor the downloads folder for dangerous files (.apk, .dex, .sh, .zip).
 * Immediately computes SHA-256 hashes and evaluates signatures upon download completion.
 */
public class DownloadFolderWatcher {
    private static final String TAG = "DownloadFolderWatcher";
    private static volatile DownloadFolderWatcher sInstance;

    private static final Set<String> TARGET_EXTENSIONS = new HashSet<>(Arrays.asList(
            ".apk", ".dex", ".sh", ".zip", ".jar", ".bin", ".js"
    ));

    private final Context mContext;
    private final ExecutorService mExecutor;
    private final java.util.List<FileObserver> mObservers = new ArrayList<>();
    private boolean mIsRunning = false;

    public static DownloadFolderWatcher getInstance(Context context) {
        if (sInstance == null) {
            synchronized (DownloadFolderWatcher.class) {
                if (sInstance == null) {
                    sInstance = new DownloadFolderWatcher(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private DownloadFolderWatcher(Context context) {
        mContext = context;
        mExecutor = Executors.newSingleThreadExecutor();
    }

    public synchronized void start() {
        if (mIsRunning) return;

        java.util.List<File> targetDirs = new ArrayList<>();
        File publicDownloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        if (publicDownloads != null) targetDirs.add(publicDownloads);

        File extStorage = Environment.getExternalStorageDirectory();
        if (extStorage != null) {
            targetDirs.add(new File(extStorage, "Download"));
            targetDirs.add(new File(extStorage, "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents"));
            targetDirs.add(new File(extStorage, "WhatsApp/Media/WhatsApp Documents"));
            targetDirs.add(new File(extStorage, "Telegram/Telegram Documents"));
            targetDirs.add(new File(extStorage, "Android/media/org.telegram.messenger/Telegram/Telegram Documents"));
        }

        int mask = FileObserver.CLOSE_WRITE | FileObserver.MOVED_TO;

        for (File dir : targetDirs) {
            try {
                if (!dir.exists()) {
                    dir.mkdirs();
                }
                if (!dir.exists() || !dir.canRead()) continue;

                FileObserver observer;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    observer = new FileObserver(dir, mask) {
                        @Override
                        public void onEvent(int event, @Nullable String path) {
                            onDownloadFileEvent(dir, path);
                        }
                    };
                } else {
                    observer = new FileObserver(dir.getAbsolutePath(), mask) {
                        @Override
                        public void onEvent(int event, @Nullable String path) {
                            onDownloadFileEvent(dir, path);
                        }
                    };
                }

                observer.startWatching();
                mObservers.add(observer);
                Log.i(TAG, "Watching sideload directory: " + dir.getAbsolutePath());
            } catch (Exception e) {
                Log.d(TAG, "Could not watch dir " + dir.getAbsolutePath() + ": " + e.getMessage());
            }
        }

        mIsRunning = !mObservers.isEmpty();
        Log.i(TAG, "DownloadFolderWatcher active on " + mObservers.size() + " directories");
    }

    public synchronized void stop() {
        if (!mIsRunning) return;
        for (FileObserver observer : mObservers) {
            try {
                observer.stopWatching();
            } catch (Exception ignored) {}
        }
        mObservers.clear();
        mIsRunning = false;
        Log.i(TAG, "DownloadFolderWatcher stopped");
    }

    private void onDownloadFileEvent(File downloadsDir, @Nullable String path) {
        if (path == null) return;
        String lower = path.toLowerCase(java.util.Locale.ROOT);
        boolean isTarget = false;
        for (String ext : TARGET_EXTENSIONS) {
            if (lower.endsWith(ext)) {
                isTarget = true;
                break;
            }
        }

        if (isTarget) {
            File targetFile = new File(downloadsDir, path);
            mExecutor.execute(() -> inspectDownloadedFile(targetFile));
        }
    }

    private void inspectDownloadedFile(File file) {
        if (!file.exists() || !file.canRead() || file.length() <= 0) return;

        try {
            String sha256 = calculateFileSha256(file);
            if (sha256.isEmpty()) return;

            Log.d(TAG, "Inspecting downloaded file: " + file.getName() + " [SHA-256: " + sha256.substring(0, 8) + "]");

            SecurityBlocklistManager secBl = SecurityBlocklistManager.getInstance(mContext);
            boolean isMalicious = false;
            String reason = null;

            if (secBl != null && secBl.isFastBlocked(sha256)) {
                isMalicious = true;
                reason = "Known Malicious Signature (Threat Feed)";
            }

            // Also check YARA rules on APK or scripts
            if (!isMalicious && (file.getName().endsWith(".apk") || file.getName().endsWith(".sh"))) {
                try {
                    YaraRuleEngine yara = YaraRuleEngine.getInstance(mContext);
                    java.util.List<YaraRuleEngine.YaraMatch> matches = yara.scanFile(file);
                    if (matches != null && !matches.isEmpty()) {
                        isMalicious = true;
                        reason = "Matched YARA Rule: " + matches.get(0).ruleName;
                    }
                } catch (Exception ignored) {}
            }

            if (isMalicious) {
                Log.w(TAG, "DANGEROUS DOWNLOAD DETECTED: " + file.getName() + " -> " + reason);

                AlertStore.getInstance(mContext).add(
                        AlertRecord.Severity.HIGH,
                        AlertRecord.AlertType.MALWARE,
                        "Malicious Download: " + file.getName(),
                        "Downloaded file matches threat signature (" + reason + "). Do not install or open.",
                        file.getName()
                );

                SmartScreenManager.getInstance(mContext).showSuspiciousWarning(
                        file.getName(),
                        sha256,
                        "MALICIOUS FILE",
                        95,
                        "KotSafe Sideload Guard"
                );
            }
        } catch (Exception e) {
            Log.e(TAG, "inspectDownloadedFile error: " + e.getMessage());
        }
    }

    private static String calculateFileSha256(File file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[8192];
            int read;
            while ((read = fis.read(buf)) != -1) {
                md.update(buf, 0, read);
            }
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
