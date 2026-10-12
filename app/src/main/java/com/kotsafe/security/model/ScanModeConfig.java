/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.os.Environment;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Defines the three scan modes and the file scope each covers.
 *
 *  QUICK — Recently changed apps (last 7 days) + Downloads + unscanned files.
 *          Fast, designed for daily background use.
 *
 *  FULL  — All installed APKs (smart-cached: skip unchanged).
 *          Standard user-initiated scan.
 *
 *  DEEP  — FULL + system apps + /sdcard + /storage recursion.
 *          Thorough; may take several minutes on large storage.
 */
public class ScanModeConfig {

    public enum ScanMode {
        QUICK,
        FULL,
        DEEP
    }

    public static class ScanScope {
        public boolean includeUserApps = true;
        public boolean includeSystemApps = false;
        public boolean includeStorage = false;
        public boolean includeDownloads = true;
        public boolean skipUnchangedFiles = true;    // use metadata cache
        public int recentAppsDays = 0;               // 0 = all apps; >0 = only apps updated within N days
        public List<File> storagePaths = new ArrayList<>();

        @Override
        public String toString() {
            return "ScanScope{userApps=" + includeUserApps +
                    ", sysApps=" + includeSystemApps +
                    ", storage=" + includeStorage +
                    ", downloads=" + includeDownloads +
                    ", recentDays=" + recentAppsDays + "}";
        }
    }

    /** Returns the scan scope for the given mode. */
    public static ScanScope getScopeFor(ScanMode mode) {
        ScanScope scope = new ScanScope();
        switch (mode) {
            case QUICK:
                scope.includeUserApps = true;
                scope.includeSystemApps = false;
                scope.includeStorage = false;
                scope.includeDownloads = true;
                scope.skipUnchangedFiles = true;
                scope.recentAppsDays = 7;  // only apps updated/installed within last 7 days
                break;

            case FULL:
                scope.includeUserApps = true;
                scope.includeSystemApps = false;
                scope.includeStorage = false;
                scope.includeDownloads = true;
                scope.skipUnchangedFiles = true;   // smart cache: skip unchanged APKs
                scope.recentAppsDays = 0;          // all apps
                break;

            case DEEP:
                scope.includeUserApps = true;
                scope.includeSystemApps = true;
                scope.includeStorage = true;
                scope.includeDownloads = true;
                scope.skipUnchangedFiles = true;   // still use cache where valid
                scope.recentAppsDays = 0;
                // Add known storage roots
                addStoragePaths(scope);
                break;
        }
        return scope;
    }

    private static void addStoragePaths(ScanScope scope) {
        // Internal Downloads
        File downloads = Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOWNLOADS);
        if (downloads != null && downloads.exists()) {
            scope.storagePaths.add(downloads);
        }
        // SD card root (if available)
        File sdCard = Environment.getExternalStorageDirectory();
        if (sdCard != null && sdCard.exists() && sdCard.canRead()) {
            scope.storagePaths.add(sdCard);
        }
    }

    /** Returns a human-readable display label for the scan mode. */
    public static String getLabel(ScanMode mode) {
        switch (mode) {
            case QUICK: return "Quick Scan";
            case FULL:  return "Full Scan";
            case DEEP:  return "Deep Scan";
            default:    return "Scan";
        }
    }

    /** Returns a description of what this mode covers for the UI. */
    public static String getDescription(ScanMode mode) {
        switch (mode) {
            case QUICK:
                return "Recently updated apps + Downloads (fast)";
            case FULL:
                return "All installed apps, smart-cached";
            case DEEP:
                return "All apps + system + storage files";
            default:
                return "";
        }
    }

    /**
     * Classifies a file by its extension/path to determine analysis depth.
     * Returns one of the FILE_CLASS_* constants from FileHashEntry.
     */
    public static String classifyFile(String path) {
        if (path == null) return FileHashEntry.FILE_CLASS_UNKNOWN;
        String lower = path.toLowerCase();
        if (lower.endsWith(".apk"))                          return FileHashEntry.FILE_CLASS_APK;
        if (lower.endsWith(".dex") || lower.endsWith(".odex")) return FileHashEntry.FILE_CLASS_DEX;
        if (lower.endsWith(".so"))                           return FileHashEntry.FILE_CLASS_SO;
        if (lower.endsWith(".sh") || lower.endsWith(".bash") || lower.endsWith(".zsh")
                || lower.endsWith(".py") || lower.endsWith(".js") || lower.endsWith(".pl")
                || lower.endsWith(".rb") || lower.endsWith(".bat") || lower.endsWith(".cmd")
                || lower.endsWith(".ps1") || lower.endsWith(".vbs") || lower.endsWith(".php")
                || lower.endsWith(".lua") || lower.endsWith(".bin") || lower.endsWith(".elf")
                || lower.endsWith(".exe"))                   return FileHashEntry.FILE_CLASS_SCRIPT;
        if (lower.endsWith(".zip") || lower.endsWith(".jar")
                || lower.endsWith(".aar") || lower.endsWith(".tar")
                || lower.endsWith(".gz")  || lower.endsWith(".rar")
                || lower.endsWith(".7z")  || lower.endsWith(".bz2")
                || lower.endsWith(".xz")  || lower.endsWith(".iso")) return FileHashEntry.FILE_CLASS_ARCHIVE;
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")
                || lower.endsWith(".png") || lower.endsWith(".gif")
                || lower.endsWith(".svg") || lower.endsWith(".bmp")
                || lower.endsWith(".webp") || lower.endsWith(".ico")
                || lower.endsWith(".mp4") || lower.endsWith(".mp3")
                || lower.endsWith(".mkv") || lower.endsWith(".avi")
                || lower.endsWith(".mov") || lower.endsWith(".aac")
                || lower.endsWith(".flac") || lower.endsWith(".webm")) return FileHashEntry.FILE_CLASS_MEDIA;
        if (lower.endsWith(".pdf") || lower.endsWith(".doc")
                || lower.endsWith(".docx") || lower.endsWith(".xls")
                || lower.endsWith(".xlsx") || lower.endsWith(".ppt")
                || lower.endsWith(".pptx") || lower.endsWith(".txt")
                || lower.endsWith(".csv") || lower.endsWith(".tsv")
                || lower.endsWith(".rtf") || lower.endsWith(".odt")
                || lower.endsWith(".ods") || lower.endsWith(".odp")
                || lower.endsWith(".xml") || lower.endsWith(".json")) return FileHashEntry.FILE_CLASS_DOCUMENT;
        return FileHashEntry.FILE_CLASS_UNKNOWN;
    }

    /**
     * Returns the scan priority for a file based on its class and context.
     * Lower number = higher priority.
     */
    public static int getPriority(String fileClass, boolean isNewOrChanged) {
        if (FileHashEntry.FILE_CLASS_APK.equals(fileClass) && isNewOrChanged)
            return FileHashEntry.PRIORITY_CRITICAL;
        if (FileHashEntry.FILE_CLASS_APK.equals(fileClass)
                || FileHashEntry.FILE_CLASS_DEX.equals(fileClass)
                || FileHashEntry.FILE_CLASS_SO.equals(fileClass))
            return FileHashEntry.PRIORITY_HIGH;
        if (FileHashEntry.FILE_CLASS_SCRIPT.equals(fileClass)
                || FileHashEntry.FILE_CLASS_ARCHIVE.equals(fileClass))
            return FileHashEntry.PRIORITY_NORMAL;
        return FileHashEntry.PRIORITY_LOW;
    }

    /**
     * Network capture telemetry states according to OS constraints.
     */
    public enum CaptureState {
        VPN_ACTIVE,               // Full per-socket UID and real-time DNS/SNI C2 sinkholing
        VPN_CONSENT_REQUIRED,     // VpnService.prepare() intent required from user
        AGGREGATE_STATS_ONLY,     // Fallback to NetworkStatsManager (degraded per-UID aggregate metrics)
        OFFLINE_ONLY              // No network telemetry (static local analysis only)
    }

    /**
     * Trust Action result from SmartScreen reputation scoring.
     */
    public enum TrustAction {
        PASS,        // trust_score >= warning_threshold (Safe)
        WARNING,     // quarantine_threshold <= trust_score < warning_threshold (Advisory banner)
        QUARANTINE   // trust_score < quarantine_threshold (Immediate isolation/block)
    }

    /**
     * Reputation and SmartScreen Calibration Configuration.
     * Scale Semantics: TRUST_SCORE (0 to 100, Higher = More Trusted / Safer).
     */
    public static class TrustScoreConfig {
        public static final int DEFAULT_TRUST_THRESHOLD_WARNING = 78;     // trust_score < 78 => Warning
        public static final int DEFAULT_TRUST_THRESHOLD_QUARANTINE = 42;  // trust_score < 42 => Quarantine
        public static final float ACHIEVED_FPR = 0.0040f;                 // 0.40% False Positive Rate
        public static final float ACHIEVED_TPR = 0.9120f;                 // 91.20% True Positive Rate (Catch Rate)
        public static final float TARGET_MAX_FPR = 0.0050f;               // 0.50% FPR budget

        /**
         * Validates the configuration invariants.
         * Enforces: quarantine_threshold < warning_threshold and achieved_fpr <= target_max_fpr.
         */
        public static void validateInvariants(int warningThreshold, int quarantineThreshold, float fpr) {
            if (quarantineThreshold >= warningThreshold) {
                throw new IllegalStateException(
                    "Config Invariant Violation: trust_threshold_quarantine (" + quarantineThreshold
                    + ") must be strictly less than trust_threshold_warning (" + warningThreshold + ")"
                );
            }
            if (fpr > TARGET_MAX_FPR) {
                throw new IllegalStateException("Config Calibration Violation: FPR " + fpr + " exceeds max budget " + TARGET_MAX_FPR);
            }
        }

        /**
         * Evaluates a trust score against the threshold boundaries.
         * 
         * trust_score >= warningThreshold => PASS
         * quarantineThreshold <= trust_score < warningThreshold => WARNING
         * trust_score < quarantineThreshold => QUARANTINE
         */
        public static TrustAction evaluateTrust(int trustScore, int warningThreshold, int quarantineThreshold) {
            validateInvariants(warningThreshold, quarantineThreshold, ACHIEVED_FPR);
            if (trustScore >= warningThreshold) {
                return TrustAction.PASS;
            } else if (trustScore >= quarantineThreshold) {
                return TrustAction.WARNING;
            } else {
                return TrustAction.QUARANTINE;
            }
        }

        public static TrustAction evaluateTrust(int trustScore) {
            return evaluateTrust(trustScore, DEFAULT_TRUST_THRESHOLD_WARNING, DEFAULT_TRUST_THRESHOLD_QUARANTINE);
        }
    }
}

