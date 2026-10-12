/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import java.io.Serializable;

/**
 * Structured model representing the report summary of a completed scan
 * (either Daily Automatic Background Deep Scan or User-Initiated Manual Scan).
 */
public class ScanReportEntry implements Serializable {
    public long id;
    public long timestamp;
    public String scanMode; // "DEEP", "FULL", "FAST"
    public boolean isBackground;
    public int securityScore;
    public int threatsDetected;
    public int suspiciousDetected;
    public int lowRiskCount;
    public int packagesScanned;
    public int splitsScanned;
    public int storageScanned;
    public int ipsScanned;
    public int urlsScanned;
    public long durationMs;
    public String summary;

    public ScanReportEntry() {
        this.timestamp = System.currentTimeMillis();
        this.scanMode = "DEEP";
        this.securityScore = 100;
        this.summary = "";
    }

    public static ScanReportEntry fromScanResult(AntivirusScanEngine.ScanResult result, boolean isBackground, long durationMs) {
        ScanReportEntry entry = new ScanReportEntry();
        entry.timestamp = System.currentTimeMillis();
        entry.scanMode = result.scanMode != null ? result.scanMode.name() : "DEEP";
        entry.isBackground = isBackground;
        entry.securityScore = result.securityScore;
        entry.threatsDetected = result.threatsDetected;
        entry.suspiciousDetected = result.suspiciousDetected;
        entry.lowRiskCount = result.lowRiskCount;
        entry.packagesScanned = result.totalPackagesScanned > 0 ? result.totalPackagesScanned : result.userPackagesScanned + result.systemPackagesScanned;
        entry.splitsScanned = result.totalSplitsScanned;
        entry.storageScanned = result.totalStorageScanned;
        entry.ipsScanned = result.totalIpsScanned;
        entry.urlsScanned = result.totalUrlsScanned;
        entry.durationMs = durationMs;

        int totalAssets = entry.packagesScanned + entry.splitsScanned + entry.storageScanned + entry.ipsScanned + entry.urlsScanned;
        if (entry.threatsDetected > 0) {
            entry.summary = String.format(java.util.Locale.US,
                    "⚠️ %d Threat(s) detected across %d items (%s scan)",
                    entry.threatsDetected, totalAssets, entry.scanMode);
        } else {
            entry.summary = String.format(java.util.Locale.US,
                    "✓ 0 threats found across %d items (%s scan)",
                    totalAssets, entry.scanMode);
        }
        return entry;
    }
}
